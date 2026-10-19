"""Background jobs that run over SSH against one node: check updates, apt upgrade, reboot.

Design notes
- The upgrade itself is started detached on the node (setsid + nohup, output to a log
  file under /var/log/proxmox-manager/). If the SSH session or the dashboard dies
  mid-way, apt keeps running - we only tail the log. Same trick Proxmox recommends
  (run upgrades in tmux/screen) without needing either installed.
- apt is run non-interactively with dpkg told to keep existing config files, so a
  package prompt can never hang the job.
- Output is appended to the job row as it arrives so the UI can show it live.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

from proxmoxer.core import ResourceException

from .database import db_session
from .models import Job, ProxmoxHost
from .pve import PveError, is_kernel_package, kernel_sort_key
from .pve import connect as pve_connect
from .ssh import SshError, connect, node_address, run

log = logging.getLogger(__name__)

_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="pm-job")
_running: set[int] = set()
_lock = threading.Lock()

UPGRADE_TIMEOUT = 90 * 60  # seconds before we stop tailing an upgrade
REBOOT_TIMEOUT = 20 * 60
LOG_DIR = "/var/log/proxmox-manager"

APT_ENV = "DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none"
APT_OPTS = "-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

ACTIVE = ("queued", "running")
NODE_REBOOT_KINDS = ("reboot", "api_reboot")


_KIND_LABELS = {"guest_onboot": "start-at-boot", "guest_resize": "expand disk"}


def _label(kind: str) -> str:
    return _KIND_LABELS.get(kind) or kind.replace("guest_", "guest ").replace("_", " ")


def start_job(host_id: int, node: str, kind: str, username: str, options: dict | None = None,
              vmid: int | None = None) -> int:
    """Create a job row and schedule it. Returns the job id.

    Node jobs (vmid None) allow one node job at a time per node. Guest jobs allow one job
    at a time per guest. A node reboot also waits for guest jobs on that node to finish,
    and guest jobs are refused while the node is rebooting.
    """
    with db_session() as db:
        running = db.query(Job).filter(Job.host_id == host_id, Job.status.in_(ACTIVE))
        if vmid is None:
            active = running.filter(Job.node == node, Job.vmid.is_(None)).first()
            if active:
                raise RuntimeError(f"A {_label(active.kind)} job is already {active.status} for {node} (job #{active.id}).")
            if kind in NODE_REBOOT_KINDS:
                busy = running.filter(Job.node == node, Job.vmid.is_not(None)).first()
                if busy:
                    raise RuntimeError(f"A {_label(busy.kind)} job is still {busy.status} for guest {busy.vmid} on {node} "
                                       f"(job #{busy.id}). Wait for it to finish before rebooting the node.")
        else:
            active = running.filter(Job.vmid == vmid).first()
            if active:
                raise RuntimeError(f"A {_label(active.kind)} job is already {active.status} for guest {vmid} (job #{active.id}).")
            rebooting = running.filter(Job.node == node, Job.vmid.is_(None), Job.kind.in_(NODE_REBOOT_KINDS)).first()
            if rebooting:
                raise RuntimeError(f"Node {node} is being rebooted (job #{rebooting.id}). Try again when it is back.")
        job = Job(host_id=host_id, node=node, vmid=vmid, kind=kind, requested_by=username,
                  options_json=json.dumps(options or {}))
        db.add(job)
        db.flush()
        job_id = job.id
    _executor.submit(_run_job, job_id)
    return job_id


# --------------------------------------------------------------------------- #
# Runner plumbing
# --------------------------------------------------------------------------- #

class _Ctx:
    """Holds the open SSH client plus helpers for appending output to the job."""

    def __init__(self, job_id: int, host: ProxmoxHost, node: str, options: dict | None = None):
        self.job_id = job_id
        self.host = host
        self.node = node
        self.options = options or {}
        self.client = None
        self._buf = ""
        self._last_flush = 0.0

    def log(self, line: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self.append(f"[{stamp}] {line}\n")

    def append(self, text: str) -> None:
        self._buf += text
        if time.monotonic() - self._last_flush > 1.0:
            self.flush()

    def flush(self) -> None:
        if not self._buf:
            return
        with db_session() as db:
            job = db.get(Job, self.job_id)
            if job:
                job.output = (job.output or "") + self._buf
        self._buf = ""
        self._last_flush = time.monotonic()

    def sh(self, cmd: str, timeout: int = 120) -> tuple[int, str]:
        return run(self.client, cmd, timeout=timeout)


def _run_job(job_id: int) -> None:
    with _lock:
        _running.add(job_id)
    try:
        with db_session() as db:
            job = db.get(Job, job_id)
            if job is None:
                return
            host = db.get(ProxmoxHost, job.host_id)
            job.status = "running"
            job.started_at = _now()
            kind, node, options = job.kind, job.node, json.loads(job.options_json or "{}")
            db.expunge(host)

        ctx = _Ctx(job_id, host, node, options)
        result: dict[str, Any] = {}
        error = ""
        try:
            if kind in API_KINDS:
                # Pure Proxmox-API jobs: no SSH involved.
                result = API_KINDS[kind](ctx)
            else:
                summary = json.loads(host.last_summary_json) if host.last_summary_json else None
                address = node_address(host, node, summary)
                ctx.log(f"Connecting to {node} ({host.ssh_user}@{address}:{host.ssh_port}) ...")
                with db_session() as db:
                    ctx.client = connect(db, host, node, address)
                ctx.log("Connected.")
                if kind == "check_updates":
                    result = _check_updates(ctx)
                elif kind == "upgrade":
                    result = _upgrade(ctx, options)
                elif kind == "reboot":
                    result = _reboot(ctx, address, options)
                else:
                    raise RuntimeError(f"Unknown job kind {kind}")
        except (SshError, PveError, RuntimeError) as exc:
            error = str(exc)
            ctx.log(f"ERROR: {error}")
        except Exception as exc:  # noqa: BLE001
            error = f"{exc.__class__.__name__}: {exc}"
            ctx.log(f"ERROR: {error}")
            log.exception("Job %s failed", job_id)
        finally:
            if ctx.client is not None:
                try:
                    ctx.client.close()
                except Exception:  # noqa: BLE001
                    pass
            ctx.flush()

        with db_session() as db:
            job = db.get(Job, job_id)
            if job:
                job.finished_at = _now()
                job.result_json = json.dumps(result)
                job.error = error
                if error or result.get("exit_code") not in (None, 0):
                    job.status = "failed"
                elif result.get("warning"):
                    job.status = "warning"
                else:
                    job.status = "done"
    finally:
        with _lock:
            _running.discard(job_id)


# --------------------------------------------------------------------------- #
# API-only jobs (no SSH): refresh package lists, reboot
# --------------------------------------------------------------------------- #

def _api_call(fn, what: str, privilege: str, path: str = "/nodes"):
    """Run a PVE API call, translating permission errors into a clear message."""
    try:
        return fn()
    except ResourceException as exc:
        msg = str(exc)
        if "403" in msg or "Permission check failed" in msg:
            raise RuntimeError(
                f"Permission denied for {what}: the API token/user needs {privilege} on {path} "
                "(a root@pam token without privilege separation has it)."
            ) from exc
        raise RuntimeError(f"{what} failed: {msg[:300]}") from exc


def _follow_task(ctx: _Ctx, api, upid: str, timeout: int) -> tuple[str, str]:
    """Stream a PVE task's log into the job until it stops. Returns its exit status."""
    seen = 0
    text = ""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lines = _safe_task_log(api, ctx.node, upid, seen)
        for line in lines:
            ctx.append(line.get("t", "") + "\n")
            text += line.get("t", "") + "\n"
        seen += len(lines)
        status = api.nodes(ctx.node).tasks(upid).status.get()
        if status.get("status") == "stopped":
            for line in _safe_task_log(api, ctx.node, upid, seen):
                ctx.append(line.get("t", "") + "\n")
                text += line.get("t", "") + "\n"
            return status.get("exitstatus", "unknown"), text
        time.sleep(1.5)
    raise RuntimeError(f"Task {upid} did not finish within {timeout}s")


def _safe_task_log(api, node: str, upid: str, start: int) -> list[dict]:
    try:
        return api.nodes(node).tasks(upid).log.get(start=start, limit=500) or []
    except ResourceException:
        return []


def _node_status(api, node: str) -> dict[str, Any]:
    st = api.nodes(node).status.get() or {}
    kparts = (st.get("kversion") or "").split()
    return {"uptime": int(st.get("uptime") or 0), "kernel": kparts[1] if len(kparts) >= 2 else ""}


def _api_refresh_packages(ctx: _Ctx) -> dict[str, Any]:
    ctx.log(f"Asking Proxmox to refresh the package lists on {ctx.node} (API: POST /nodes/{ctx.node}/apt/update) ...")
    api = pve_connect(ctx.host)
    upid = _api_call(lambda: api.nodes(ctx.node).apt.update.post(), "refreshing package lists", "Sys.Modify")
    ctx.log(f"Task {upid}")
    exitstatus, task_text = _follow_task(ctx, api, upid, timeout=600)
    repo = analyze_apt_output(task_text)
    if exitstatus != "OK":
        if not repo["repo_errors"]:
            raise RuntimeError(f"apt update task ended with: {exitstatus}")
        ctx.log("WARNING: " + repo["repo_hint"])

    pending = _api_call(lambda: api.nodes(ctx.node).apt.update.get(), "listing updates", "Sys.Modify") or []
    updates = [{"package": p.get("Package", ""), "old": p.get("OldVersion", ""), "new": p.get("Version", "")} for p in pending]
    kernel = [u["package"] for u in updates if is_kernel_package(u["package"])]
    if updates:
        ctx.log(f"{len(updates)} package(s) can be upgraded:")
        for u in updates:
            ctx.append(f"    {u['package']}: {u['old'] or '(new)'} -> {u['new']}\n")
        if kernel:
            ctx.log("A kernel update is included - a reboot will be needed after upgrading.")
        ctx.log("To install: use 'Update node (SSH)'." if ctx.host.ssh_enabled
                else "To install: use 'Upgrade shell' on this node (runs pveupgrade in the Proxmox web UI).")
    else:
        ctx.log("System is up to date.")
    ctx.flush()
    _repoll(ctx)
    return {"count": len(updates), "updates": updates, "kernel_in_updates": kernel, "warning": bool(repo["repo_errors"]), **repo}


def _api_reboot(ctx: _Ctx) -> dict[str, Any]:
    api = pve_connect(ctx.host)
    before = _api_call(lambda: _node_status(api, ctx.node), "reading node status", "Sys.Audit")
    ctx.log(f"Running kernel: {before['kernel']}, uptime {before['uptime'] // 3600}h")
    ctx.log(f"Issuing reboot via API (POST /nodes/{ctx.node}/status command=reboot). Guests on this node will be shut down "
            "(or migrated first if HA-managed) and started again per their start-at-boot setting.")
    _api_call(lambda: api.nodes(ctx.node).status.post(command="reboot"), "rebooting the node", "Sys.PowerMgmt")
    t0 = time.monotonic()
    went_down = False
    after = None
    deadline = t0 + REBOOT_TIMEOUT
    ctx.flush()
    while time.monotonic() < deadline:
        time.sleep(5)
        try:
            api = pve_connect(ctx.host)
            st = _node_status(api, ctx.node)
        except Exception:  # noqa: BLE001 - node (or the API endpoint itself) is down
            if not went_down:
                ctx.log("Node is down, waiting for it to come back ...")
                ctx.flush()
            went_down = True
            continue
        elapsed = time.monotonic() - t0
        if st["uptime"] and st["uptime"] < before["uptime"] and st["uptime"] <= elapsed + 60:
            after = st
            break
    if after is None:
        raise RuntimeError(f"Node did not come back within {REBOOT_TIMEOUT // 60} minutes. Check it via IPMI / the PVE console.")
    elapsed = int(time.monotonic() - t0)
    changed = after["kernel"] != before["kernel"]
    ctx.log(f"Node is back after {elapsed}s. Kernel: {after['kernel']}" + (f" (was {before['kernel']})" if changed else " (unchanged)"))
    _repoll(ctx)
    return {
        "went_down": went_down,
        "back": True,
        "seconds": elapsed,
        "kernel_before": before["kernel"],
        "running_kernel": after["kernel"],
        "kernel_changed": changed,
        "via": "api",
    }


def _repo_get(r: dict, key: str, default=None):
    """Repository objects from the API use capitalised deb822 keys (Enabled, URIs, ...)."""
    for k in (key, key.lower()):
        if k in r:
            return r[k]
    return default


def _api_switch_repos(ctx: _Ctx) -> dict[str, Any]:
    """Disable enterprise repositories and add the matching no-subscription ones, using the
    same API the Proxmox web UI uses (Node > Updates > Repositories). Needs Sys.Modify."""
    api = pve_connect(ctx.host)
    node = ctx.node
    get = lambda: _api_call(lambda: api.nodes(node).apt.repositories.get(), "reading repositories", "Sys.Audit")
    cfg = get()

    # 1) disable every enabled entry that points at enterprise.proxmox.com
    disabled = []
    for f in cfg.get("files") or []:
        for idx, repo in enumerate(f.get("repositories") or []):
            uris = " ".join(_repo_get(repo, "URIs", []) or [])
            if "enterprise.proxmox.com" in uris and _repo_get(repo, "Enabled", True) in (True, 1, "1"):
                ctx.log(f"Disabling {uris} ({f.get('path')} entry {idx})")
                cfg = get()  # fresh digest for each change
                _api_call(lambda: api.nodes(node).apt.repositories.post(
                    path=f["path"], index=idx, enabled=0, digest=cfg.get("digest")), "disabling a repository", "Sys.Modify")
                disabled.append(uris)

    # 2) add/enable the no-subscription counterparts
    cfg = get()
    std = {r.get("handle"): r for r in cfg.get("standard-repos") or []}
    wanted = ["no-subscription"]
    for h in std:
        if h.startswith("ceph-") and h.endswith("-enterprise"):
            ceph_was_used = any(h.split("-enterprise")[0].split("ceph-")[1] in u for u in disabled) or std[h].get("status") is not None
            nos = h.replace("-enterprise", "-no-subscription")
            if ceph_was_used and nos in std:
                wanted.append(nos)
    added = []
    for h in wanted:
        if h not in std:
            ctx.log(f"Standard repository '{h}' not offered by this node; skipping.")
            continue
        if std[h].get("status") in (True, 1, "1"):
            ctx.log(f"'{std[h].get('name', h)}' is already enabled.")
            continue
        ctx.log(f"Adding '{std[h].get('name', h)}' repository")
        cfg = get()
        _api_call(lambda: api.nodes(node).apt.repositories.put(handle=h, digest=cfg.get("digest")), "adding a repository", "Sys.Modify")
        added.append(h)

    if not disabled and not added:
        ctx.log("Nothing to change: no enabled enterprise repositories and no-subscription already present.")
    ctx.flush()

    # 3) refresh package lists so the effect is visible immediately
    ctx.log("Refreshing package lists ...")
    refresh = _api_refresh_packages(ctx)
    return {"disabled": disabled, "added": added, **refresh}


def _repoll(ctx: _Ctx) -> None:
    """Refresh the host's dashboard data right away so badges update."""
    try:
        from .poller import poll_host

        poll_host(ctx.host.id)
    except Exception:  # noqa: BLE001
        log.exception("Re-poll after job failed")


# --------------------------------------------------------------------------- #
# Guest jobs (Proxmox API only): power, snapshot, backup
# --------------------------------------------------------------------------- #

GUEST_POWER_TIMEOUT = 15 * 60
GUEST_SNAPSHOT_TIMEOUT = 60 * 60
GUEST_BACKUP_TIMEOUT = 12 * 60 * 60
SHUTDOWN_TIMEOUT = 180  # seconds a guest gets to shut down cleanly

POWER_ACTIONS = ("start", "shutdown", "reboot", "stop")
_POWER_WORDS = {"start": "Starting", "shutdown": "Shutting down", "reboot": "Rebooting", "stop": "Stopping (hard power off)"}
SNAPNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_\-]{1,39}$")
_ARCHIVE_RE = re.compile(r"creating (?:vzdump|Proxmox Backup Server) archive '([^']+)'")
_SIZE_RE = re.compile(r"archive file size: (\S+)")


def _guest_ref(ctx: _Ctx) -> tuple[int, str, str]:
    o = ctx.options
    vmid = int(o["vmid"])
    gtype = o.get("type") if o.get("type") in ("qemu", "lxc") else "qemu"
    label = f"{'VM' if gtype == 'qemu' else 'CT'} {vmid}" + (f" ({o['name']})" if o.get("name") else "")
    return vmid, gtype, label


def _guest_api(api, node: str, gtype: str, vmid: int):
    """api.nodes(node).qemu(vmid) or .lxc(vmid)"""
    return getattr(api.nodes(node), gtype)(vmid)


def _guest_status(api, node: str, gtype: str, vmid: int) -> str:
    try:
        return (_guest_api(api, node, gtype, vmid).status.current.get() or {}).get("status", "")
    except Exception:  # noqa: BLE001
        return ""


def _api_guest_power(ctx: _Ctx) -> dict[str, Any]:
    vmid, gtype, label = _guest_ref(ctx)
    action = ctx.options.get("action")
    if action not in POWER_ACTIONS:
        raise RuntimeError(f"Unknown power action {action!r}")
    api = pve_connect(ctx.host)
    params: dict[str, Any] = {}
    if action == "shutdown":
        params["timeout"] = SHUTDOWN_TIMEOUT
        if ctx.options.get("force_stop"):
            params["forceStop"] = 1
    ctx.log(f"{_POWER_WORDS[action]} {label} on {ctx.node} (API: POST /nodes/{ctx.node}/{gtype}/{vmid}/status/{action}) ...")
    if action == "shutdown":
        ctx.log(f"The guest gets {SHUTDOWN_TIMEOUT // 60} minutes to shut down cleanly"
                + (", then it is stopped hard." if params.get("forceStop") else "; if it doesn't, the task fails and the guest keeps running."))
    upid = _api_call(lambda: getattr(_guest_api(api, ctx.node, gtype, vmid).status, action).post(**params),
                     f"{action} of {label}", "VM.PowerMgmt", f"/vms/{vmid}")
    ctx.log(f"Task {upid}")
    exitstatus, _ = _follow_task(ctx, api, upid, GUEST_POWER_TIMEOUT)
    status = _guest_status(api, ctx.node, gtype, vmid)
    _repoll(ctx)
    if exitstatus != "OK":
        raise RuntimeError(f"Proxmox task ended with: {exitstatus}" + (f" ({label} is {status})" if status else ""))
    ctx.log(f"Done. {label} is now {status or 'in an unknown state'}.")
    return {"action": action, "vmid": vmid, "type": gtype, "status_after": status, "exitstatus": exitstatus}


def _api_guest_snapshot(ctx: _Ctx) -> dict[str, Any]:
    vmid, gtype, label = _guest_ref(ctx)
    o = ctx.options
    name = o.get("snapname", "")
    if not SNAPNAME_RE.match(name):
        raise RuntimeError("Snapshot name must start with a letter and use only letters, digits, - and _ (2-40 characters).")
    params: dict[str, Any] = {"snapname": name}
    if o.get("description"):
        params["description"] = o["description"]
    if gtype == "qemu" and o.get("vmstate"):
        params["vmstate"] = 1
    api = pve_connect(ctx.host)
    ctx.log(f"Taking snapshot '{name}' of {label}" + (" including RAM" if params.get("vmstate") else "")
            + f" (API: POST /nodes/{ctx.node}/{gtype}/{vmid}/snapshot) ...")
    upid = _api_call(lambda: _guest_api(api, ctx.node, gtype, vmid).snapshot.post(**params),
                     f"snapshot of {label}", "VM.Snapshot", f"/vms/{vmid}")
    ctx.log(f"Task {upid}")
    exitstatus, _ = _follow_task(ctx, api, upid, GUEST_SNAPSHOT_TIMEOUT)
    if exitstatus != "OK":
        raise RuntimeError(f"Snapshot task ended with: {exitstatus}")
    ctx.log(f"Snapshot '{name}' created. Roll back or delete it in the Proxmox web UI ({label} > Snapshots).")
    return {"vmid": vmid, "type": gtype, "snapname": name, "vmstate": bool(params.get("vmstate")), "exitstatus": exitstatus}


def _api_guest_backup(ctx: _Ctx) -> dict[str, Any]:
    vmid, gtype, label = _guest_ref(ctx)
    o = ctx.options
    storage, mode = o.get("storage", ""), o.get("mode", "snapshot")
    compress = o.get("compress", "") if o.get("storage_type") != "pbs" else ""
    params: dict[str, Any] = {"vmid": vmid, "storage": storage, "mode": mode}
    if compress:
        params["compress"] = compress
    if o.get("notes"):
        params["notes-template"] = o["notes"]
    api = pve_connect(ctx.host)
    ctx.log(f"Backing up {label} to storage '{storage}' (mode {mode}" + (f", {compress}" if compress else "")
            + f") (API: POST /nodes/{ctx.node}/vzdump) ...")
    if mode == "stop":
        ctx.log("Mode 'stop': the guest is shut down for the backup and started again afterwards.")
    upid = _api_call(lambda: api.nodes(ctx.node).vzdump.post(**params), f"backup of {label}",
                     f"VM.Backup on /vms/{vmid} and Datastore.AllocateSpace", f"/storage/{storage}")
    ctx.log(f"Task {upid}")
    exitstatus, text = _follow_task(ctx, api, upid, GUEST_BACKUP_TIMEOUT)
    m, s = _ARCHIVE_RE.search(text), _SIZE_RE.search(text)
    result: dict[str, Any] = {"vmid": vmid, "type": gtype, "storage": storage, "mode": mode,
                              "archive": m.group(1) if m else "", "size": s.group(1) if s else "", "exitstatus": exitstatus}
    if mode == "stop":
        _repoll(ctx)
    if exitstatus.startswith("WARNINGS"):
        result["warning"] = True
        ctx.log(f"Backup finished with {exitstatus.lower()} (see the log above).")
    elif exitstatus != "OK":
        raise RuntimeError(f"Backup task ended with: {exitstatus}")
    else:
        ctx.log("Backup finished" + (f": {result['archive']}" if result["archive"] else "") + (f" ({result['size']})" if result["size"] else "") + ".")
    return result


GUEST_RESIZE_TIMEOUT = 30 * 60


def _api_guest_resize(ctx: _Ctx) -> dict[str, Any]:
    vmid, gtype, label = _guest_ref(ctx)
    o = ctx.options
    disk, add, storage = o.get("disk", ""), int(o.get("add_gb") or 0), o.get("storage", "")
    before = o.get("size_before", "")
    if add < 1:
        raise RuntimeError("Nothing to add.")
    api = pve_connect(ctx.host)
    ctx.log(f"Expanding {disk} of {label} by {add} GiB" + (f" (now {before})" if before else "")
            + f" (API: PUT /nodes/{ctx.node}/{gtype}/{vmid}/resize disk={disk} size=+{add}G) ...")
    res = _api_call(lambda: _guest_api(api, ctx.node, gtype, vmid).resize.put(disk=disk, size=f"+{add}G"),
                    f"disk resize of {label}", f"VM.Config.Disk on /vms/{vmid} and Datastore.AllocateSpace", f"/storage/{storage}")
    if isinstance(res, str) and res.startswith("UPID:"):
        ctx.log(f"Task {res}")
        exitstatus, _ = _follow_task(ctx, api, res, GUEST_RESIZE_TIMEOUT)
        if exitstatus != "OK":
            raise RuntimeError(f"Resize task ended with: {exitstatus}")
    after = ""
    try:
        cfg = _guest_api(api, ctx.node, gtype, vmid).config.get() or {}
        after = next((x.split("=", 1)[1] for x in str(cfg.get(disk, "")).split(",") if x.startswith("size=")), "")
    except Exception:  # noqa: BLE001
        pass
    ctx.log(f"Done. {disk} is now {after or 'larger'}" + (f" (was {before})." if before else "."))
    if gtype == "qemu":
        ctx.log("Proxmox only grows the virtual disk. Extend the partition and filesystem inside the guest: "
                "Linux e.g. growpart /dev/sda 1 && resize2fs /dev/sda1 (xfs_growfs / for XFS); "
                "Windows: Disk Management > Extend Volume.")
    else:
        ctx.log("Proxmox grew the container's filesystem as well; nothing to do inside the container.")
    return {"vmid": vmid, "type": gtype, "disk": disk, "added_gb": add, "size_before": before, "size_after": after}


def _onboot_on(cfg: dict) -> bool:
    try:
        return int(cfg.get("onboot") or 0) == 1
    except (TypeError, ValueError):
        return False


def _api_guest_onboot(ctx: _Ctx) -> dict[str, Any]:
    """Turn "Start at boot" on or off (PUT /nodes/{node}/{type}/{vmid}/config onboot=0|1).

    The current config is read first: if it already has the wanted value nothing is written,
    otherwise the change is sent with the config digest so Proxmox refuses it if someone
    else changed the guest's config in between. Nothing restarts; Proxmox applies onboot
    straight away and uses it the next time the node boots.
    """
    vmid, gtype, label = _guest_ref(ctx)
    want = bool(ctx.options.get("onboot"))
    word = "on" if want else "off"
    api = pve_connect(ctx.host)
    gapi = _guest_api(api, ctx.node, gtype, vmid)
    cfg = _api_call(lambda: gapi.config.get() or {}, f"reading the config of {label}", "VM.Audit", f"/vms/{vmid}")
    before = _onboot_on(cfg)
    ctx.log(f"Start at boot for {label} is currently {'on' if before else 'off'}.")
    if before == want:
        ctx.log(f"Nothing to change; it is already {word}.")
        return {"vmid": vmid, "type": gtype, "onboot": want, "onboot_before": before, "changed": False}
    params: dict[str, Any] = {"onboot": 1 if want else 0}
    if cfg.get("digest"):
        params["digest"] = cfg["digest"]
    ctx.log(f"Turning Start at boot {word} (API: PUT /nodes/{ctx.node}/{gtype}/{vmid}/config onboot={params['onboot']}) ...")
    try:
        res = _api_call(lambda: gapi.config.put(**params), f"changing Start at boot of {label}",
                        "VM.Config.Options", f"/vms/{vmid}")
    except RuntimeError as exc:
        if "digest" in str(exc).lower() or "modified configuration" in str(exc).lower():
            raise RuntimeError(f"The config of {label} was changed in Proxmox at the same moment, so nothing was "
                               "changed. Open More again to see the current value and try again.") from exc
        raise
    if isinstance(res, str) and res.startswith("UPID:"):
        ctx.log(f"Task {res}")
        exitstatus, _ = _follow_task(ctx, api, res, 120)
        if exitstatus != "OK":
            raise RuntimeError(f"Config task ended with: {exitstatus}")
    after = _onboot_on(_api_call(lambda: gapi.config.get() or {}, f"reading the config of {label}", "VM.Audit", f"/vms/{vmid}"))
    if after != want:
        raise RuntimeError(f"Proxmox accepted the change but the config still says Start at boot is {'on' if after else 'off'}.")
    ctx.log(f"Done. Start at boot is now {word} for {label}. {label} itself was not touched; this applies "
            f"the next time {ctx.node} boots.")
    return {"vmid": vmid, "type": gtype, "onboot": after, "onboot_before": before, "changed": True}


API_KINDS = {
    "refresh_packages": _api_refresh_packages,
    "api_reboot": _api_reboot,
    "switch_repos": _api_switch_repos,
    "guest_power": _api_guest_power,
    "guest_snapshot": _api_guest_snapshot,
    "guest_backup": _api_guest_backup,
    "guest_resize": _api_guest_resize,
    "guest_onboot": _api_guest_onboot,
}


# --------------------------------------------------------------------------- #
# Reboot-required detection (used by check and after upgrade)
# --------------------------------------------------------------------------- #

def _reboot_state(ctx: _Ctx) -> dict[str, Any]:
    rc, out = ctx.sh(
        "uname -r; echo __SEP__; "
        "test -f /var/run/reboot-required && echo yes || echo no; echo __SEP__; "
        "cat /var/run/reboot-required.pkgs 2>/dev/null; echo __SEP__; "
        "dpkg-query -W -f='${Package}\\t${Status}\\n' 'proxmox-kernel-*' 'pve-kernel-*' 2>/dev/null | grep 'install ok installed' | cut -f1",
        timeout=60,
    )
    parts = out.split("__SEP__")
    running = parts[0].strip() if parts else ""
    flag = parts[1].strip() == "yes" if len(parts) > 1 else False
    flag_pkgs = [p.strip() for p in parts[2].splitlines() if p.strip()] if len(parts) > 2 else []
    installed = [p.strip() for p in parts[3].splitlines() if p.strip()] if len(parts) > 3 else []
    newest = ""
    for pkg in installed:
        m = re.match(r"^(?:proxmox|pve)-kernel-(\d+\.\d+\.\d+-\d+-pve)(?:-signed)?$", pkg)
        if m and (not newest or kernel_sort_key(m.group(1)) > kernel_sort_key(newest)):
            newest = m.group(1)
    kernel_pending = bool(running and newest and kernel_sort_key(newest) > kernel_sort_key(running))
    reasons = []
    if kernel_pending:
        reasons.append(f"new kernel {newest} installed, running {running}")
    if flag:
        reasons.append("/var/run/reboot-required is set" + (f" ({', '.join(flag_pkgs)})" if flag_pkgs else ""))
    return {
        "running_kernel": running,
        "newest_kernel": newest,
        "reboot_required": kernel_pending or flag,
        "reboot_reason": "; ".join(reasons),
    }


# --------------------------------------------------------------------------- #
# check_updates
# --------------------------------------------------------------------------- #

_FETCH_ERR_RE = re.compile(r"^(?:E|W|Err):?\s*Failed to fetch (\S+)\s+(\d{3})?\s*(.*)$")
_ERR_LINE_RE = re.compile(r"^Err:\d+\s+(\S+)\s+(\S+)\s+(\S+)")
_UPGRADED_RE = re.compile(r"(\d+) upgraded, (\d+) newly installed, (\d+) to remove and (\d+) not upgraded")


def analyze_apt_output(text: str) -> dict[str, Any]:
    """Find repositories apt could not read, and explain the common Proxmox case."""
    failed: dict[str, dict] = {}
    for line in text.splitlines():
        line = line.strip()
        m = _FETCH_ERR_RE.match(line)
        if m:
            url = m.group(1)
            base = url.split("/dists/")[0]
            code = m.group(2) or ""
            failed.setdefault(base, {"repo": base, "code": code, "detail": (m.group(3) or "").strip()})
    repos = list(failed.values())
    enterprise = [r for r in repos if "enterprise.proxmox.com" in r["repo"]]
    suite_m = re.search(r"enterprise\.proxmox\.com/debian/\S+?/dists/([a-z]+)/", text)
    suite = suite_m.group(1) if suite_m else ""
    ceph = sorted({m.group(1) for m in re.finditer(r"enterprise\.proxmox\.com/debian/(ceph-[a-z]+)", text)})
    hint = ""
    if enterprise and all(r["code"] in ("401", "") for r in enterprise):
        hint = ("The node is set to the Proxmox ENTERPRISE repositories but has no subscription key, so "
                "enterprise.proxmox.com refuses it (401). Proxmox packages (pve-manager, kernel, ceph) were NOT "
                "checked or upgraded. Either add the subscription key, or switch the node to the "
                "no-subscription repositories (Node > Updates > Repositories in the Proxmox UI).")
    elif repos:
        hint = "Some repositories could not be read, so their packages were not checked: " + ", ".join(r["repo"] for r in repos)
    fix = no_subscription_fix(suite, ceph[0] if ceph else "") if enterprise else ""
    return {"repo_errors": repos, "enterprise_no_subscription": bool(enterprise), "repo_hint": hint, "repo_fix": fix}


def no_subscription_fix(suite: str, ceph: str) -> str:
    """Shell commands that switch a node from enterprise to no-subscription repositories.
    PVE 9 (trixie) uses deb822 .sources files; PVE 8 (bookworm) and older use .list files."""
    suite = suite or "trixie"
    if suite == "trixie":
        lines = [
            "# Switch to the Proxmox no-subscription repositories (PVE 9 / Debian trixie)",
            "f=/etc/apt/sources.list.d/pve-enterprise.sources",
            "[ -f \"$f\" ] && ! grep -q '^Enabled:' \"$f\" && echo 'Enabled: no' >> \"$f\"",
            "cat > /etc/apt/sources.list.d/proxmox.sources <<'EOF'",
            "Types: deb",
            "URIs: http://download.proxmox.com/debian/pve",
            "Suites: trixie",
            "Components: pve-no-subscription",
            "Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg",
            "EOF",
        ]
        if ceph:
            lines += [
                "cat > /etc/apt/sources.list.d/ceph.sources <<'EOF'",
                "Types: deb",
                f"URIs: http://download.proxmox.com/debian/{ceph}",
                "Suites: trixie",
                "Components: no-subscription",
                "Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg",
                "EOF",
            ]
    else:
        lines = [
            f"# Switch to the Proxmox no-subscription repositories (Debian {suite})",
            "sed -i 's/^deb/# deb/' /etc/apt/sources.list.d/pve-enterprise.list",
            f"echo 'deb http://download.proxmox.com/debian/pve {suite} pve-no-subscription' > /etc/apt/sources.list.d/pve-no-subscription.list",
        ]
        if ceph:
            lines.append(f"echo 'deb http://download.proxmox.com/debian/{ceph} {suite} no-subscription' > /etc/apt/sources.list.d/ceph.list")
    lines.append("apt-get update")
    return "\n".join(lines)


_INST_RE = re.compile(r"^Inst (\S+) (?:\[(\S+)\] )?\((\S+) ")
_REMV_RE = re.compile(r"^Remv (\S+) \[(\S+)\]")


def _check_updates(ctx: _Ctx) -> dict[str, Any]:
    ctx.log("Refreshing package lists (apt-get update) ...")
    rc, out = ctx.sh(f"{APT_ENV} apt-get update -q 2>&1", timeout=300)
    ctx.append(out if out.endswith("\n") else out + "\n")
    repo = analyze_apt_output(out)
    if rc != 0 and not repo["repo_errors"]:
        raise RuntimeError(f"apt-get update failed with exit code {rc} (see output above).")
    if repo["repo_errors"]:
        ctx.log("WARNING: " + repo["repo_hint"])

    ctx.log("Simulating dist-upgrade ...")
    rc, out = ctx.sh(f"{APT_ENV} apt-get -s -o Debug::NoLocking=true dist-upgrade 2>&1", timeout=300)
    updates, removals = [], []
    for line in out.splitlines():
        m = _INST_RE.match(line)
        if m:
            updates.append({"package": m.group(1), "old": m.group(2) or "", "new": m.group(3)})
            continue
        m = _REMV_RE.match(line)
        if m:
            removals.append({"package": m.group(1), "old": m.group(2)})
    if rc != 0:
        ctx.append(out + "\n")
        raise RuntimeError(f"apt-get -s dist-upgrade failed with exit code {rc}.")

    state = _reboot_state(ctx)
    kernel_in_updates = [u["package"] for u in updates if is_kernel_package(u["package"])]
    if updates:
        ctx.log(f"{len(updates)} package(s) can be upgraded" + (f", {len(removals)} removed" if removals else "") + ":")
        for u in updates:
            ctx.append(f"    {u['package']}: {u['old'] or '(new)'} -> {u['new']}\n")
        for r in removals:
            ctx.append(f"    remove {r['package']} ({r['old']})\n")
    else:
        ctx.log("System is up to date.")
    if kernel_in_updates:
        ctx.log(f"A kernel update is included ({', '.join(kernel_in_updates)}) - a reboot will be needed afterwards.")
    if state["reboot_required"]:
        ctx.log(f"Reboot already pending: {state['reboot_reason']}.")
    return {
        "updates": updates,
        "removals": removals,
        "count": len(updates),
        "kernel_in_updates": kernel_in_updates,
        "warning": bool(repo["repo_errors"]),
        **repo,
        **state,
    }


# --------------------------------------------------------------------------- #
# upgrade
# --------------------------------------------------------------------------- #

def _upgrade(ctx: _Ctx, options: dict) -> dict[str, Any]:
    auto_reboot = bool(options.get("auto_reboot"))
    logfile = f"{LOG_DIR}/upgrade-{int(time.time())}-{ctx.job_id}.log"
    script = (
        f"export {APT_ENV}; "
        "echo \"== apt-get update ==\"; apt-get update -q; echo \"__PM_UPDATE_RC__ $?\"; "
        "echo; echo \"== apt-get dist-upgrade ==\"; "
        f"apt-get {APT_OPTS} dist-upgrade; rc=$?; "
        "echo; echo \"== apt-get autoremove ==\"; "
        f"apt-get {APT_OPTS} autoremove; "
        'echo "__PM_EXIT__ $rc"'
    )
    # Only the nohup'd process may go to the background, with every fd redirected, so the
    # SSH command returns immediately. (An earlier "mkdir && nohup ... &" backgrounded the
    # whole AND-list in a subshell that kept the channel open until apt finished.)
    launcher = (
        f"mkdir -p {LOG_DIR}; "
        f"{{ nohup setsid bash -c {shlex.quote(script)} > {shlex.quote(logfile)} 2>&1 < /dev/null & }}; "
        "echo started"
    )
    # Refuse to start if apt/dpkg is already busy (another upgrade, unattended-upgrades...).
    rc, out = ctx.sh("fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock >/dev/null 2>&1 && echo busy || echo free", timeout=30)
    if "busy" in out:
        raise RuntimeError("apt/dpkg is already running on this node (another upgrade in progress?). Try again later.")

    ctx.log(f"Starting detached upgrade on {ctx.node}; log on node: {logfile}")
    try:
        rc, out = ctx.sh(launcher, timeout=30)
        started = rc == 0 and "started" in out
    except SshError as exc:
        # The launch may have succeeded even if the channel did not close; check for the log.
        ctx.log(f"Launcher did not return cleanly ({exc}); checking whether the upgrade is running ...")
        with db_session() as db:
            ctx.client = connect(db, ctx.host, ctx.node)
        out = ""
        started = False
    if not started:
        rc2, chk = ctx.sh(f"test -s {shlex.quote(logfile)} && echo present || echo missing", timeout=30)
        if "present" not in chk:
            raise RuntimeError(f"Could not start the upgrade: {out.strip() or 'no log file created'}")
        ctx.log("Upgrade is running on the node; following its log.")

    # Tail the log until the exit marker appears.
    offset = 0
    full_log = ""
    exit_code: int | None = None
    deadline = time.monotonic() + UPGRADE_TIMEOUT
    quiet_polls = 0
    while time.monotonic() < deadline:
        time.sleep(2 if quiet_polls < 5 else 5)
        try:
            rc, chunk = ctx.sh(f"tail -c +{offset + 1} {shlex.quote(logfile)}", timeout=60)
        except SshError as exc:
            # Connection dropped (e.g. sshd restarted by the upgrade). Reconnect and keep tailing.
            ctx.log(f"SSH hiccup ({exc}); reconnecting ...")
            time.sleep(5)
            with db_session() as db:
                ctx.client = connect(db, ctx.host, ctx.node)
            continue
        if chunk:
            offset += len(chunk.encode("utf-8", "replace"))
            quiet_polls = 0
            m = re.search(r"__PM_EXIT__ (\d+)", chunk)
            if m:
                exit_code = int(m.group(1))
                chunk = chunk[: m.start()]
            full_log += chunk
            ctx.append(re.sub(r"__PM_UPDATE_RC__ \d+\n?", "", chunk))
            if exit_code is not None:
                break
        else:
            quiet_polls += 1
    ctx.flush()
    if exit_code is None:
        raise RuntimeError(
            f"Gave up waiting after {UPGRADE_TIMEOUT // 60} minutes. The upgrade may still be running on the node; "
            f"check {logfile} there."
        )

    ctx.log(f"dist-upgrade finished with exit code {exit_code}.")
    m = re.search(r"__PM_UPDATE_RC__ (\d+)", full_log)
    update_rc = int(m.group(1)) if m else None
    dist_part = full_log.split("== apt-get dist-upgrade ==", 1)[-1].split("== apt-get autoremove ==", 1)[0]
    cm = _UPGRADED_RE.search(dist_part)
    counts = {"upgraded": int(cm.group(1)), "newly_installed": int(cm.group(2)), "removed": int(cm.group(3)),
              "held_back": int(cm.group(4))} if cm else {}
    repo = analyze_apt_output(full_log.split("== apt-get dist-upgrade ==", 1)[0])
    if counts:
        ctx.log(f"{counts['upgraded']} upgraded, {counts['newly_installed']} newly installed, "
                f"{counts['removed']} removed, {counts['held_back']} held back.")
    if repo["repo_errors"]:
        ctx.log("WARNING: " + repo["repo_hint"])
    state = _reboot_state(ctx)
    result: dict[str, Any] = {"exit_code": exit_code, "logfile": logfile, "rebooted": False, "update_rc": update_rc,
                              "warning": bool(repo["repo_errors"]), **counts, **repo, **state}
    if state["reboot_required"]:
        ctx.log(f"REBOOT REQUIRED: {state['reboot_reason']}.")
    else:
        ctx.log("No reboot required.")

    if exit_code == 0 and state["reboot_required"] and auto_reboot:
        ctx.log("Auto-reboot requested - rebooting node now. All guests on this node will stop or migrate.")
        _trigger_reboot(ctx)
        result["rebooted"] = True
    return result


# --------------------------------------------------------------------------- #
# reboot
# --------------------------------------------------------------------------- #

def _trigger_reboot(ctx: _Ctx) -> None:
    rc, out = ctx.sh("nohup setsid sh -c 'sleep 2; systemctl reboot' >/dev/null 2>&1 < /dev/null & echo scheduled", timeout=20)
    if "scheduled" not in out:
        raise RuntimeError(f"Could not schedule reboot: {out.strip()}")


def _port_open(address: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True
    except OSError:
        return False


def _reboot(ctx: _Ctx, address: str, options: dict) -> dict[str, Any]:
    before = _reboot_state(ctx)
    ctx.log(f"Running kernel before reboot: {before['running_kernel']}")
    ctx.log("Issuing reboot. All guests on this node will be stopped (or migrated by HA).")
    _trigger_reboot(ctx)
    ctx.client.close()
    ctx.client = None
    port = ctx.host.ssh_port or 22

    went_down = False
    t0 = time.monotonic()
    while time.monotonic() - t0 < 180:
        time.sleep(3)
        if not _port_open(address, port):
            went_down = True
            break
    ctx.log("Node is down, waiting for it to come back ..." if went_down else "Node still answering on SSH after 3 min; continuing to wait.")

    back = False
    deadline = time.monotonic() + REBOOT_TIMEOUT
    while time.monotonic() < deadline:
        time.sleep(5)
        if _port_open(address, port):
            # sshd answers early in boot; give PVE services a moment, then verify over SSH.
            time.sleep(10)
            try:
                with db_session() as db:
                    ctx.client = connect(db, ctx.host, ctx.node, address)
                back = True
                break
            except SshError as exc:
                ctx.log(f"SSH not ready yet: {exc}")
    if not back:
        raise RuntimeError(f"Node did not come back within {REBOOT_TIMEOUT // 60} minutes. Check it via the PVE console / IPMI.")

    rc, out = ctx.sh("uname -r; uptime -p; systemctl is-active pve-cluster pvedaemon pveproxy 2>/dev/null | tr '\\n' ' '", timeout=60)
    lines = out.splitlines()
    after_kernel = lines[0].strip() if lines else ""
    ctx.log(f"Node is back. Kernel: {after_kernel}; {lines[1].strip() if len(lines) > 1 else ''}; services: {lines[2].strip() if len(lines) > 2 else '?'}")
    elapsed = int(time.monotonic() - t0)
    return {
        "went_down": went_down,
        "back": True,
        "seconds": elapsed,
        "kernel_before": before["running_kernel"],
        "running_kernel": after_kernel,
        "kernel_changed": after_kernel != before["running_kernel"],
    }
