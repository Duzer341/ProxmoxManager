"""Proxmox VE API client wrapper and stat collection.

Everything here is synchronous (proxmoxer uses requests); the poller runs it in
worker threads.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

import urllib3
from proxmoxer import ProxmoxAPI
from proxmoxer.core import AuthenticationError, ResourceException

from . import crypto
from .config import settings
from .models import ProxmoxHost

log = logging.getLogger(__name__)

# Most PVE hosts run self-signed certs; we let the user opt in to verification per host.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PveError(Exception):
    """Human-readable failure talking to a Proxmox host."""


class ConsoleAuthError(PveError):
    """The root@pam password was rejected."""


def connect(host: ProxmoxHost, secret: str | None = None) -> ProxmoxAPI:
    """Build a ProxmoxAPI client for a host record (token or password auth)."""
    secret = secret if secret is not None else crypto.decrypt(host.secret_enc)
    common = dict(
        host=host.host,
        port=host.port,
        user=host.pve_user,
        verify_ssl=host.verify_ssl,
        timeout=settings.PVE_TIMEOUT,
    )
    try:
        if host.auth_type == "token":
            return ProxmoxAPI(token_name=host.token_name, token_value=secret, **common)
        return ProxmoxAPI(password=secret, **common)
    except AuthenticationError as exc:
        raise PveError(_describe(exc)) from exc
    except Exception as exc:  # connection refused, DNS, TLS...
        raise PveError(_describe(exc)) from exc


def _describe(exc: Exception) -> str:
    msg = str(exc) or exc.__class__.__name__
    low = msg.lower()
    if isinstance(exc, AuthenticationError) or "couldn't authenticate" in low:
        return "Authentication failed (check user, token/password and permissions)."
    if "certificate verify failed" in low or "ssl" in low and "verify" in low:
        return "TLS certificate verification failed (disable 'Verify SSL' for self-signed certs)."
    if "max retries" in low or "connection refused" in low or "name or service not known" in low:
        return "Could not connect (host unreachable, wrong port, or DNS failure)."
    if "timed out" in low or "timeout" in low:
        return "Connection timed out."
    if "401" in msg or "authentication" in low:
        return "Authentication failed (check user, token/password and permissions)."
    if "403" in msg or "permission" in low:
        return "Permission denied (the PVE user/token needs Sys.Audit on /, or the PVEAuditor role)."
    return msg[:300]


def _safe(call, default=None):
    """Call a PVE endpoint and swallow permission / not-found errors."""
    try:
        return call()
    except ResourceException as exc:
        log.debug("PVE call failed: %s", exc)
        return default


def _pct(used: float, total: float) -> float:
    return round(100.0 * used / total, 1) if total else 0.0


def _no_permission_message(host: ProxmoxHost) -> str:
    """PVE filters /nodes by permission, so an authenticated-but-unprivileged token
    gets an empty list rather than an error. Explain the two usual causes."""
    if host.auth_type == "token":
        tid = f"{host.pve_user}!{host.token_name}"
        return (
            "Authenticated, but the token has no permissions (the node list came back empty). "
            "The token was probably created with Privilege Separation enabled, which means it does "
            f"not inherit {host.pve_user}'s roles. Fix on the PVE host with:  "
            f"pveum acl modify / --tokens '{tid}' --roles PVEAuditor   "
            "or recreate the token with Privilege Separation unticked."
        )
    return (
        f"Authenticated, but {host.pve_user} has no permissions (the node list came back empty). "
        f"Grant a role with:  pveum acl modify / --users {host.pve_user} --roles PVEAuditor"
    )


def _fetch_nodes(api: ProxmoxAPI, host: ProxmoxHost) -> list[dict[str, Any]]:
    try:
        nodes = api.nodes.get() or []
    except ResourceException as exc:
        raise PveError(_describe(exc)) from exc
    except Exception as exc:
        raise PveError(_describe(exc)) from exc
    if not nodes:
        raise PveError(_no_permission_message(host))
    return nodes


KERNEL_PKG_RE = re.compile(r"^(?:proxmox|pve)-kernel-(\d+\.\d+\.\d+-\d+-pve)(?:-signed)?$")
KERNEL_META_RE = re.compile(r"^(?:proxmox|pve)-kernel(?:-\d+\.\d+)?$")


def is_kernel_package(name: str) -> bool:
    return bool(KERNEL_PKG_RE.match(name) or KERNEL_META_RE.match(name) or name.startswith("proxmox-kernel-"))


def kernel_sort_key(version: str) -> tuple:
    """'6.8.12-9-pve' -> (6, 8, 12, 9)"""
    nums = re.findall(r"\d+", version)
    return tuple(int(x) for x in nums[:4]) + (0,) * (4 - min(4, len(nums)))


def _node_updates(api: ProxmoxAPI, node: str, entry: dict[str, Any]) -> None:
    """Pending apt updates from the package lists PVE refreshes daily. Needs Sys.Modify."""
    try:
        pending = api.nodes(node).apt.update.get() or []
    except ResourceException as exc:
        msg = str(exc)
        entry["updates_error"] = "permission" if "403" in msg or "Permission" in msg else msg[:120]
        return
    except Exception as exc:  # noqa: BLE001
        entry["updates_error"] = str(exc)[:120]
        return
    entry["updates"] = len(pending)
    entry["updates_list"] = [
        {
            "package": p.get("Package", ""),
            "old": p.get("OldVersion", ""),
            "new": p.get("Version", ""),
            "title": p.get("Title", ""),
            "priority": p.get("Priority", ""),
            "origin": p.get("Origin", ""),
        }
        for p in pending
    ]
    entry["updates_kernel"] = any(is_kernel_package(p.get("Package", "")) for p in pending)


def _node_repos(api: ProxmoxAPI, node: str, entry: dict[str, Any]) -> None:
    """Flag repository setups where apt cannot see Proxmox updates:
    an enabled enterprise repo without an active subscription (apt gets 401s), or no
    Proxmox repo enabled at all. Uses /apt/repositories (Sys.Audit) and /subscription."""
    repos = _safe(lambda: api.nodes(node).apt.repositories.get(), None)
    if not repos:
        return  # older PVE or no permission: stay silent
    std = repos.get("standard-repos") or []
    enabled = [r.get("handle", "") for r in std if r.get("status") in (1, True, "1")]
    entry["repos_enabled"] = enabled
    sub = _safe(lambda: api.nodes(node).subscription.get(), {}) or {}
    status = (sub.get("status") or "").lower()
    entry["subscription"] = status
    ent = [h for h in enabled if "enterprise" in h]
    pve_repo = [h for h in enabled if h in ("enterprise", "no-subscription", "test")]
    if ent and status != "active":
        entry["repo_warning"] = "enterprise_no_subscription"
        entry["repo_warning_text"] = (
            "Enterprise repository enabled (" + ", ".join(ent) + ") but the subscription status is '"
            + (status or "unknown") + "'. apt gets 401 from enterprise.proxmox.com, so Proxmox updates "
            "are invisible and this node can show 'up to date' while it is not. Fix: Node > Updates > "
            "Repositories: disable Enterprise, add No-Subscription (or add the subscription key)."
        )
    elif not pve_repo:
        entry["repo_warning"] = "no_pve_repo"
        entry["repo_warning_text"] = "No Proxmox VE package repository is enabled, so Proxmox updates cannot be installed."


def _node_kernels(api: ProxmoxAPI, node: str, entry: dict[str, Any]) -> None:
    """Compare the running kernel with the newest installed kernel package (Sys.Audit)."""
    versions = _safe(lambda: api.nodes(node).apt.versions.get(), []) or []
    running = ""
    newest = ""
    for p in versions:
        if p.get("Package") == "proxmox-ve" and p.get("RunningKernel"):
            running = p["RunningKernel"]
        m = KERNEL_PKG_RE.match(p.get("Package", ""))
        if m and (p.get("CurrentState") or "Installed") == "Installed":
            ver = m.group(1)
            if not newest or kernel_sort_key(ver) > kernel_sort_key(newest):
                newest = ver
    if running and not entry["kernel"]:
        entry["kernel"] = running
    running = running or entry["kernel"]
    entry["newest_kernel"] = newest
    entry["kernel_reboot_pending"] = bool(running and newest and kernel_sort_key(newest) > kernel_sort_key(running))


# --------------------------------------------------------------------------- #
# Collection
# --------------------------------------------------------------------------- #

def collect_summary(host: ProxmoxHost) -> dict[str, Any]:
    """Pull everything the dashboard needs for one host (or its whole cluster)."""
    started = time.monotonic()
    api = connect(host)

    try:
        version = api.version.get()
    except AuthenticationError as exc:
        raise PveError(_describe(exc)) from exc
    except ResourceException as exc:
        raise PveError(_describe(exc)) from exc
    except Exception as exc:
        raise PveError(_describe(exc)) from exc

    nodes_raw = _fetch_nodes(api, host)
    resources = _safe(lambda: api.cluster.resources.get(), []) or []
    cluster_status = _safe(lambda: api.cluster.status.get(), []) or []

    cluster_name = ""
    quorate = None
    node_ips: dict[str, str] = {}
    for item in cluster_status:
        if item.get("type") == "cluster":
            cluster_name = item.get("name", "")
            quorate = bool(item.get("quorate", 0))
        elif item.get("type") == "node" and item.get("ip"):
            node_ips[item.get("name", "")] = item["ip"]

    # ---- nodes -----------------------------------------------------------
    nodes: list[dict[str, Any]] = []
    total_cpu_weighted = 0.0
    total_cores = 0
    mem_used = mem_total = 0
    updates_total = 0
    updates_known = False
    for n in nodes_raw:
        online = n.get("status") == "online"
        maxcpu = int(n.get("maxcpu") or 0)
        cpu = float(n.get("cpu") or 0.0)
        nmem = int(n.get("mem") or 0)
        nmaxmem = int(n.get("maxmem") or 0)
        node_entry = {
            "node": n.get("node"),
            "status": n.get("status", "unknown"),
            "online": online,
            "ip": node_ips.get(n.get("node"), ""),
            "cpu_pct": round(cpu * 100, 1),
            "cores": maxcpu,
            "mem_used": nmem,
            "mem_total": nmaxmem,
            "mem_pct": _pct(nmem, nmaxmem),
            "rootfs_used": int(n.get("disk") or 0),
            "rootfs_total": int(n.get("maxdisk") or 0),
            "uptime": int(n.get("uptime") or 0),
            "pve_version": "",
            "kernel": "",
            "cpu_model": "",
            "loadavg": [],
            # apt / kernel state (see _node_updates / _node_kernels)
            "updates": None,  # pending package count, None = unknown
            "updates_error": "",
            "updates_kernel": False,  # a kernel package is among the pending updates
            "updates_list": [],
            "newest_kernel": "",
            "kernel_reboot_pending": False,
            "repos_enabled": None,
            "subscription": "",
            "repo_warning": "",
            "repo_warning_text": "",
        }
        if online:
            total_cpu_weighted += cpu * maxcpu
            total_cores += maxcpu
            mem_used += nmem
            mem_total += nmaxmem
            st = _safe(lambda: api.nodes(n["node"]).status.get(), {}) or {}
            # "pve-manager/8.4.1/2a5fa54a8503f96d" -> "8.4.1"
            pvever = st.get("pveversion", "") or ""
            parts = pvever.split("/")
            node_entry["pve_version"] = parts[1] if len(parts) >= 2 else pvever
            node_entry["pve_version_full"] = pvever
            # "Linux 6.8.12-9-pve #1 SMP PREEMPT_DYNAMIC ..." -> "6.8.12-9-pve"
            kparts = (st.get("kversion") or "").split()
            node_entry["kernel"] = kparts[1] if len(kparts) >= 2 else (st.get("kversion") or "")
            cpuinfo = st.get("cpuinfo") or {}
            node_entry["cpu_model"] = cpuinfo.get("model", "")
            node_entry["loadavg"] = st.get("loadavg") or []
            _node_updates(api, n["node"], node_entry)
            _node_kernels(api, n["node"], node_entry)
            _node_repos(api, n["node"], node_entry)
            if node_entry["updates"] is not None:
                updates_known = True
                updates_total += node_entry["updates"]
        nodes.append(node_entry)

    nodes.sort(key=lambda x: (not x["online"], x["node"] or ""))
    avg_cpu = round(100.0 * total_cpu_weighted / total_cores, 1) if total_cores else 0.0

    # ---- storage (dedupe shared storage that is reported once per node) --
    seen_shared: set[str] = set()
    storages: list[dict[str, Any]] = []
    disk_used = disk_total = 0
    for r in resources:
        if r.get("type") != "storage":
            continue
        if r.get("status") not in (None, "available"):
            continue
        sid = r.get("storage", "")
        shared = bool(r.get("shared", 0))
        if shared:
            if sid in seen_shared:
                continue
            seen_shared.add(sid)
        used = int(r.get("disk") or 0)
        total = int(r.get("maxdisk") or 0)
        if total <= 0:
            continue
        disk_used += used
        disk_total += total
        storages.append(
            {
                "storage": sid,
                "node": "shared" if shared else r.get("node", ""),
                "plugintype": r.get("plugintype", ""),
                "content": r.get("content", ""),
                "shared": shared,
                "used": used,
                "total": total,
                "pct": _pct(used, total),
            }
        )
    storages.sort(key=lambda s: (s["node"], s["storage"]))

    # ---- guests ------------------------------------------------------------
    guests: list[dict[str, Any]] = []
    running = stopped = 0
    for r in resources:
        if r.get("type") not in ("qemu", "lxc"):
            continue
        status_ = r.get("status", "unknown")
        if status_ == "running":
            running += 1
        else:
            stopped += 1
        gmaxmem = int(r.get("maxmem") or 0)
        gmem = int(r.get("mem") or 0)
        guests.append(
            {
                "vmid": r.get("vmid"),
                "name": r.get("name", ""),
                "type": r.get("type"),
                "node": r.get("node", ""),
                "status": status_,
                "cpu_pct": round(float(r.get("cpu") or 0.0) * 100, 1),
                "cores": int(r.get("maxcpu") or 0),
                "mem_used": gmem,
                "mem_total": gmaxmem,
                "mem_pct": _pct(gmem, gmaxmem),
                "disk_total": int(r.get("maxdisk") or 0),
                "uptime": int(r.get("uptime") or 0),
                "template": bool(r.get("template", 0)),
                "tags": r.get("tags", ""),
            }
        )
    guests.sort(key=lambda g: (g["node"], g["vmid"] or 0))

    versions = sorted({n["pve_version"] for n in nodes if n["pve_version"]})
    summary = {
        "collected_at": time.time(),
        "latency_ms": int((time.monotonic() - started) * 1000),
        "version": version.get("version", ""),
        "release": version.get("release", ""),
        "repoid": version.get("repoid", ""),
        "pve_versions": versions,  # per-node pve-manager versions (may differ mid-upgrade)
        "cluster_name": cluster_name,
        "quorate": quorate,
        "is_cluster": bool(cluster_name),
        "node_count": len(nodes),
        "nodes_online": sum(1 for n in nodes if n["online"]),
        "cpu_pct": avg_cpu,
        "cores": total_cores,
        "mem_used": mem_used,
        "mem_total": mem_total,
        "mem_pct": _pct(mem_used, mem_total),
        "disk_used": disk_used,
        "disk_total": disk_total,
        "disk_pct": _pct(disk_used, disk_total),
        "guests_running": running,
        "guests_stopped": stopped,
        "updates": updates_total if updates_known else None,
        "reboot_pending_nodes": [n["node"] for n in nodes if n["kernel_reboot_pending"]],
        "repo_warning_nodes": [n["node"] for n in nodes if n.get("repo_warning")],
        "nodes": nodes,
        "storages": storages,
        "guests": guests,
    }
    return summary


def test_connection(host: ProxmoxHost, secret: str) -> dict[str, Any]:
    """Quick connectivity/auth check used by the 'Test' button. Returns version info."""
    api = connect(host, secret=secret)
    try:
        version = api.version.get()
    except AuthenticationError as exc:
        raise PveError(_describe(exc)) from exc
    except ResourceException as exc:
        raise PveError(_describe(exc)) from exc
    except Exception as exc:
        raise PveError(_describe(exc)) from exc
    nodes = _fetch_nodes(api, host)
    return {
        "version": version.get("version", ""),
        "release": version.get("release", ""),
        "nodes": [n.get("node") for n in nodes],
    }


# --------------------------------------------------------------------------- #
# Disks / SMART
# --------------------------------------------------------------------------- #

def list_disks(host: ProxmoxHost, node: str) -> list[dict[str, Any]]:
    api = connect(host)
    try:
        disks = api.nodes(node).disks.list.get(include_partitions=0)
    except ResourceException as exc:
        raise PveError(_describe(exc)) from exc
    except Exception as exc:
        raise PveError(_describe(exc)) from exc
    out = []
    for d in disks:
        out.append(
            {
                "devpath": d.get("devpath", ""),
                "model": d.get("model", ""),
                "serial": d.get("serial", ""),
                "vendor": d.get("vendor", ""),
                "type": d.get("type", ""),  # hdd | ssd | nvme | unknown
                "size": int(d.get("size") or 0),
                "health": d.get("health", ""),
                "wearout": d.get("wearout", "N/A"),
                "used": d.get("used", ""),  # LVM, ZFS, partitions, ...
                "rpm": d.get("rpm", ""),
                "gpt": bool(d.get("gpt", 0)),
                "osdid": d.get("osdid", -1),
            }
        )
    out.sort(key=lambda d: d["devpath"])
    return out


def list_backup_storages(host: ProxmoxHost, node: str) -> list[dict[str, Any]]:
    """Enabled storages on a node that accept backups. PVE only lists storages the
    token/user can see (Datastore.Audit or Datastore.AllocateSpace)."""
    api = connect(host)
    try:
        stores = api.nodes(node).storage.get(content="backup", enabled=1) or []
    except ResourceException as exc:
        raise PveError(_describe(exc)) from exc
    except Exception as exc:
        raise PveError(_describe(exc)) from exc
    out = []
    for s in stores:
        if "backup" not in (s.get("content") or "").split(","):
            continue
        out.append(
            {
                "storage": s.get("storage", ""),
                "type": s.get("type", ""),  # dir | nfs | cifs | pbs | ...
                "shared": bool(s.get("shared", 0)),
                "active": bool(s.get("active", 0)),
                "avail": int(s.get("avail") or 0),
                "total": int(s.get("total") or 0),
            }
        )
    out.sort(key=lambda s: (not s["active"], s["storage"]))
    return out


_QEMU_DISK_RE = re.compile(r"^(scsi|virtio|sata|ide)\d+$")
_LXC_DISK_RE = re.compile(r"^(rootfs|mp\d+)$")
_SIZE_RE = re.compile(r"^(\d+(?:\.\d+)?)([KMGT]?)$")


def size_bytes(size: str) -> int:
    """'32G' -> bytes. PVE writes disk sizes as a number with an optional K/M/G/T suffix."""
    m = _SIZE_RE.match((size or "").strip())
    if not m:
        return 0
    return int(float(m.group(1)) * {"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}[m.group(2)])


def _guest_config(host: ProxmoxHost, node: str, gtype: str, vmid: int) -> dict[str, Any]:
    api = connect(host)
    try:
        return getattr(api.nodes(node), gtype)(vmid).config.get() or {}
    except ResourceException as exc:
        raise PveError(_describe(exc)) from exc
    except Exception as exc:
        raise PveError(_describe(exc)) from exc


def _opts(parts: list[str]) -> dict[str, str]:
    return dict(x.split("=", 1) for x in parts if "=" in x)


def _disks_from_config(cfg: dict[str, Any], gtype: str) -> list[dict[str, Any]]:
    """Resizable disks. VMs: scsi/virtio/sata/ide disks that are not CD-ROMs.
    Containers: rootfs and mpN volumes (not bind mounts)."""
    rx = _QEMU_DISK_RE if gtype == "qemu" else _LXC_DISK_RE
    out = []
    for key, val in cfg.items():
        if not rx.match(key) or not isinstance(val, str):
            continue
        parts = val.split(",")
        volume = parts[0]
        opts = _opts(parts[1:])
        if "=" in volume:  # "volume=storage:vol" spelling
            k, _, v = volume.partition("=")
            opts.setdefault(k, v)
            volume = opts.get("volume", "")
        if opts.get("media") == "cdrom" or ":" not in volume:
            continue  # CD-ROMs, passthrough devices and bind mounts can't be resized
        size = opts.get("size", "")
        out.append({
            "disk": key,
            "volume": volume,
            "storage": volume.split(":", 1)[0],
            "size": size,
            "size_bytes": size_bytes(size),
            "mountpoint": "/" if key == "rootfs" else opts.get("mp", ""),
        })
    out.sort(key=lambda d: (re.sub(r"\d+$", "", d["disk"]) != "rootfs", re.sub(r"\d+$", "", d["disk"]), int(re.sub(r"^\D+", "", d["disk"]) or 0)))
    return out


_NET_RE = re.compile(r"^net(\d+)$")
_VM_NIC_MODELS = ("virtio", "e1000", "e1000e", "e1000-82540em", "e1000-82544gc", "e1000-82545em", "rtl8139",
                  "vmxnet3", "i82551", "i82557b", "i82559er", "ne2k_isa", "ne2k_pci", "pcnet")


def _nets_from_config(cfg: dict[str, Any], gtype: str) -> list[dict[str, Any]]:
    """Network adapters with their bridge and VLAN.
    VM:  net0: virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1,tag=20
    CT:  net0: name=eth0,bridge=vmbr0,hwaddr=BC:24:...,ip=dhcp,tag=20,type=veth"""
    out = []
    for key, val in cfg.items():
        m = _NET_RE.match(key)
        if not m or not isinstance(val, str):
            continue
        o = _opts(val.split(","))
        if gtype == "qemu":
            model = next((k for k in o if k in _VM_NIC_MODELS), o.get("model", ""))
            mac = o.get(model, "") if model in o else o.get("macaddr", "")
        else:
            model, mac = o.get("type", "veth"), o.get("hwaddr", "")
        tag = o.get("tag", "")
        out.append({
            "net": key,
            "index": int(m.group(1)),
            "name": o.get("name", ""),            # in-guest name (containers)
            "model": model,
            "mac": mac,
            "bridge": o.get("bridge", ""),
            "vlan": int(tag) if tag.isdigit() else None,
            "trunks": o.get("trunks", ""),
            "firewall": o.get("firewall") == "1",
            "link_down": o.get("link_down") == "1",
            "rate": o.get("rate", ""),
            "mtu": o.get("mtu", ""),
            "ip": o.get("ip", ""),
            "ip6": o.get("ip6", ""),
            "gw": o.get("gw", ""),
        })
    out.sort(key=lambda n: n["index"])
    return out


def _startup(raw: str) -> dict[str, Any]:
    """'order=1,up=30,down=60' -> {'order': 1, 'up': 30, 'down': 60}"""
    o = _opts((raw or "").split(","))
    return {k: int(o[k]) for k in ("order", "up", "down") if o.get(k, "").isdigit()}


def guest_details(host: ProxmoxHost, node: str, gtype: str, vmid: int) -> dict[str, Any]:
    """Start-at-boot, startup order, network adapters (bridge / VLAN) and resizable disks,
    read live from the guest's config (needs VM.Audit)."""
    cfg = _guest_config(host, node, gtype, vmid)
    return {
        "onboot": str(cfg.get("onboot", "0")) == "1",
        "startup": _startup(str(cfg.get("startup", ""))),
        "nets": _nets_from_config(cfg, gtype),
        "disks": _disks_from_config(cfg, gtype),
    }


def guest_disks(host: ProxmoxHost, node: str, gtype: str, vmid: int) -> list[dict[str, Any]]:
    """Resizable disks of a guest, read live from its config (VM.Audit)."""
    return _disks_from_config(_guest_config(host, node, gtype, vmid), gtype)


def read_smart(host: ProxmoxHost, node: str, devpath: str) -> dict[str, Any]:
    """Read SMART health + attributes for one disk via the PVE API (runs smartctl on the node)."""
    api = connect(host)
    try:
        data = api.nodes(node).disks.smart.get(disk=devpath)
    except ResourceException as exc:
        raise PveError(_describe(exc)) from exc
    except Exception as exc:
        raise PveError(_describe(exc)) from exc

    result: dict[str, Any] = {
        "devpath": devpath,
        "health": data.get("health", "UNKNOWN"),
        "type": data.get("type", ""),  # ata | text
        "attributes": [],
        "text": data.get("text", ""),
        "temperature_c": None,
        "power_on_hours": None,
        "reallocated_sectors": None,
        "pending_sectors": None,
    }
    for attr in data.get("attributes") or []:
        entry = {
            "id": attr.get("id"),
            "name": attr.get("name", ""),
            "value": attr.get("value"),
            "worst": attr.get("worst"),
            "threshold": attr.get("threshold"),
            "raw": attr.get("raw"),
            "flags": attr.get("flags", ""),
            "fail": attr.get("fail", "-"),
        }
        result["attributes"].append(entry)
        name = (entry["name"] or "").lower()
        raw = _raw_int(entry["raw"])
        if name in ("temperature_celsius", "airflow_temperature_cel") and raw is not None:
            result["temperature_c"] = raw if result["temperature_c"] is None else result["temperature_c"]
        elif name == "power_on_hours" and raw is not None:
            result["power_on_hours"] = raw
        elif name == "reallocated_sector_ct" and raw is not None:
            result["reallocated_sectors"] = raw
        elif name == "current_pending_sector" and raw is not None:
            result["pending_sectors"] = raw

    # NVMe / SAS disks come back as free text; pull a few common fields out of it.
    if result["text"]:
        for line in result["text"].splitlines():
            low = line.lower().strip()
            if low.startswith("temperature:") and result["temperature_c"] is None:
                result["temperature_c"] = _first_int(line)
            elif low.startswith("power on hours:") and result["power_on_hours"] is None:
                result["power_on_hours"] = _first_int(line)
    return result


def _raw_int(raw: Any) -> int | None:
    if raw is None:
        return None
    try:
        return int(str(raw).split(" ")[0].replace(",", ""))
    except ValueError:
        return None


def _first_int(line: str) -> int | None:
    """First integer after the colon; tolerates thousands separators ("8,201")."""
    digits = ""
    for ch in line.split(":", 1)[-1]:
        if ch.isdigit():
            digits += ch
        elif ch in (",", " ") and digits:
            continue
        elif digits:
            break
    return int(digits) if digits else None


def console_ticket(host: ProxmoxHost, password: str) -> str:
    """Log in as root@pam and return a PVE auth ticket.

    Used by the Upgrade shell button: the browser exchanges this ticket for a
    PVEAuthCookie on the host (POST /api2/html/access/ticket), because the
    upgrade console only works for a real root@pam login, never an API token.
    """
    import requests

    h = f"[{host.host}]" if ":" in host.host and not host.host.startswith("[") else host.host
    url = f"https://{h}:{host.port}/api2/json/access/ticket"
    try:
        r = requests.post(url, data={"username": "root@pam", "password": password},
                          verify=host.verify_ssl, timeout=settings.PVE_TIMEOUT + 5)
    except Exception as exc:  # connection refused, DNS, TLS...
        raise PveError(_describe(exc)) from exc
    if r.status_code == 401:
        raise ConsoleAuthError("Proxmox rejected the root@pam password.")
    if r.status_code != 200:
        raise PveError(f"Login failed: HTTP {r.status_code} {r.reason}")
    data = (r.json() or {}).get("data") or {}
    if data.get("NeedTFA"):
        raise PveError("root@pam has two-factor login enabled on this host, so the dashboard can't sign in "
                       "for you. Log in to the Proxmox web UI first, then use Upgrade shell.")
    ticket = data.get("ticket")
    if not ticket:
        raise PveError("Login failed: no ticket in the response.")
    return ticket
