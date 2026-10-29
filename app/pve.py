"""Proxmox VE API client wrapper and stat collection.

Everything here is synchronous (proxmoxer uses requests); the poller runs it in
worker threads.
"""

from __future__ import annotations

import logging
import random
import re
import threading
import time
from typing import Any

import urllib3
from proxmoxer import ProxmoxAPI
from proxmoxer.core import AuthenticationError, ResourceException

from . import crypto, tlspin
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
    try:
        tlspin.prepare(host)   # pin (or first-use pin) before anything is sent
    except (OSError, tlspin.PinError) as exc:
        raise PveError(_describe(exc)) from exc
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
    if "no certificate is pinned" in low:
        return "The dashboard refused to contact the host without a pinned TLS certificate. Run Test connection on Edit host."
    if "fingerprints did not match" in low or tlspin.MISMATCH_MARK in low:
        return ("The host's TLS certificate changed since it was pinned, so nothing was sent to it. If the "
                "certificate was replaced on purpose, accept the new one on Edit host (Check certificate); "
                "otherwise the connection may be intercepted.")
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

def _num(v, default=0.0) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return default
    return f if f == f and abs(f) != float("inf") else default


def _loadavg(raw) -> list[str]:
    """A managed host's /nodes/{node}/status must not be able to place markup
    on the dashboard, so the load average is reduced to at most three numbers."""
    if not isinstance(raw, (list, tuple)):
        return []
    return [f"{_num(x):.2f}" for x in raw[:3]]


_TOKEN_RE = re.compile(r"[^0-9A-Za-z.+~:_-]")


def _token(v, maxlen: int = 64) -> str:
    """Version-like strings from a managed host: only version characters survive."""
    return _TOKEN_RE.sub("", str(v or ""))[:maxlen]


def _vmid(v) -> int | None:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n if 0 < n < 10**9 else None


def _clock_offset(api: ProxmoxAPI, node: str) -> int | None:
    """Node clock minus the dashboard's clock, in whole seconds (GET /nodes/{node}/time, Sys.Audit).
    Proxmox only accepts a root@pam ticket on another cluster node when their clocks are within
    5 minutes, so a drifting node breaks consoles while token-based polling keeps working."""
    t0 = time.time()
    tm = _safe(lambda: api.nodes(node).time.get(), {}) or {}
    t1 = time.time()
    try:
        return int(round(int(tm["time"]) - (t0 + t1) / 2))
    except (KeyError, TypeError, ValueError):
        return None


def clock_check(host: ProxmoxHost, node: str) -> dict[str, Any]:
    """Live clock comparison between `node` and the node the dashboard talks to (ticket issuer)."""
    api = connect(host)
    entry = ""
    try:
        for item in api.cluster.status.get() or []:
            if item.get("type") == "node" and item.get("local"):
                entry = item.get("name", "")
    except Exception:  # noqa: BLE001
        pass
    out = {"node": node, "entry": entry, "node_offset": _clock_offset(api, node), "entry_offset": None}
    if entry and entry != node:
        out["entry_offset"] = _clock_offset(api, entry)
    return out


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
    entry_node = ""   # the node that answers the dashboard's API calls (and issues its root@pam tickets)
    for item in cluster_status:
        if item.get("type") == "cluster":
            cluster_name = item.get("name", "")
            quorate = bool(item.get("quorate", 0))
        elif item.get("type") == "node":
            if item.get("ip"):
                node_ips[item.get("name", "")] = item["ip"]
            if item.get("local"):
                entry_node = item.get("name", "")

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
            "api_entry": n.get("node") == entry_node,
            "clock_offset": None,   # seconds this node's clock is ahead (+) / behind (-) the dashboard
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
            node_entry["pve_version"] = _token(parts[1] if len(parts) >= 2 else pvever)
            node_entry["pve_version_full"] = str(pvever)[:200]
            # "Linux 6.8.12-9-pve #1 SMP PREEMPT_DYNAMIC ..." -> "6.8.12-9-pve"
            kparts = (st.get("kversion") or "").split()
            node_entry["kernel"] = _token(kparts[1] if len(kparts) >= 2 else (st.get("kversion") or ""))
            cpuinfo = st.get("cpuinfo") or {}
            node_entry["cpu_model"] = cpuinfo.get("model", "")
            node_entry["loadavg"] = _loadavg(st.get("loadavg"))
            node_entry["clock_offset"] = _clock_offset(api, n["node"])
            _node_updates(api, n["node"], node_entry)
            _node_kernels(api, n["node"], node_entry)
            _node_repos(api, n["node"], node_entry)
            if node_entry["updates"] is not None:
                updates_known = True
                updates_total += node_entry["updates"]
        nodes.append(node_entry)

    nodes.sort(key=lambda x: (not x["online"], x["node"] or ""))
    online_nodes = {n["node"] for n in nodes if n["online"]}
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
                # the node is offline, so these figures are the last ones it reported
                "node_offline": (not shared) and r.get("node", "") not in online_nodes,
            }
        )
    storages.sort(key=lambda s: (s["node"], s["storage"]))

    # ---- guests ------------------------------------------------------------
    guests: list[dict[str, Any]] = []
    running = stopped = unknown = 0
    for r in resources:
        if r.get("type") not in ("qemu", "lxc"):
            continue
        if _vmid(r.get("vmid")) is None:
            continue   # not a real guest id
        status_ = r.get("status", "unknown")
        # on a node that is offline Proxmox keeps reporting the guest's last state ("running",
        # with its last CPU / RAM), which is not true any more: the state is unknown until the node is back.
        node_offline = r.get("node", "") not in online_nodes
        last_status = status_ if node_offline else ""
        if node_offline:
            status_ = "unknown"
        if status_ == "running":
            running += 1
        elif status_ == "stopped":
            stopped += 1
        else:
            unknown += 1
        gmaxmem = int(r.get("maxmem") or 0)
        gmem = 0 if node_offline else int(r.get("mem") or 0)
        guests.append(
            {
                "vmid": _vmid(r.get("vmid")),
                "name": r.get("name", ""),
                "type": r.get("type"),
                "node": r.get("node", ""),
                "status": status_,
                "node_offline": node_offline,
                "last_status": last_status,   # what the offline node last reported
                "cpu_pct": 0.0 if node_offline else round(float(r.get("cpu") or 0.0) * 100, 1),
                "cores": int(r.get("maxcpu") or 0),
                "mem_used": gmem,
                "mem_total": gmaxmem,
                "mem_pct": _pct(gmem, gmaxmem),
                "disk_total": int(r.get("maxdisk") or 0),
                "uptime": 0 if node_offline else int(r.get("uptime") or 0),
                "template": bool(r.get("template", 0)),
                "tags": r.get("tags", ""),
            }
        )
    guests.sort(key=lambda g: (g["node"], g["vmid"] or 0))
    # maxdisk above is only the boot disk (VMs) / rootfs (CTs); add every disk from the config.
    _attach_guest_disks(api, host, guests, online_nodes)

    versions = sorted({n["pve_version"] for n in nodes if n["pve_version"]})
    summary = {
        "collected_at": time.time(),
        "latency_ms": int((time.monotonic() - started) * 1000),
        "version": _token(version.get("version", "")),
        "release": _token(version.get("release", "")),
        "repoid": _token(version.get("repoid", "")),
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
        "guests_unknown": unknown,   # on offline nodes
        "updates": updates_total if updates_known else None,
        "reboot_pending_nodes": [n["node"] for n in nodes if n["kernel_reboot_pending"]],
        "repo_warning_nodes": [n["node"] for n in nodes if n.get("repo_warning")],
        "nodes": nodes,
        "storages": storages,
        "guests": guests,
    }
    return summary


def test_connection(host: ProxmoxHost, secret: str) -> dict[str, Any]:
    """Quick connectivity/auth check used by the 'Test' button. Returns version info and the
    certificate fingerprint that will be pinned."""
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
        "version": _token(version.get("version", "")),
        "release": _token(version.get("release", "")),
        "nodes": [_token(n.get("node")) for n in nodes],
        "tls_fingerprint": "" if host.verify_ssl else tlspin.pretty(host.tls_fingerprint),
    }


# --------------------------------------------------------------------------- #
# Disks / SMART
# --------------------------------------------------------------------------- #

def list_disks(host: ProxmoxHost, node: str) -> list[dict[str, Any]]:
    api = connect(host)
    try:
        # No parameters: partitions are excluded by default ("include-partitions" = 0).
        # Never pass include_partitions (underscore): Proxmox VE 9.2 rejects it with
        # "property is not defined in schema".
        disks = api.nodes(node).disks.list.get() or []
    except ResourceException as exc:
        raise PveError(_describe(exc)) from exc
    except Exception as exc:
        raise PveError(_describe(exc)) from exc
    out = []
    for d in disks:
        if d.get("parent"):
            continue  # a partition (only listed when include-partitions is set)
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


# --------------------------------------------------------------------------- #
# Node network: read-only, needs Sys.Audit on the node (PVEAuditor has it)
# --------------------------------------------------------------------------- #

_IFACE_KIND = {"bridge": "Bridge", "OVSBridge": "OVS bridge", "bond": "Bond", "OVSBond": "OVS bond", "vlan": "VLAN",
               "eth": "NIC", "alias": "Alias", "OVSPort": "OVS port", "OVSIntPort": "OVS int port", "fabric": "Fabric"}
_IFACE_ORDER = {"bridge": 0, "OVSBridge": 0, "bond": 1, "OVSBond": 1, "vlan": 2, "eth": 3}


def _natural(name: str) -> list:
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", name or "")]


def _prefix(address: str, netmask: str, v6: bool = False) -> str:
    """'10.0.0.5' + '24' or '255.255.255.0' -> '10.0.0.5/24'."""
    import ipaddress

    if not address:
        return ""
    if not netmask:
        return address
    if netmask.isdigit():
        return f"{address}/{netmask}"
    try:
        return str(ipaddress.ip_interface(f"{address}/{netmask}").with_prefixlen) if not v6 else f"{address}/{netmask}"
    except ValueError:
        return f"{address}/{netmask}"


def _flag(v) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _iface(d: dict[str, Any]) -> dict[str, Any]:
    t = d.get("type", "") or ""
    name = d.get("iface", "") or ""
    vlan_id = str(d.get("vlan-id") or "")
    raw_dev = d.get("vlan-raw-device") or ""
    if t == "vlan" and not vlan_id:
        m = re.match(r"^(.+)\.(\d+)$", name) or re.match(r"^vlan(\d+)$", name)
        if m and m.lastindex == 2:
            raw_dev, vlan_id = raw_dev or m.group(1), m.group(2)
        elif m:
            vlan_id = m.group(1)
    if t in ("bridge", "OVSBridge"):
        ports = d.get("bridge_ports") or d.get("ovs_ports") or ""
    elif t in ("bond", "OVSBond"):
        ports = d.get("slaves") or d.get("ovs_bonds") or ""
    elif t == "vlan":
        ports = raw_dev
    else:
        ports = d.get("ovs_bridge") or ""
    comments = " ".join(x.strip() for x in (d.get("comments"), d.get("comments6")) if x and x.strip())
    return {
        "iface": name,
        "type": t,
        "kind": _IFACE_KIND.get(t, t or "unknown"),
        "method": d.get("method", "") or "",
        "method6": d.get("method6", "") or "",
        "cidr": d.get("cidr") or _prefix(d.get("address", "") or "", str(d.get("netmask") or "")),
        "gateway": d.get("gateway", "") or "",
        "cidr6": d.get("cidr6") or _prefix(d.get("address6", "") or "", str(d.get("netmask6") or ""), v6=True),
        "gateway6": d.get("gateway6", "") or "",
        "ports": " ".join(str(ports).split()),
        "bond_mode": d.get("bond_mode") or d.get("bond-mode") or "",
        "vlan_id": vlan_id,
        "vlan_aware": _flag(d.get("bridge_vlan_aware", 0)),
        "vlan_ids": d.get("bridge_vids", "") or "",
        "mtu": str(d.get("mtu") or ""),
        "active": _flag(d.get("active", 0)),
        "autostart": _flag(d.get("autostart", 0)),
        "exists": _flag(d.get("exists", 1 if t != "eth" else 0)),
        "comments": comments[:200],
    }


def node_network(host: ProxmoxHost, node: str) -> dict[str, Any]:
    """A node's network interfaces (as configured in /etc/network/interfaces, with live state) and DNS."""
    api = connect(host)
    try:
        raw = api.nodes(node).network.get() or []
    except ResourceException as exc:
        raise PveError(_describe(exc)) from exc
    except Exception as exc:
        raise PveError(_describe(exc)) from exc
    ifaces = [_iface(d) for d in raw if isinstance(d, dict)]
    ifaces.sort(key=lambda i: (_IFACE_ORDER.get(i["type"], 4), _natural(i["iface"])))
    dns: dict[str, Any] | None = None
    dns_error = ""
    try:
        d = api.nodes(node).dns.get() or {}
        dns = {"search": d.get("search", "") or "",
               "servers": [d[k] for k in ("dns1", "dns2", "dns3") if d.get(k)]}
    except Exception as exc:  # noqa: BLE001  (DNS is extra; the interface list still shows)
        dns_error = _describe(exc)
    return {"interfaces": ifaces, "dns": dns, "dns_error": dns_error}


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


# ---- every disk of a guest -------------------------------------
# /cluster/resources reports maxdisk = the boot disk of a VM (rootfs of a CT) only, so a VM with
# sata0 100G + sata1 700G showed 100 GiB. The full list comes from the guest config, cached per guest.

_EFI_TPM_RE = re.compile(r"^(efidisk|tpmstate)\d+$")
_DISK_KINDS_COUNTED = ("disk", "passthrough")


def _guest_disk_list(cfg: dict[str, Any], gtype: str) -> list[dict[str, Any]]:
    """Every disk / volume attached to a guest, for display. kind: disk | passthrough | bind | efi | tpm.
    CD-ROMs and unused (detached) volumes are left out."""
    rx = _QEMU_DISK_RE if gtype == "qemu" else _LXC_DISK_RE
    out = []
    for key, val in cfg.items():
        if not isinstance(val, str):
            continue
        sysdisk = gtype == "qemu" and _EFI_TPM_RE.match(key)
        if not (rx.match(key) or sysdisk):
            continue
        parts = val.split(",")
        volume = parts[0]
        opts = _opts(parts[1:])
        if "=" in volume:
            k, _, v = volume.partition("=")
            opts.setdefault(k, v)
            volume = opts.get("volume", "")
        if opts.get("media") == "cdrom" or volume in ("", "none"):
            continue
        if sysdisk:
            kind = "efi" if key.startswith("efidisk") else "tpm"
        elif ":" in volume:
            kind = "disk"
        elif gtype == "lxc":
            kind = "bind"          # host directory bind-mounted into the container
        else:
            kind = "passthrough"   # physical disk / LUN passed to the VM (/dev/disk/by-id/...)
        out.append({
            "disk": key,
            "kind": kind,
            "storage": volume.split(":", 1)[0] if ":" in volume else "",
            "volume": volume if kind in ("passthrough", "bind") else volume.split(":", 1)[-1],
            "size": size_bytes(opts.get("size", "")),
            "mountpoint": "/" if key == "rootfs" else opts.get("mp", ""),
            "backup": opts.get("backup", "1") != "0" if key != "rootfs" else True,
        })
    order = {"rootfs": 0, "scsi": 1, "virtio": 1, "sata": 1, "ide": 1, "mp": 2, "efidisk": 3, "tpmstate": 4}
    out.sort(key=lambda d: (order.get(re.sub(r"\d+$", "", d["disk"]), 5), re.sub(r"\d+$", "", d["disk"]),
                            int(re.sub(r"^\D+", "", d["disk"]) or 0)))
    return out


_gd_lock = threading.Lock()
_gd_cache: dict[tuple[int, str, int], dict[str, Any]] = {}   # (host_id, type, vmid) -> {node, disks, expires, gen}
_gd_gen: dict[int, int] = {}       # host_id -> generation; bumped when the host's cache is cleared
GUEST_DISK_READS_PER_POLL = 60     # spread a large host's first reads over a few polls
GUEST_DISK_READ_SECONDS = 10.0     # and never spend longer than this per poll on them


def remember_guest_disks(host_id: int, node: str, gtype: str, vmid: int, cfg: dict[str, Any]) -> None:
    """Store a freshly read config's disks (More dialog, after Expand disk)."""
    ttl = max(30, settings.GUEST_DISK_REFRESH)
    with _gd_lock:
        _gd_cache[(host_id, gtype, int(vmid))] = {"node": node, "disks": _guest_disk_list(cfg, gtype), "gen": _gd_gen.get(host_id, 0),
                                                  "expires": time.monotonic() + ttl + random.uniform(0, 60)}


def forget_guest_disks(host_id: int, vmid: int | None = None) -> None:
    """vmid=None: the whole host (address / credentials changed, host deleted). A poll that is still
    running for the host can't write its (old) results back afterwards."""
    with _gd_lock:
        if vmid is None:
            _gd_gen[host_id] = _gd_gen.get(host_id, 0) + 1
        for k in [k for k in _gd_cache if k[0] == host_id and (vmid is None or k[2] == int(vmid))]:
            _gd_cache.pop(k, None)


def _attach_guest_disks(api: ProxmoxAPI, host: ProxmoxHost, guests: list[dict[str, Any]], online: set) -> None:
    now = time.monotonic()
    ttl = max(30, settings.GUEST_DISK_REFRESH)
    budget = GUEST_DISK_READS_PER_POLL
    stop_at = now + GUEST_DISK_READ_SECONDS
    dead_nodes: set[str] = set()        # a node that timed out / dropped the connection: skip it this poll
    with _gd_lock:
        gen = _gd_gen.get(host.id, 0)
    seen = set()
    for g in guests:
        key = (host.id, g["type"], int(g["vmid"] or 0))
        seen.add(key)
        with _gd_lock:
            c = _gd_cache.get(key)
        if c is not None and c.get("gen") != gen:
            c = None
        stale = c is None or c["node"] != g["node"] or now >= c["expires"]
        if (stale and budget > 0 and g["node"] in online and g["node"] not in dead_nodes
                and time.monotonic() < stop_at):
            budget -= 1
            try:
                cfg = getattr(api.nodes(g["node"]), g["type"])(g["vmid"]).config.get() or {}
                c = {"node": g["node"], "disks": _guest_disk_list(cfg, g["type"]), "gen": gen,
                     "expires": now + ttl + random.uniform(0, 60)}
            except Exception as exc:  # noqa: BLE001  (VM.Audit missing, node busy...): keep what we had
                log.debug("guest %s config read failed: %s", g["vmid"], exc)
                if not isinstance(exc, ResourceException):
                    dead_nodes.add(g["node"])   # timeout / connection error: don't wait on its other guests
                if c is None or c["node"] != g["node"]:
                    c = {"node": g["node"], "disks": None, "gen": gen, "expires": now + 120}
                else:
                    c = dict(c, expires=now + 120)
            with _gd_lock:
                if _gd_gen.get(host.id, 0) == gen:   # not cleared meanwhile (host edited / deleted)
                    _gd_cache[key] = c
        disks = c.get("disks") if c and c["node"] == g["node"] else None
        g["boot_disk"] = g["disk_total"]
        if disks is None:
            g["disks"] = None       # not read (yet): disk_total stays the boot disk only
            g["disk_count"] = None
            continue
        counted = [d for d in disks if d["kind"] in _DISK_KINDS_COUNTED]
        total = sum(d["size"] for d in counted)
        g["disks"] = [{k: d[k] for k in ("disk", "kind", "storage", "size", "mountpoint", "backup")} for d in disks]
        g["disk_count"] = len(counted)
        if total:
            g["disk_total"] = total
    with _gd_lock:
        for k in [k for k in _gd_cache if k[0] == host.id and k not in seen]:
            _gd_cache.pop(k, None)


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
    remember_guest_disks(host.id, node, gtype, vmid, cfg)   # the guest table picks it up at the next poll
    return {
        "onboot": str(cfg.get("onboot", "0")) == "1",
        "startup": _startup(str(cfg.get("startup", ""))),
        "nets": _nets_from_config(cfg, gtype),
        "disks": _disks_from_config(cfg, gtype),
        "disk_list": _guest_disk_list(cfg, gtype),
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
    return console_auth(host, password)[0]


def console_auth(host: ProxmoxHost, password: str) -> tuple[str, str]:
    """Log in as root@pam; return (ticket, CSRFPreventionToken) for cookie-authenticated calls."""
    import requests

    h = f"[{host.host}]" if ":" in host.host and not host.host.startswith("[") else host.host
    url = f"https://{h}:{host.port}/api2/json/access/ticket"
    try:
        tlspin.prepare(host)   # the root@pam password only goes to the pinned certificate
    except (OSError, tlspin.PinError) as exc:
        raise PveError(_describe(exc)) from exc
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
        raise PveError("root@pam has two-factor login enabled on this host, so the dashboard can't open "
                       "consoles for it.")
    if not data.get("ticket") or not data.get("CSRFPreventionToken"):
        raise PveError("Login failed: no ticket in the response.")
    return data["ticket"], data["CSRFPreventionToken"]

