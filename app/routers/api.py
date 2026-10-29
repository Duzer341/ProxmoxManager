"""JSON API used by the web UI (and usable from scripts with a session cookie)."""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

import logging

from .. import crypto, jobs, loginconfig, mfa, ssh, tlspin
from .. import permissions as perms
from ..events import note_current
from ..auth import (
    hash_password,
    require_admin,
    require_cap,
    require_same_origin,
    require_user,
    validate_password_strength,
    verify_password,
)
from ..config import settings
from ..database import get_db
from ..models import Job, ProxmoxHost, SmartResult, StatSample, User, node_names_of
from ..poller import poller
from ..templating import clean_theme, theme_cookie
from ..pve import (
    PveError,
    guest_details,
    guest_disks,
    list_backup_storages,
    forget_guest_disks,
    list_disks,
    node_network,
    read_smart,
    test_connection,
)

_NODE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}")   # used with fullmatch


def _node_param_ok(request: Request) -> None:
    """a node name in the URL must look like one before it reaches a Proxmox API path."""
    node = request.path_params.get("node")
    if node is not None and not _NODE_NAME_RE.fullmatch(node):
        raise HTTPException(404, "Unknown node")


router = APIRouter(prefix="/api", dependencies=[Depends(require_same_origin), Depends(_node_param_ok)])


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _summary(host: ProxmoxHost) -> dict | None:
    if not host.last_summary_json:
        return None
    try:
        return json.loads(host.last_summary_json)
    except json.JSONDecodeError:
        return None


def _averages(db: Session, host_ids: list[int]) -> dict[int, dict]:
    """Rolling averages over AVERAGE_WINDOW_MINUTES for a set of hosts."""
    if not host_ids:
        return {}
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=settings.AVERAGE_WINDOW_MINUTES)
    rows = (
        db.query(
            StatSample.host_id,
            func.avg(StatSample.cpu_pct),
            func.avg(StatSample.mem_pct),
            func.avg(StatSample.disk_pct),
            func.count(StatSample.id),
        )
        .filter(StatSample.host_id.in_(host_ids), StatSample.ts >= cutoff)
        .group_by(StatSample.host_id)
        .all()
    )
    return {
        hid: {
            "cpu_pct": round(cpu or 0, 1),
            "mem_pct": round(mem or 0, 1),
            "disk_pct": round(disk or 0, 1),
            "samples": count,
        }
        for hid, cpu, mem, disk, count in rows
    }


def _console_source(host: ProxmoxHost) -> str:
    """Where the root@pam password for the Upgrade shell comes from: host / saved / '' (ask)."""
    if host.auth_type == "password" and host.pve_user.strip().lower() == "root@pam":
        return "host"
    return "saved" if host.console_secret_enc else ""


def _host_public(host: ProxmoxHost, include_config: bool = False) -> dict:
    data = {
        "id": host.id,
        "name": host.name,
        "client": host.client,
        "host": host.host,
        "port": host.port,
        "ui_url": host.ui_url,
        "enabled": host.enabled,
        "notes": host.notes,
        "last_poll_at": _iso(host.last_poll_at),
        "last_ok_at": _iso(host.last_ok_at),
        "last_error": host.last_error,
        "console_login": _console_source(host),
        "node_names": node_names_of(host),
    }
    if include_config:
        data.update(
            {
                "web_url": host.web_url,
                "verify_ssl": host.verify_ssl,
                "auth_type": host.auth_type,
                "pve_user": host.pve_user,
                "token_name": host.token_name,
                "token_id": f"{host.pve_user}!{host.token_name}" if host.auth_type == "token" else "",
                "has_secret": bool(host.secret_enc),
                "ssh_user": host.ssh_user,
                "ssh_port": host.ssh_port,
                "ssh_auth": host.ssh_auth,
                "ssh_has_secret": bool(host.ssh_secret_enc),
                "ssh_node_addrs": _node_addrs_text(host.ssh_node_addrs),
                "tls_mode": "ca" if host.verify_ssl else ("pinned" if host.tls_fingerprint else "pending"),
                "tls_fingerprint": "" if host.verify_ssl else tlspin.pretty(host.tls_fingerprint),
                "nodes": [n.get("node") for n in (_summary(host) or {}).get("nodes", []) if n.get("node")],
            }
        )
    data["ssh_enabled"] = host.ssh_enabled
    return data


def _get_host(db: Session, host_id: int) -> ProxmoxHost:
    host = db.get(ProxmoxHost, host_id)
    if host is None:
        raise HTTPException(404, "Host not found")
    return host


def _history(db: Session, host_id: int, hours: int = 6) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = (
        db.query(StatSample)
        .filter(StatSample.host_id == host_id, StatSample.ts >= cutoff)
        .order_by(StatSample.ts)
        .all()
    )
    return [{"ts": _iso(r.ts), "cpu": r.cpu_pct, "mem": r.mem_pct, "disk": r.disk_pct} for r in rows]


# --------------------------------------------------------------------------- #
# Dashboard
# --------------------------------------------------------------------------- #

@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db), user: User = Depends(require_user)):
    hosts = db.query(ProxmoxHost).order_by(ProxmoxHost.client, ProxmoxHost.name).all()
    averages = _averages(db, [h.id for h in hosts])

    out = []
    fleet = {
        "hosts": len(hosts),
        "hosts_ok": 0,
        "hosts_error": 0,
        "hosts_disabled": 0,
        "nodes": 0,
        "nodes_online": 0,
        "guests_running": 0,
        "guests_stopped": 0,
        "guests_unknown": 0,
        "cores": 0,
        "cpu_weighted": 0.0,
        "mem_used": 0,
        "mem_total": 0,
        "disk_used": 0,
        "disk_total": 0,
        "versions": {},
        "updates": 0,
        "reboot_pending": 0,
        "repo_warnings": 0,
    }
    for h in hosts:
        s = _summary(h)
        entry = _host_public(h)
        entry["summary"] = None
        entry["average"] = averages.get(h.id)
        if not h.enabled:
            fleet["hosts_disabled"] += 1
            entry["state"] = "disabled"
        elif h.last_error:
            fleet["hosts_error"] += 1
            entry["state"] = "error"
        elif s:
            fleet["hosts_ok"] += 1
            entry["state"] = "ok"
        else:
            entry["state"] = "pending"

        if s:
            # Dashboard view does not need the full guest/storage lists.
            slim = {k: v for k, v in s.items() if k not in ("guests", "storages")}
            slim["nodes"] = [
                {k: n[k] for k in ("node", "status", "online", "cpu_pct", "mem_pct", "pve_version", "uptime")}
                for n in s.get("nodes", [])
            ]
            entry["summary"] = slim
            if h.enabled:
                fleet["nodes"] += s["node_count"]
                fleet["nodes_online"] += s["nodes_online"]
                fleet["guests_running"] += s["guests_running"]
                fleet["guests_stopped"] += s["guests_stopped"]
                fleet["guests_unknown"] += s.get("guests_unknown", 0)
                fleet["cores"] += s["cores"]
                fleet["cpu_weighted"] += s["cpu_pct"] * s["cores"]
                fleet["mem_used"] += s["mem_used"]
                fleet["mem_total"] += s["mem_total"]
                fleet["disk_used"] += s["disk_used"]
                fleet["disk_total"] += s["disk_total"]
                v = s.get("version") or "unknown"
                fleet["versions"][v] = fleet["versions"].get(v, 0) + 1
                fleet["updates"] += s.get("updates") or 0
                fleet["reboot_pending"] += len(s.get("reboot_pending_nodes") or [])
                fleet["repo_warnings"] += len(s.get("repo_warning_nodes") or [])
        out.append(entry)

    fleet["cpu_pct"] = round(fleet["cpu_weighted"] / fleet["cores"], 1) if fleet["cores"] else 0.0
    fleet["mem_pct"] = round(100.0 * fleet["mem_used"] / fleet["mem_total"], 1) if fleet["mem_total"] else 0.0
    fleet["disk_pct"] = round(100.0 * fleet["disk_used"] / fleet["disk_total"], 1) if fleet["disk_total"] else 0.0
    del fleet["cpu_weighted"]

    return {
        "generated_at": _iso(datetime.now(timezone.utc)),
        "poll_interval": settings.POLL_INTERVAL,
        "average_window_minutes": settings.AVERAGE_WINDOW_MINUTES,
        "fleet": fleet,
        "hosts": out,
    }


# --------------------------------------------------------------------------- #
# Hosts
# --------------------------------------------------------------------------- #

# Proxmox's own rules: user@realm and token names never contain '!' so a Token ID
# like root@pam!dashboard splits unambiguously on the first '!'.
_USER_RE = re.compile(r"^[A-Za-z0-9.\-_]+@[A-Za-z][A-Za-z0-9.\-_]*$")
_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9.\-_]*$")


def _parse_node_addrs(text: str) -> str:
    """'pve1=10.0.0.11\\npve2=10.0.0.12' -> JSON string; accepts ':' or '=' separators."""
    out: dict[str, str] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        sep = "=" if "=" in line else (":" if ":" in line else None)
        if sep is None:
            raise HTTPException(400, f"SSH node address override '{line}' must be node=address")
        node, _, addr = line.partition(sep)
        if not node.strip() or not addr.strip():
            raise HTTPException(400, f"SSH node address override '{line}' must be node=address")
        out[node.strip()] = addr.strip()
    return json.dumps(out) if out else ""


def _node_addrs_text(js: str) -> str:
    try:
        return "\n".join(f"{k}={v}" for k, v in json.loads(js).items()) if js else ""
    except json.JSONDecodeError:
        return ""


def _clean_node_names(d: dict) -> dict[str, str]:
    """Validate {"node": "friendly name"}: real node names, names up to 64 printable characters, blanks dropped."""
    if len(d) > 64:
        raise HTTPException(400, "Too many node names (64 at most).")
    out = {}
    for k, v in d.items():
        k, v = str(k).strip(), " ".join(str(v or "").split())
        if not _NODE_NAME_RE.fullmatch(k):
            raise HTTPException(400, f"'{k[:40]}' is not a valid node name.")
        if len(v) > 64:
            raise HTTPException(400, f"The name for {k} is longer than 64 characters.")
        if v:
            out[k] = v
    return dict(sorted(out.items()))


class HostIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    client: str = Field(default="", max_length=128)
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=8006, ge=1, le=65535)
    web_url: str = Field(default="", max_length=255)
    verify_ssl: bool = False
    auth_type: Literal["token", "password"] = "token"
    # Token auth: either token_id ("user@realm!tokenname", as the PVE UI shows it)
    # or pve_user + token_name. Password auth: pve_user only.
    token_id: str = Field(default="", max_length=256)
    pve_user: str = Field(default="", max_length=128)
    token_name: str = Field(default="", max_length=128)
    secret: str = Field(default="", max_length=512)  # token secret or password; blank on edit = keep
    enabled: bool = True
    notes: str = Field(default="", max_length=4000)
    # SSH (for updates / reboots)
    ssh_enabled: bool = False
    ssh_user: str = Field(default="root", max_length=64)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_auth: Literal["appkey", "key", "password"] = "appkey"
    ssh_secret: str = Field(default="", max_length=16000)  # pasted private key or password; blank on edit = keep
    ssh_node_addrs: str = Field(default="", max_length=4000)  # "node=address" per line
    node_names: dict[str, str] | None = None   # {"node": "friendly name"}; None = leave unchanged
    # the certificate fingerprint shown by "Test connection", pinned on save
    tls_fingerprint: str = Field(default="", max_length=100)

    def validate_auth(self, editing: bool) -> None:
        """Normalise and validate the credential fields. Mutates pve_user / token_name."""
        self.pve_user = self.pve_user.strip()
        self.token_name = self.token_name.strip()
        self.token_id = self.token_id.strip()
        self.ssh_user = self.ssh_user.strip() or "root"
        if self.ssh_enabled and self.ssh_auth != "appkey" and not self.ssh_secret and not editing:
            raise HTTPException(400, "SSH private key / password is required for the selected SSH auth type")
        if self.ssh_enabled and self.ssh_auth == "key" and self.ssh_secret and "PRIVATE KEY" not in self.ssh_secret:
            raise HTTPException(400, "That does not look like a private key (expected a -----BEGIN ... PRIVATE KEY----- block)")
        self.ssh_node_addrs = _parse_node_addrs(self.ssh_node_addrs)
        if self.node_names is not None:
            self.node_names = _clean_node_names(self.node_names)

        if self.auth_type == "token":
            # Accept the Token ID in either field; people paste "root@pam!name" where the user goes.
            tid = self.token_id or (self.pve_user if "!" in self.pve_user else "")
            if tid:
                user, _, tok = tid.partition("!")
                if self.token_name and self.token_name != tok:
                    raise HTTPException(
                        400,
                        f"Token ID '{tid}' already contains the token name '{tok}', "
                        f"but a different token name '{self.token_name}' was also given. Use one or the other.",
                    )
                self.pve_user, self.token_name = user.strip(), tok.strip()
            if not self.pve_user or not self.token_name:
                raise HTTPException(400, "Enter the Token ID exactly as Proxmox shows it, e.g. monitor@pve!dashboard")
            if not _TOKEN_RE.match(self.token_name):
                raise HTTPException(
                    400,
                    f"'{self.token_name}' is not a valid token name. A Token ID has exactly one '!': "
                    "user@realm!tokenname (e.g. root@pam!dashboard).",
                )
        else:
            self.token_name = ""
            if "!" in self.pve_user:
                raise HTTPException(400, "For password auth enter just the user, e.g. root@pam (no '!token' part)")

        if not _USER_RE.match(self.pve_user):
            raise HTTPException(400, "PVE user must be user@realm, e.g. monitor@pve or root@pam")
        if not self.secret and not editing:
            raise HTTPException(400, "Token secret / password is required")
        if self.web_url and not self.web_url.lower().startswith(("http://", "https://")):
            raise HTTPException(400, "Web URL must start with http:// or https://")


@router.get("/hosts")
def hosts_list(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    hosts = db.query(ProxmoxHost).order_by(ProxmoxHost.client, ProxmoxHost.name).all()
    return [_host_public(h, include_config=True) for h in hosts]


@router.post("/hosts", status_code=201)
async def hosts_create(body: HostIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    body.validate_auth(editing=False)
    host = ProxmoxHost(
        name=body.name.strip(),
        client=body.client.strip(),
        host=body.host.strip(),
        port=body.port,
        web_url=body.web_url.strip(),
        verify_ssl=body.verify_ssl,
        auth_type=body.auth_type,
        pve_user=body.pve_user.strip(),
        token_name=body.token_name.strip(),
        secret_enc=crypto.encrypt(body.secret),
        enabled=body.enabled,
        notes=body.notes,
        ssh_enabled=body.ssh_enabled,
        ssh_user=body.ssh_user,
        ssh_port=body.ssh_port,
        ssh_auth=body.ssh_auth,
        ssh_secret_enc=crypto.encrypt(body.ssh_secret) if body.ssh_secret else "",
        ssh_node_addrs=body.ssh_node_addrs,
        node_names=json.dumps(body.node_names) if body.node_names else "",
        tls_fingerprint="" if body.verify_ssl else tlspin.normalize(body.tls_fingerprint),
    )
    db.add(host)
    db.commit()
    db.refresh(host)
    note_current(action="host.create", host_name=host.name, details={"host_id": host.id, "address": f"{host.host}:{host.port}",
                 "auth_type": host.auth_type, "ssh_enabled": host.ssh_enabled, "verify_ssl": host.verify_ssl})
    if host.enabled:
        asyncio.create_task(poller.poll_one_now(host.id))
    return _host_public(host, include_config=True)


@router.get("/hosts/{host_id}")
def host_detail(
    host_id: int,
    hours: int = Query(default=6, ge=1, le=168),
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    host = _get_host(db, host_id)
    data = _host_public(host, include_config=user.is_admin)
    data["summary"] = _summary(host)
    data["average"] = _averages(db, [host.id]).get(host.id)
    data["history"] = _history(db, host.id, hours=hours)
    data["history_hours"] = hours
    recent = db.query(Job).filter(Job.host_id == host.id).order_by(Job.created_at.desc()).limit(15).all()
    data["jobs"] = [_job_public(j, with_output=False) for j in recent]
    active = db.query(Job).filter(Job.host_id == host.id, Job.status.in_(("queued", "running"))).all()
    data["active_jobs"] = {j.node: j.id for j in active if j.vmid is None}
    data["active_guest_jobs"] = {str(j.vmid): j.id for j in active if j.vmid is not None}
    smart = (
        db.query(SmartResult)
        .filter(SmartResult.host_id == host.id)
        .order_by(SmartResult.node, SmartResult.devpath)
        .all()
    )
    data["smart"] = [
        {
            "node": s.node,
            "devpath": s.devpath,
            "ts": _iso(s.ts),
            "health": s.health,
            "requested_by": s.requested_by,
            "result": json.loads(s.result_json) if s.result_json else None,
        }
        for s in smart
    ]
    return data


@router.put("/hosts/{host_id}")
async def hosts_update(
    host_id: int, body: HostIn, db: Session = Depends(get_db), user: User = Depends(require_admin)
):
    body.validate_auth(editing=True)
    host = _get_host(db, host_id)
    _before = {k: getattr(host, k) for k in _HOST_AUDIT_FIELDS}
    _old_name = host.name
    _old_target = (host.host.strip().lower(), host.port, host.verify_ssl)
    new_target = (body.host.strip().lower(), body.port, body.verify_ssl)
    same_machine = new_target == _old_target
    if not same_machine and not body.verify_ssl and not _old_target[2] and host.tls_fingerprint:
        # A renumbered host (new address, same pinned certificate) keeps its saved secrets.
        try:
            same_machine = await asyncio.to_thread(tlspin.fetch, body.host.strip(), body.port, 10) == \
                tlspin.normalize(host.tls_fingerprint)
        except Exception:  # noqa: BLE001
            same_machine = False
    if not same_machine and not body.secret:
        # the saved token / password is only sent to the machine it was saved for
        raise HTTPException(400, "The address, port or certificate check changed and the new address doesn't present "
                                 "this host's pinned certificate, so the saved API token secret / password isn't sent "
                                 "there. Enter it again to save these settings.")
    host.name = body.name.strip()
    host.client = body.client.strip()
    host.host = body.host.strip()
    host.port = body.port
    host.web_url = body.web_url.strip()
    host.verify_ssl = body.verify_ssl
    host.auth_type = body.auth_type
    host.pve_user = body.pve_user.strip()
    host.token_name = body.token_name.strip()
    if body.secret:
        host.secret_enc = crypto.encrypt(body.secret)
    host.enabled = body.enabled
    host.notes = body.notes
    host.ssh_enabled = body.ssh_enabled
    host.ssh_user = body.ssh_user
    host.ssh_port = body.ssh_port
    host.ssh_auth = body.ssh_auth
    if body.ssh_secret:
        host.ssh_secret_enc = crypto.encrypt(body.ssh_secret)
    host.ssh_node_addrs = body.ssh_node_addrs
    if body.node_names is not None:
        host.node_names = json.dumps(body.node_names) if body.node_names else ""
    if new_target != _old_target and not same_machine:
        # a different machine gets a new pin (the one the admin just tested, else pinned on
        # first use at the next poll) and the saved root@pam console password is not sent to it
        host.tls_fingerprint = "" if host.verify_ssl else tlspin.normalize(body.tls_fingerprint)
        host.console_secret_enc = ""
    if not host.enabled:
        host.last_error = ""
    db.commit()
    db.refresh(host)
    changed = [k for k in _HOST_AUDIT_FIELDS if getattr(host, k) != _before[k]]
    if body.secret:
        changed.append("api secret / password (value not recorded)")
    if body.ssh_secret:
        changed.append("ssh key / password (value not recorded)")
    note_current(action="host.update", host_name=_old_name,
                 details={"changed": changed, **({"renamed_to": host.name} if host.name != _old_name else {})})
    if body.secret or any(k in changed for k in ("host", "port", "auth_type", "pve_user", "token_name")):
        forget_guest_disks(host.id)   # it may point at different guests now
    if host.enabled:
        asyncio.create_task(poller.poll_one_now(host.id))
    return _host_public(host, include_config=True)


_HOST_AUDIT_FIELDS = ("name", "client", "host", "port", "web_url", "verify_ssl", "auth_type", "pve_user", "token_name",
                      "enabled", "notes", "ssh_enabled", "ssh_user", "ssh_port", "ssh_auth", "ssh_node_addrs", "node_names",
                      "tls_fingerprint")


@router.delete("/hosts/{host_id}", status_code=204)
def hosts_delete(host_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    host = _get_host(db, host_id)
    active = db.query(Job).filter(Job.host_id == host.id, Job.status.in_(("queued", "running"))).first()
    if active:
        raise HTTPException(409, f"Job #{active.id} ({active.kind.replace('_', ' ')}) is still running on {active.node}. Wait for it to finish before deleting the host.")
    note_current(action="host.delete", host_name=host.name, details={"address": f"{host.host}:{host.port}"})
    db.delete(host)
    db.commit()
    forget_guest_disks(host_id)
    return None


class TestIn(HostIn):
    host_id: int | None = None  # when editing, lets a blank secret reuse the stored one


@router.post("/hosts/test")
async def hosts_test(body: TestIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    body.validate_auth(editing=body.host_id is not None)
    secret = body.secret
    existing = _get_host(db, body.host_id) if body.host_id is not None else None
    same_target = (existing is not None and body.host.strip().lower() == existing.host.strip().lower()
                   and body.port == existing.port and body.verify_ssl == existing.verify_ssl)
    if not secret and existing is not None:
        # the stored secret is only ever sent to the stored host and account
        if not (same_target and body.auth_type == existing.auth_type and body.pve_user.strip() == existing.pve_user
                and (body.auth_type != "token" or body.token_name.strip() == existing.token_name)):
            note_current(details={"refused": "stored secret not reused for a different address or account"})
            return {"ok": False, "error": "The address or account differs from the saved host, so the saved "
                                          "token / password is not sent. Enter it to test these settings."}
        secret = crypto.decrypt(existing.secret_enc)
    probe = ProxmoxHost(
        name=body.name,
        host=body.host.strip(),
        port=body.port,
        verify_ssl=body.verify_ssl,
        auth_type=body.auth_type,
        pve_user=body.pve_user.strip(),
        token_name=body.token_name.strip(),
        secret_enc="",
        tls_fingerprint=(existing.tls_fingerprint if same_target and existing.verify_ssl == body.verify_ssl else ""),
    )
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(None, test_connection, probe, secret)
    except PveError as exc:
        return {"ok": False, "error": str(exc)}
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, **result}


# --------------------------------------------------------------------------- #
# TLS pin
# --------------------------------------------------------------------------- #

@router.get("/hosts/{host_id}/tls")
async def host_tls(host_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """The pinned certificate and the one the host presents right now."""
    host = _get_host(db, host_id)
    presented, error = "", ""
    try:
        presented = await asyncio.to_thread(tlspin.fetch, host.host, host.port, 10)
    except Exception as exc:  # noqa: BLE001
        error = f"Could not read the certificate from {host.host}:{host.port} ({exc.__class__.__name__})."
    pinned = tlspin.normalize(host.tls_fingerprint)
    return {"mode": "ca" if host.verify_ssl else ("pinned" if pinned else "pending"),
            "pinned": tlspin.pretty(pinned), "presented": tlspin.pretty(presented),
            "match": bool(pinned and presented and pinned == presented), "error": error}


class TlsAcceptIn(BaseModel):
    fingerprint: str = Field(min_length=1, max_length=100)


@router.post("/hosts/{host_id}/tls/accept")
async def host_tls_accept(host_id: int, body: TlsAcceptIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Pin the certificate the host presents now. The admin must send the fingerprint they were
    shown (and checked on the node); it must still be what the host presents."""
    host = _get_host(db, host_id)
    if host.verify_ssl:
        raise HTTPException(400, "This host is verified against the system CAs (Verify SSL), so it has no pin.")
    want = tlspin.normalize(body.fingerprint)
    if not want:
        raise HTTPException(400, "That isn't a SHA-256 fingerprint.")
    try:
        presented = await asyncio.to_thread(tlspin.fetch, host.host, host.port, 10)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(502, f"Could not read the certificate from {host.host}:{host.port} ({exc.__class__.__name__}).")
    if presented != want:
        raise HTTPException(409, "The host presents a different certificate than the one you accepted "
                                 f"({tlspin.pretty(presented)}). Check again.")
    old = host.tls_fingerprint
    host.tls_fingerprint = want
    host.last_error = ""
    db.commit()
    note_current(action="host.tls_accept", host_name=host.name,
                 details={"previous_sha256": tlspin.pretty(old), "sha256": tlspin.pretty(want)})
    if host.enabled:
        asyncio.create_task(poller.poll_one_now(host.id))
    return {"ok": True, "pinned": tlspin.pretty(want)}


@router.post("/hosts/{host_id}/refresh")
async def hosts_refresh(host_id: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    host = _get_host(db, host_id)
    if not host.enabled:
        raise HTTPException(400, "Host is disabled")
    await poller.poll_one_now(host.id)
    db.expire_all()
    host = _get_host(db, host_id)
    return {"ok": not host.last_error, "error": host.last_error, "last_poll_at": _iso(host.last_poll_at)}


@router.post("/refresh-all")
async def refresh_all(user: User = Depends(require_user)):
    poller.trigger()
    return {"ok": True}


# --------------------------------------------------------------------------- #
# SSH: dashboard key, per-host test, pinned host keys
# --------------------------------------------------------------------------- #

@router.get("/ssh/key")
def ssh_key_get(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    pub = ssh.get_app_public_key(db)
    return {"public_key": pub, "exists": bool(pub)}


@router.post("/ssh/key/generate")
def ssh_key_generate(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    pub = ssh.generate_app_keypair(db)
    return {"public_key": pub, "exists": True}


class SshTestIn(BaseModel):
    host_id: int | None = None
    host: str = Field(min_length=1, max_length=255)
    ssh_user: str = Field(default="root", max_length=64)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_auth: Literal["appkey", "key", "password"] = "appkey"
    ssh_secret: str = Field(default="", max_length=16000)


@router.post("/ssh/test")
async def ssh_test(body: SshTestIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Test SSH to the host's main address with the credentials in the form (saved or not)."""
    secret = body.ssh_secret
    if body.ssh_auth != "appkey" and not secret:
        if body.host_id is not None:
            h = _get_host(db, body.host_id)
            # a stored SSH key / password only goes to the stored address and user
            if (body.host.strip().lower() != h.host.strip().lower() or (body.ssh_user.strip() or "root") != (h.ssh_user or "root")
                    or body.ssh_port != (h.ssh_port or 22) or body.ssh_auth != h.ssh_auth):
                note_current(details={"refused": "stored SSH secret not reused for a different address or user"})
                return {"ok": False, "error": "The address or SSH user differs from the saved host, so the saved "
                                              "SSH key / password is not sent. Enter it to test these settings."}
            secret = crypto.decrypt(h.ssh_secret_enc) if h.ssh_secret_enc else ""
        if not secret:
            return {"ok": False, "error": "Enter the SSH private key / password first."}
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            None, ssh.probe, db, body.host.strip(), body.ssh_port, body.ssh_user.strip() or "root", body.ssh_auth, secret
        )
    except (ssh.SshError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{exc.__class__.__name__}: {exc}"}
    if result["ok"] and not result["is_root"]:
        result["warning"] = f"Connected as a non-root user ({body.ssh_user}); apt upgrades and reboots need root."
    return result


@router.post("/hosts/{host_id}/ssh/enable")
async def ssh_enable(host_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """One-click from the SSH key card: test the dashboard key against the host and,
    if it works, turn SSH on (dashboard key, root, existing port or 22)."""
    host = _get_host(db, host_id)
    auth = host.ssh_auth if host.ssh_enabled else "appkey"
    secret = crypto.decrypt(host.ssh_secret_enc) if auth != "appkey" and host.ssh_secret_enc else ""
    port = host.ssh_port or 22
    username = host.ssh_user or "root"
    address = ssh.node_address(host, ((_summary(host) or {}).get("nodes") or [{}])[0].get("node", ""), _summary(host))
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(None, ssh.probe, db, address, port, username, auth, secret)
    except (ssh.SshError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{exc.__class__.__name__}: {exc}"}
    if not result.get("ok"):
        return {"ok": False, "error": "Connected, but the test command failed."}
    if not result.get("is_root"):
        return {"ok": False, "error": f"Connected as non-root user {username}; updates and reboots need root."}
    host.ssh_enabled = True
    host.ssh_auth = auth
    host.ssh_user = username
    host.ssh_port = port
    db.commit()
    return result


@router.post("/hosts/{host_id}/ssh/forget-keys")
def ssh_forget_keys(host_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    host = _get_host(db, host_id)
    return {"removed": ssh.forget_host_keys(db, host)}


# --------------------------------------------------------------------------- #
# Jobs: check updates / upgrade / reboot
# --------------------------------------------------------------------------- #

def _job_public(j: Job, with_output: bool = True) -> dict:
    d = {
        "id": j.id,
        "host_id": j.host_id,
        "node": j.node,
        "vmid": j.vmid,
        "kind": j.kind,
        "status": j.status,
        "requested_by": j.requested_by,
        "options": json.loads(j.options_json or "{}"),
        "result": json.loads(j.result_json) if j.result_json else None,
        "error": j.error,
        "created_at": _iso(j.created_at),
        "started_at": _iso(j.started_at),
        "finished_at": _iso(j.finished_at),
    }
    if with_output:
        d["output"] = j.output
    return d


class JobIn(BaseModel):
    auto_reboot: bool = False
    confirm: str = Field(default="", max_length=128)  # node name typed by the user for upgrade/reboot


def _check_node(host: ProxmoxHost, node: str, needs_ssh: bool = True) -> None:
    s = _summary(host)
    if s and not any(n.get("node") == node for n in s.get("nodes", [])):
        raise HTTPException(404, f"Node '{node}' is not part of this host")
    if needs_ssh and not host.ssh_enabled:
        raise HTTPException(400, "SSH is not enabled for this host. Edit the host and configure SSH access first.")
    if not host.enabled:
        raise HTTPException(400, "Host is disabled")


_JOB_AUDIT_KEYS = ("action", "force_stop", "snapname", "vmstate", "storage", "mode", "compress", "disk", "add_gb",
                   "size_before", "onboot", "auto_reboot", "type", "name")


def _start(host: ProxmoxHost, node: str, kind: str, user: User, options: dict, vmid: int | None = None) -> dict:
    det = {"job": kind, **{k: options[k] for k in _JOB_AUDIT_KEYS if k in options}}
    note_current(action="job." + kind, host_name=host.name, node=node, vmid=vmid, details=det)
    try:
        job_id = jobs.start_job(host.id, node, kind, user.username, options, vmid=vmid)
    except RuntimeError as exc:
        note_current(details={"refused": str(exc)[:200]})
        raise HTTPException(409, str(exc))
    note_current(details={"job_id": job_id})
    return {"job_id": job_id}


@router.post("/hosts/{host_id}/nodes/{node}/check-updates", status_code=202)
def node_check_updates(host_id: int, node: str, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    host = _get_host(db, host_id)
    _check_node(host, node)
    return _start(host, node, "check_updates", user, {})


@router.post("/hosts/{host_id}/nodes/{node}/upgrade", status_code=202)
def node_upgrade(host_id: int, node: str, body: JobIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    host = _get_host(db, host_id)
    _check_node(host, node)
    if body.confirm.strip() != node:
        raise HTTPException(400, f"Type the node name '{node}' to confirm the upgrade")
    return _start(host, node, "upgrade", user, {"auto_reboot": body.auto_reboot})


@router.post("/hosts/{host_id}/nodes/{node}/reboot", status_code=202)
def node_reboot(host_id: int, node: str, body: JobIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    host = _get_host(db, host_id)
    _check_node(host, node)
    if body.confirm.strip() != node:
        raise HTTPException(400, f"Type the node name '{node}' to confirm the reboot")
    return _start(host, node, "reboot", user, {})


@router.post("/hosts/{host_id}/nodes/{node}/refresh-packages", status_code=202)
def node_refresh_packages(host_id: int, node: str, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """apt update via the Proxmox API (no SSH). Needs Sys.Modify on the token."""
    host = _get_host(db, host_id)
    _check_node(host, node, needs_ssh=False)
    return _start(host, node, "refresh_packages", user, {})


@router.post("/hosts/{host_id}/nodes/{node}/switch-repos", status_code=202)
def node_switch_repos(host_id: int, node: str, body: JobIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Disable enterprise repos and add no-subscription ones via the PVE API. Needs Sys.Modify."""
    host = _get_host(db, host_id)
    _check_node(host, node, needs_ssh=False)
    if body.confirm.strip() != node:
        raise HTTPException(400, f"Type the node name '{node}' to confirm the repository change")
    return _start(host, node, "switch_repos", user, {})


@router.post("/hosts/{host_id}/nodes/{node}/api-reboot", status_code=202)
def node_api_reboot(host_id: int, node: str, body: JobIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Reboot via the Proxmox API (no SSH). Needs Sys.PowerMgmt on the token."""
    host = _get_host(db, host_id)
    _check_node(host, node, needs_ssh=False)
    if body.confirm.strip() != node:
        raise HTTPException(400, f"Type the node name '{node}' to confirm the reboot")
    return _start(host, node, "api_reboot", user, {})


# --------------------------------------------------------------------------- #
# Guests: power, snapshot, backup (Proxmox API jobs; admins and technicians, see permissions.py)
# --------------------------------------------------------------------------- #

def _guest(host: ProxmoxHost, node: str, vmid: int) -> dict:
    """The guest as the last poll saw it. Refuses unknown guests and guests on another node."""
    for g in (_summary(host) or {}).get("guests") or []:
        try:
            gid = int(g.get("vmid"))
        except (TypeError, ValueError):
            continue
        if gid != vmid:
            continue
        if g.get("node") != node:
            raise HTTPException(409, f"Guest {vmid} is on node {g.get('node')} now, not {node}. Refresh the page and try again.")
        if g.get("node_offline"):
            raise HTTPException(409, f"Node {node} is offline, so guest {vmid} can't be managed until it is back.")
        return g
    raise HTTPException(404, f"Guest {vmid} is not in the last poll of this host. Refresh the host and try again.")


def _guest_options(g: dict, **extra) -> dict:
    return {"vmid": int(g["vmid"]), "type": g.get("type"), "name": g.get("name", ""), **extra}


class GuestPowerIn(BaseModel):
    action: Literal["start", "shutdown", "reboot", "stop"]
    confirm: str = Field(default="", max_length=32)  # the VMID, required for a hard stop
    force_stop: bool = False  # shutdown only: stop hard if the guest hasn't shut down in time


@router.post("/hosts/{host_id}/nodes/{node}/guests/{vmid}/power", status_code=202)
def guest_power(host_id: int, node: str, vmid: int, body: GuestPowerIn, db: Session = Depends(get_db),
                user: User = Depends(require_cap(perms.GUEST_POWER))):
    host = _get_host(db, host_id)
    _check_node(host, node, needs_ssh=False)
    g = _guest(host, node, vmid)
    if g.get("template"):
        raise HTTPException(400, f"{vmid} is a template; templates can't be started or stopped.")
    if body.action == "stop" and body.confirm.strip() != str(vmid):
        raise HTTPException(400, f"Type the guest ID {vmid} to confirm the hard stop")
    options = _guest_options(g, action=body.action, force_stop=bool(body.force_stop and body.action == "shutdown"))
    return _start(host, node, "guest_power", user, options, vmid=vmid)


class GuestSnapshotIn(BaseModel):
    snapname: str = Field(min_length=2, max_length=40)
    description: str = Field(default="", max_length=500)
    vmstate: bool = False  # VMs only: include RAM so the snapshot resumes a running VM


@router.post("/hosts/{host_id}/nodes/{node}/guests/{vmid}/snapshot", status_code=202)
def guest_snapshot(host_id: int, node: str, vmid: int, body: GuestSnapshotIn, db: Session = Depends(get_db),
                   user: User = Depends(require_cap(perms.GUEST_SNAPSHOT))):
    host = _get_host(db, host_id)
    _check_node(host, node, needs_ssh=False)
    g = _guest(host, node, vmid)
    if g.get("template"):
        raise HTTPException(400, f"{vmid} is a template; templates can't have snapshots.")
    name = body.snapname.strip()
    if not jobs.SNAPNAME_RE.match(name) or name.lower() == "current":
        raise HTTPException(400, "Snapshot name must start with a letter and use only letters, digits, - and _ "
                                 "(2-40 characters; 'current' is reserved).")
    vmstate = bool(body.vmstate and g.get("type") == "qemu" and g.get("status") == "running")
    options = _guest_options(g, snapname=name, description=body.description.strip(), vmstate=vmstate)
    return _start(host, node, "guest_snapshot", user, options, vmid=vmid)


class GuestBackupIn(BaseModel):
    storage: str = Field(min_length=1, max_length=64)
    mode: Literal["snapshot", "suspend", "stop"] = "snapshot"
    compress: Literal["zstd", "lzo", "gzip", "0"] = "zstd"  # ignored for Proxmox Backup Server storage
    notes: str = Field(default="{{guestname}}", max_length=200)


@router.get("/hosts/{host_id}/nodes/{node}/backup-storages")
async def backup_storages(host_id: int, node: str, db: Session = Depends(get_db), user: User = Depends(require_cap(perms.GUEST_BACKUP))):
    """Storages on the node that accept backups (live from Proxmox)."""
    host = _get_host(db, host_id)
    _check_node(host, node, needs_ssh=False)
    loop = asyncio.get_running_loop()
    try:
        stores = await loop.run_in_executor(None, list_backup_storages, host, node)
    except (PveError, ValueError) as exc:
        raise HTTPException(502, str(exc))
    return {"node": node, "storages": stores}


@router.post("/hosts/{host_id}/nodes/{node}/guests/{vmid}/backup", status_code=202)
async def guest_backup(host_id: int, node: str, vmid: int, body: GuestBackupIn, db: Session = Depends(get_db),
                       user: User = Depends(require_cap(perms.GUEST_BACKUP))):
    host = _get_host(db, host_id)
    _check_node(host, node, needs_ssh=False)
    g = _guest(host, node, vmid)
    loop = asyncio.get_running_loop()
    try:
        stores = await loop.run_in_executor(None, list_backup_storages, host, node)
    except (PveError, ValueError) as exc:
        raise HTTPException(502, str(exc))
    st = next((s for s in stores if s["storage"] == body.storage), None)
    if st is None:
        raise HTTPException(400, f"Storage '{body.storage}' doesn't take backups on {node}, or the API token can't see it.")
    options = _guest_options(g, storage=st["storage"], storage_type=st["type"], mode=body.mode,
                             compress=body.compress, notes=body.notes.strip())
    return _start(host, node, "guest_backup", user, options, vmid=vmid)


@router.get("/hosts/{host_id}/nodes/{node}/guests/{vmid}/disks")
async def guest_disks_list(host_id: int, node: str, vmid: int, db: Session = Depends(get_db),
                           user: User = Depends(require_cap(perms.GUEST_DISK))):
    """Disks of a guest that can be expanded (live from its Proxmox config)."""
    host = _get_host(db, host_id)
    _check_node(host, node, needs_ssh=False)
    g = _guest(host, node, vmid)
    loop = asyncio.get_running_loop()
    try:
        disks = await loop.run_in_executor(None, guest_disks, host, node, g.get("type") or "qemu", vmid)
    except (PveError, ValueError) as exc:
        raise HTTPException(502, str(exc))
    return {"vmid": vmid, "disks": disks}


@router.get("/hosts/{host_id}/nodes/{node}/guests/{vmid}/details")
async def guest_details_get(host_id: int, node: str, vmid: int, db: Session = Depends(get_db),
                            user: User = Depends(require_cap(perms.GUEST_DETAILS))):
    """Start at boot, startup order, network adapters with bridge / VLAN, and the disks that
    can be expanded (live from the guest's Proxmox config)."""
    host = _get_host(db, host_id)
    _check_node(host, node, needs_ssh=False)
    g = _guest(host, node, vmid)
    loop = asyncio.get_running_loop()
    try:
        details = await loop.run_in_executor(None, guest_details, host, node, g.get("type") or "qemu", vmid)
    except (PveError, ValueError) as exc:
        raise HTTPException(502, str(exc))
    return {"vmid": vmid, **details}


class GuestOnbootIn(BaseModel):
    onboot: bool


@router.post("/hosts/{host_id}/nodes/{node}/guests/{vmid}/onboot", status_code=202)
def guest_onboot(host_id: int, node: str, vmid: int, body: GuestOnbootIn, db: Session = Depends(get_db),
                 user: User = Depends(require_cap(perms.GUEST_ONBOOT))):
    """Turn "Start at boot" on or off. Runs as a job so the change is recorded with the user."""
    host = _get_host(db, host_id)
    _check_node(host, node, needs_ssh=False)
    g = _guest(host, node, vmid)
    if g.get("template"):
        raise HTTPException(400, f"{vmid} is a template; templates can't be started, so Start at boot doesn't apply.")
    return _start(host, node, "guest_onboot", user, _guest_options(g, onboot=body.onboot), vmid=vmid)


class GuestResizeIn(BaseModel):
    disk: str = Field(pattern=r"^((scsi|virtio|sata|ide|mp)\d+|rootfs)$")
    add_gb: int = Field(ge=1, le=16384)  # grow only; Proxmox can't shrink disks


@router.post("/hosts/{host_id}/nodes/{node}/guests/{vmid}/resize", status_code=202)
async def guest_resize(host_id: int, node: str, vmid: int, body: GuestResizeIn, db: Session = Depends(get_db),
                       user: User = Depends(require_cap(perms.GUEST_DISK))):
    host = _get_host(db, host_id)
    _check_node(host, node, needs_ssh=False)
    g = _guest(host, node, vmid)
    if g.get("template"):
        raise HTTPException(400, f"{vmid} is a template; clone it and expand the clone's disk instead.")
    loop = asyncio.get_running_loop()
    try:
        disks = await loop.run_in_executor(None, guest_disks, host, node, g.get("type") or "qemu", vmid)
    except (PveError, ValueError) as exc:
        raise HTTPException(502, str(exc))
    d = next((x for x in disks if x["disk"] == body.disk), None)
    if d is None:
        raise HTTPException(400, f"{body.disk} is not a disk of {vmid} that can be expanded.")
    options = _guest_options(g, disk=d["disk"], add_gb=body.add_gb, size_before=d["size"], storage=d["storage"])
    return _start(host, node, "guest_resize", user, options, vmid=vmid)


# The browser-side sign-in (POST /console-login returning a root@pam ticket) was
# replaced by the console relay in routers/console.py; the root ticket never leaves the server.


@router.delete("/hosts/{host_id}/console-login", status_code=204)
def console_login_forget(host_id: int, db: Session = Depends(get_db), user: User = Depends(require_cap(perms.CONSOLE))):
    host = _get_host(db, host_id)
    host.console_secret_enc = ""
    db.commit()


@router.get("/jobs/{job_id}")
def job_get(job_id: int, since: int = Query(default=0, ge=0), db: Session = Depends(get_db), user: User = Depends(require_user)):
    """Job state plus output. Pass since=<chars already received> to get only new output."""
    j = db.get(Job, job_id)
    if j is None:
        raise HTTPException(404, "Job not found")
    d = _job_public(j, with_output=False)
    full = j.output or ""
    d["output"] = full[since:] if since <= len(full) else full
    d["output_len"] = len(full)
    return d


@router.get("/hosts/{host_id}/jobs")
def host_jobs(host_id: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    host = _get_host(db, host_id)
    rows = db.query(Job).filter(Job.host_id == host.id).order_by(Job.created_at.desc()).limit(50).all()
    return [_job_public(j, with_output=False) for j in rows]


# --------------------------------------------------------------------------- #
# Node network
# --------------------------------------------------------------------------- #

@router.get("/hosts/{host_id}/nodes/{node}/network")
async def node_network_get(host_id: int, node: str, db: Session = Depends(get_db), user: User = Depends(require_user)):
    """Read-only: interfaces, addresses, bridges / bonds / VLANs and DNS of one node (every role)."""
    host = _get_host(db, host_id)
    if not _NODE_NAME_RE.fullmatch(node):
        raise HTTPException(404, "Unknown node")
    _check_node(host, node, needs_ssh=False)
    loop = asyncio.get_running_loop()
    try:
        net = await loop.run_in_executor(None, node_network, host, node)
    except (PveError, ValueError) as exc:
        raise HTTPException(502, str(exc))
    s = _summary(host) or {}
    mgmt = next((n.get("ip", "") for n in s.get("nodes", []) if n.get("node") == node), "")
    return {"node": node, "management_ip": mgmt, **net}


# --------------------------------------------------------------------------- #
# Disks / SMART
# --------------------------------------------------------------------------- #

@router.get("/hosts/{host_id}/nodes/{node}/disks")
async def node_disks(host_id: int, node: str, db: Session = Depends(get_db), user: User = Depends(require_user)):
    host = _get_host(db, host_id)
    loop = asyncio.get_running_loop()
    try:
        disks = await loop.run_in_executor(None, list_disks, host, node)
    except (PveError, ValueError) as exc:
        raise HTTPException(502, str(exc))
    last = {
        s.devpath: s
        for s in db.query(SmartResult).filter(SmartResult.host_id == host.id, SmartResult.node == node).all()
    }
    for d in disks:
        s = last.get(d["devpath"])
        d["last_smart"] = (
            {
                "ts": _iso(s.ts),
                "health": s.health,
                "requested_by": s.requested_by,
                "result": json.loads(s.result_json) if s.result_json else None,
            }
            if s
            else None
        )
    return {"node": node, "disks": disks}


class SmartIn(BaseModel):
    devpath: str = Field(min_length=5, max_length=128, pattern=r"^/dev/[A-Za-z0-9/_\-]+$")


def _store_smart(db: Session, host: ProxmoxHost, node: str, result: dict, username: str) -> dict:
    row = (
        db.query(SmartResult)
        .filter(SmartResult.host_id == host.id, SmartResult.node == node, SmartResult.devpath == result["devpath"])
        .first()
    )
    if row is None:
        row = SmartResult(host_id=host.id, node=node, devpath=result["devpath"])
        db.add(row)
    row.ts = datetime.now(timezone.utc)
    row.health = result.get("health", "")
    row.result_json = json.dumps(result)
    row.requested_by = username
    db.commit()
    return {"ts": _iso(row.ts), "health": row.health, "requested_by": username, "result": result}


@router.post("/hosts/{host_id}/nodes/{node}/smart")
async def node_smart(
    host_id: int, node: str, body: SmartIn, db: Session = Depends(get_db), user: User = Depends(require_user)
):
    """Read SMART health + attributes for one disk (runs smartctl on the node via the PVE API)."""
    host = _get_host(db, host_id)
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(None, read_smart, host, node, body.devpath)
    except (PveError, ValueError) as exc:
        raise HTTPException(502, str(exc))
    return _store_smart(db, host, node, result, user.username)


@router.post("/hosts/{host_id}/nodes/{node}/smart/all")
async def node_smart_all(host_id: int, node: str, db: Session = Depends(get_db), user: User = Depends(require_user)):
    """Read SMART for every physical disk on a node."""
    host = _get_host(db, host_id)
    loop = asyncio.get_running_loop()
    try:
        disks = await loop.run_in_executor(None, list_disks, host, node)
    except (PveError, ValueError) as exc:
        raise HTTPException(502, str(exc))
    results = []
    for d in disks:
        try:
            r = await loop.run_in_executor(None, read_smart, host, node, d["devpath"])
            results.append({"devpath": d["devpath"], "ok": True, **_store_smart(db, host, node, r, user.username)})
        except (PveError, ValueError) as exc:
            results.append({"devpath": d["devpath"], "ok": False, "error": str(exc)})
    return {"node": node, "results": results}


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #

_authlog = logging.getLogger("app.auth")


def _user_public(u: User, cfg: loginconfig.LoginConfig | None = None) -> dict:
    d = {
        "id": u.id,
        "username": u.username,
        "role": u.role,
        "is_active": u.is_active,
        "created_at": _iso(u.created_at),
        "last_login_at": _iso(u.last_login_at),
        "auth_source": u.auth_source or "local",
        "display_name": u.display_name or "",
        "mfa_enabled": bool(u.mfa_enabled),
        "must_change_password": bool(u.must_change_password) and not u.is_sso,
    }
    if cfg is not None:
        d["mfa_required"] = cfg.mfa_required(u)
    d["enroll_code_pending"] = (not u.mfa_enabled) and mfa.enroll_code_pending(u)
    return d


def _maybe_enroll_code(db: Session, u: User) -> str:
    """A local admin / technician without an authenticator gets a one-time enrollment code
    (returned once to the admin, shown in the UI) when MFA sign-in is in use."""
    cfg = loginconfig.load(db)
    if u.is_sso or u.mfa_enabled or not cfg.mfa_available or not cfg.mfa_required(u):
        return ""
    return mfa.new_enroll_code(u)


class UserIn(BaseModel):
    username: str = Field(min_length=2, max_length=64, pattern=r"^[A-Za-z0-9._@\-]+$")
    password: str = Field(default="", max_length=128)
    role: Literal["admin", "technician", "viewer"] = "viewer"
    is_active: bool = True


@router.get("/me")
def me(db: Session = Depends(get_db), user: User = Depends(require_user)):
    cfg = loginconfig.load(db)
    d = _user_public(user, cfg)
    d["login_mode"] = cfg.mode
    d["mfa_available"] = cfg.mfa_available
    d["recovery_codes_left"] = mfa.recovery_left(user) if user.mfa_enabled else 0
    d["caps"] = user.caps
    d["theme"] = clean_theme(user.theme)
    return d


class ThemeIn(BaseModel):
    theme: Literal["dark", "light", "system"]


@router.put("/me/theme")
def set_my_theme(body: ThemeIn, db: Session = Depends(get_db), user: User = Depends(require_user)):
    """Colour theme for this account (follows the user to every browser)."""
    from fastapi.responses import JSONResponse

    note_current(action="account.theme", details={"theme": body.theme})
    db_user = db.get(User, user.id)
    db_user.theme = body.theme
    db.commit()
    resp = JSONResponse({"ok": True, "theme": body.theme})
    theme_cookie(resp, body.theme)
    return resp


@router.get("/login-config")
def login_config(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Current sign-in mode (read only; change it with manage.py configure-login)."""
    cfg = loginconfig.load(db)
    return {"mode": cfg.mode, "label": loginconfig.MODE_LABELS[cfg.mode], "configured": cfg.configured,
            "entra_tenant": cfg.tenant, "entra_client_id": cfg.client_id, "entra_redirect_uri": cfg.redirect_uri,
            "entra_ready": cfg.entra_ready}


class MfaCodeIn(BaseModel):
    code: str = Field(default="", max_length=16)


def _local_mfa_user(db: Session, user: User) -> tuple[User, loginconfig.LoginConfig]:
    cfg = loginconfig.load(db)
    if user.is_sso:
        raise HTTPException(400, "Microsoft accounts use Entra ID for two-step sign-in.")
    if not cfg.mfa_available:
        raise HTTPException(400, "Two-step sign-in is not enabled on this dashboard (login mode is password only).")
    return db.get(User, user.id), cfg


@router.post("/me/mfa/setup")
def mfa_setup(db: Session = Depends(get_db), user: User = Depends(require_user)):
    """Start enrolling an authenticator app: returns the secret and a QR code."""
    note_current(category="auth", action="account.mfa.setup")
    u, _cfg = _local_mfa_user(db, user)
    if u.mfa_enabled:
        raise HTTPException(400, "Two-step sign-in is already on. Turn it off first to move it to a new phone.")
    secret = mfa.start_enrollment(u)
    db.commit()
    uri = mfa.provisioning_uri(secret, u.username)
    return {"secret": secret, "uri": uri, "qr_svg": mfa.qr_svg(uri)}


@router.post("/me/mfa/enable")
def mfa_enable(body: MfaCodeIn, request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    note_current(category="auth", action="account.mfa.enable")
    u, _cfg = _local_mfa_user(db, user)
    codes = mfa.finish_enrollment(u, body.code)
    if codes is None:
        raise HTTPException(400, "That code didn't match. Enter the current 6-digit code from the app.")
    db.commit()
    request.session["amr"] = "mfa"
    _authlog.info("mfa enrolled user=%s (account page)", u.username)
    return {"recovery_codes": codes}


@router.post("/me/mfa/disable")
def mfa_disable(body: MfaCodeIn, db: Session = Depends(get_db), user: User = Depends(require_user)):
    note_current(category="auth", action="account.mfa.disable")
    u, cfg = _local_mfa_user(db, user)
    if cfg.mfa_required(u):
        raise HTTPException(400, "Two-step sign-in is required for admin and technician accounts and can't be turned off.")
    if not u.mfa_enabled:
        return {"ok": True}
    if not (mfa.verify_user_code(u, body.code) or mfa.use_recovery_code(u, body.code)):
        raise HTTPException(400, "Wrong code.")
    mfa.disable(u)
    db.commit()
    _authlog.info("mfa disabled user=%s (account page)", u.username)
    return {"ok": True}


@router.post("/me/mfa/recovery-codes")
def mfa_new_recovery(body: MfaCodeIn, db: Session = Depends(get_db), user: User = Depends(require_user)):
    note_current(category="auth", action="account.mfa.recovery_codes")
    u, _cfg = _local_mfa_user(db, user)
    if not u.mfa_enabled:
        raise HTTPException(400, "Two-step sign-in is not on.")
    if not mfa.verify_user_code(u, body.code):
        raise HTTPException(400, "Wrong code. Enter the current code from your authenticator app.")
    codes = mfa.new_recovery_codes(u)
    db.commit()
    _authlog.info("mfa recovery codes regenerated user=%s", u.username)
    return {"recovery_codes": codes}


class PasswordChangeIn(BaseModel):
    current_password: str
    new_password: str


@router.post("/me/password")
def change_my_password(body: PasswordChangeIn, request: Request, db: Session = Depends(get_db), user: User = Depends(require_user)):
    note_current(category="auth", action="account.password")
    if user.is_sso:
        raise HTTPException(400, "Microsoft accounts have no password here; change it in Microsoft 365.")
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(400, "Current password is incorrect")
    err = validate_password_strength(body.new_password)
    if err:
        raise HTTPException(400, err)
    db_user = db.get(User, user.id)
    db_user.password_hash = hash_password(body.new_password)
    db_user.must_change_password = False
    db_user.rotate_session_key()                    # other browsers are signed out...
    request.session["uk"] = db_user.session_key     # ...this one stays signed in
    db.commit()
    note_current(details={"other_sessions_signed_out": True})
    return {"ok": True}


@router.get("/users")
def users_list(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    cfg = loginconfig.load(db)
    return [_user_public(u, cfg) for u in db.query(User).order_by(User.username).all()]


@router.delete("/users/{user_id}/mfa")
def users_reset_mfa(user_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Remove a user's authenticator so they enroll again at next sign-in."""
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "User not found")
    if u.id == user.id:
        raise HTTPException(400, "Reset your own authenticator from your Account page, or ask another admin.")
    if u.is_sso:
        raise HTTPException(400, "Microsoft accounts use Entra ID for two-step sign-in.")
    mfa.disable(u)
    u.rotate_session_key()
    code = _maybe_enroll_code(db, u)
    db.commit()
    _authlog.warning("mfa reset user=%s by=%s", u.username, user.username)
    note_current(category="auth", action="user.mfa_reset", target_user=u.username, details={"enrollment_code_issued": bool(code)})
    return {"ok": True, "enrollment_code": code}


@router.post("/users/{user_id}/enrollment-code")
def users_enroll_code(user_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """A new one-time authenticator enrollment code for a user who must use one."""
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "User not found")
    if u.is_sso:
        raise HTTPException(400, "Microsoft accounts use Entra ID for two-step sign-in.")
    if u.mfa_enabled:
        raise HTTPException(400, "This user already has an authenticator. Reset it first to move it to a new phone.")
    code = _maybe_enroll_code(db, u)
    if not code:
        raise HTTPException(400, "This user doesn't need an authenticator in the current sign-in mode.")
    db.commit()
    note_current(category="auth", action="user.enroll_code", target_user=u.username, details={"valid_days": mfa.ENROLL_CODE_DAYS})
    return {"enrollment_code": code, "valid_days": mfa.ENROLL_CODE_DAYS}


@router.post("/users", status_code=201)
def users_create(body: UserIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    err = validate_password_strength(body.password)
    if err:
        raise HTTPException(400, err)
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(409, "Username already exists")
    # the user replaces the admin-chosen password at the first sign-in
    u = User(username=body.username, password_hash=hash_password(body.password), role=body.role, is_active=body.is_active,
             must_change_password=True)
    code = _maybe_enroll_code(db, u)
    db.add(u)
    db.commit()
    db.refresh(u)
    note_current(action="user.create", target_user=u.username, details={"role": u.role, "active": u.is_active,
                                                                        "enrollment_code_issued": bool(code),
                                                                        "password_change_required": True})
    return {**_user_public(u), "enrollment_code": code}


@router.put("/users/{user_id}")
def users_update(user_id: int, body: UserIn, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "User not found")
    note_current(action="user.update", target_user=u.username)
    if u.id == user.id and (body.role != "admin" or not body.is_active):
        raise HTTPException(400, "You cannot demote or disable your own account")
    if u.is_sso:
        # Name and role come from Entra ID at every sign-in; only enable/disable is managed here.
        if body.password:
            raise HTTPException(400, "Microsoft accounts have no password here.")
        was_active = u.is_active
        u.is_active = body.is_active
        if was_active != u.is_active:
            u.rotate_session_key()
        db.commit()
        note_current(details={"changed": ["active"] if was_active != u.is_active else [], "active": u.is_active})
        _after_user_change(u)
        return _user_public(u)
    clash = db.query(User).filter(User.username == body.username, User.id != u.id).first()
    if clash:
        raise HTTPException(409, "Username already exists")
    before = {"username": u.username, "role": u.role, "active": u.is_active}
    promoted = before["role"] == "viewer" and body.role in ("admin", "technician")
    if promoted and u.mfa_enabled:
        # an authenticator a viewer set up without an enrollment code isn't trusted for a privileged role
        mfa.disable(u)
    u.username = body.username
    u.role = body.role
    u.is_active = body.is_active
    if body.password:
        err = validate_password_strength(body.password)
        if err:
            raise HTTPException(400, err)
        u.password_hash = hash_password(body.password)
        # a password an admin sets for someone else is replaced at their next sign-in
        u.must_change_password = u.id != user.id
    signed_out = bool(body.password) or before["role"] != u.role or before["active"] != u.is_active
    code = _maybe_enroll_code(db, u) if before["role"] != u.role and not mfa.enroll_code_pending(u) else ""
    if signed_out:
        u.rotate_session_key()   # signed out of every browser
        if u.id == user.id:
            request.session["uk"] = u.session_key   # ...except the admin's own current one
    db.commit()
    after = {"username": u.username, "role": u.role, "active": u.is_active}
    det = {k: f"{before[k]} -> {after[k]}" for k in before if before[k] != after[k]}
    if body.password:
        det["password"] = "set by admin (value not recorded)" + (", user sets a new one at next sign-in"
                                                                  if u.must_change_password else "")
    note_current(details={"changed": det, **({"signed_out_everywhere": True} if signed_out and u.id != user.id else {}),
                          **({"enrollment_code_issued": True} if code else {})})
    _after_user_change(u)
    return {**_user_public(u), "enrollment_code": code}


def _after_user_change(u: User) -> None:
    """A user who lost console access (demoted, disabled) loses open consoles and re-auth windows now."""
    from .. import consoles, stepup

    if not u.can(perms.CONSOLE):
        stepup.drop_user(u.id)
        n = consoles.kick_user(u.id, "account changed by an admin (role or access removed)")
        if n:
            note_current(details={"consoles_closed": n})


@router.delete("/users/{user_id}", status_code=204)
def users_delete(user_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "User not found")
    if u.id == user.id:
        raise HTTPException(400, "You cannot delete your own account")
    note_current(action="user.delete", target_user=u.username, details={"role": u.role})
    from .. import consoles, stepup

    stepup.drop_user(u.id)
    n = consoles.kick_user(u.id, "account deleted by an admin")
    if n:
        note_current(details={"consoles_closed": n})
    db.delete(u)
    db.commit()
    return None
