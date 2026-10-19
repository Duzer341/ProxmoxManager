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

from .. import crypto, jobs, ssh
from ..auth import (
    hash_password,
    require_admin,
    require_same_origin,
    require_user,
    validate_password_strength,
    verify_password,
)
from ..config import settings
from ..database import get_db
from ..models import Job, ProxmoxHost, SmartResult, StatSample, User
from ..poller import poller
from ..pve import (
    ConsoleAuthError,
    PveError,
    console_ticket,
    guest_details,
    guest_disks,
    list_backup_storages,
    list_disks,
    read_smart,
    test_connection,
)

router = APIRouter(prefix="/api", dependencies=[Depends(require_same_origin)])


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
    )
    db.add(host)
    db.commit()
    db.refresh(host)
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
    if not host.enabled:
        host.last_error = ""
    db.commit()
    db.refresh(host)
    if host.enabled:
        asyncio.create_task(poller.poll_one_now(host.id))
    return _host_public(host, include_config=True)


@router.delete("/hosts/{host_id}", status_code=204)
def hosts_delete(host_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    host = _get_host(db, host_id)
    active = db.query(Job).filter(Job.host_id == host.id, Job.status.in_(("queued", "running"))).first()
    if active:
        raise HTTPException(409, f"Job #{active.id} ({active.kind.replace('_', ' ')}) is still running on {active.node}. Wait for it to finish before deleting the host.")
    db.delete(host)
    db.commit()
    return None


class TestIn(HostIn):
    host_id: int | None = None  # when editing, lets a blank secret reuse the stored one


@router.post("/hosts/test")
async def hosts_test(body: TestIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    body.validate_auth(editing=body.host_id is not None)
    secret = body.secret
    if not secret and body.host_id is not None:
        existing = _get_host(db, body.host_id)
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
    )
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(None, test_connection, probe, secret)
    except PveError as exc:
        return {"ok": False, "error": str(exc)}
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, **result}


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
            stored = _get_host(db, body.host_id).ssh_secret_enc
            secret = crypto.decrypt(stored) if stored else ""
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


def _start(host: ProxmoxHost, node: str, kind: str, user: User, options: dict, vmid: int | None = None) -> dict:
    try:
        job_id = jobs.start_job(host.id, node, kind, user.username, options, vmid=vmid)
    except RuntimeError as exc:
        raise HTTPException(409, str(exc))
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
# Guests: power, snapshot, backup (Proxmox API jobs, admin only)
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
                user: User = Depends(require_admin)):
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
                   user: User = Depends(require_admin)):
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
async def backup_storages(host_id: int, node: str, db: Session = Depends(get_db), user: User = Depends(require_admin)):
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
                       user: User = Depends(require_admin)):
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
                           user: User = Depends(require_admin)):
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
                            user: User = Depends(require_admin)):
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
                 user: User = Depends(require_admin)):
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
                       user: User = Depends(require_admin)):
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


class ConsoleLoginIn(BaseModel):
    password: str = Field(default="", max_length=512)
    remember: bool = False


@router.post("/hosts/{host_id}/console-login")
async def console_login(host_id: int, body: ConsoleLoginIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Get a root@pam ticket so the browser can sign in to the PVE web UI (Upgrade shell).

    The password comes from the request, the host's own credentials (password auth as
    root@pam) or a saved console password. Only the 2-hour ticket goes back to the browser.
    """
    host = _get_host(db, host_id)
    source = _console_source(host)
    if body.password:
        password, source = body.password, "typed"
    elif source == "host":
        password = crypto.decrypt(host.secret_enc)
    elif source == "saved":
        password = crypto.decrypt(host.console_secret_enc)
    else:
        raise HTTPException(409, "Enter the root@pam password for this host.")
    try:
        ticket = await asyncio.to_thread(console_ticket, host, password)
    except ConsoleAuthError as exc:
        if source == "saved":
            host.console_secret_enc = ""
            db.commit()
            raise HTTPException(409, "The saved root password no longer works and was removed. Enter it again.") from exc
        if source == "host":
            raise HTTPException(409, "The root password stored for this host was rejected. Enter it here, "
                                     "and update the host's credentials too.") from exc
        raise HTTPException(422, str(exc)) from exc
    except PveError as exc:
        raise HTTPException(502, str(exc)) from exc
    if source == "typed" and body.remember:
        host.console_secret_enc = crypto.encrypt(body.password)
        db.commit()
    elif source == "typed" and not body.remember and host.console_secret_enc:
        host.console_secret_enc = ""
        db.commit()
    return {
        "login_url": host.ui_url.rstrip("/") + "/api2/html/access/ticket",
        "username": "root@pam",
        "ticket": ticket,
        "saved": bool(host.console_secret_enc),
    }


@router.delete("/hosts/{host_id}/console-login", status_code=204)
def console_login_forget(host_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
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

def _user_public(u: User) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "role": u.role,
        "is_active": u.is_active,
        "created_at": _iso(u.created_at),
        "last_login_at": _iso(u.last_login_at),
    }


class UserIn(BaseModel):
    username: str = Field(min_length=2, max_length=64, pattern=r"^[A-Za-z0-9._@\-]+$")
    password: str = Field(default="", max_length=128)
    role: Literal["admin", "viewer"] = "viewer"
    is_active: bool = True


@router.get("/me")
def me(user: User = Depends(require_user)):
    return _user_public(user)


class PasswordChangeIn(BaseModel):
    current_password: str
    new_password: str


@router.post("/me/password")
def change_my_password(body: PasswordChangeIn, db: Session = Depends(get_db), user: User = Depends(require_user)):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(400, "Current password is incorrect")
    err = validate_password_strength(body.new_password)
    if err:
        raise HTTPException(400, err)
    db_user = db.get(User, user.id)
    db_user.password_hash = hash_password(body.new_password)
    db.commit()
    return {"ok": True}


@router.get("/users")
def users_list(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return [_user_public(u) for u in db.query(User).order_by(User.username).all()]


@router.post("/users", status_code=201)
def users_create(body: UserIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    err = validate_password_strength(body.password)
    if err:
        raise HTTPException(400, err)
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(409, "Username already exists")
    u = User(username=body.username, password_hash=hash_password(body.password), role=body.role, is_active=body.is_active)
    db.add(u)
    db.commit()
    db.refresh(u)
    return _user_public(u)


@router.put("/users/{user_id}")
def users_update(user_id: int, body: UserIn, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "User not found")
    if u.id == user.id and (body.role != "admin" or not body.is_active):
        raise HTTPException(400, "You cannot demote or disable your own account")
    clash = db.query(User).filter(User.username == body.username, User.id != u.id).first()
    if clash:
        raise HTTPException(409, "Username already exists")
    u.username = body.username
    u.role = body.role
    u.is_active = body.is_active
    if body.password:
        err = validate_password_strength(body.password)
        if err:
            raise HTTPException(400, err)
        u.password_hash = hash_password(body.password)
    db.commit()
    return _user_public(u)


@router.delete("/users/{user_id}", status_code=204)
def users_delete(user_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(404, "User not found")
    if u.id == user.id:
        raise HTTPException(400, "You cannot delete your own account")
    db.delete(u)
    db.commit()
    return None
