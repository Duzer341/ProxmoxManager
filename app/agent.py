"""Update agent: one-click updates without root passwords or SSH.

A small agent (app/agent/pmm-agent.pl) runs as a systemd service on each Proxmox node. The dashboard
asks it to do something by writing a signed request line into the node's Notes over the Proxmox API
(PUT /nodes/{node}/config, Sys.Modify), and reads the agent's output from the node's journal
(GET /nodes/{node}/syslog?service=pmm-agent, Sys.Syslog). Nothing else is opened on the host.

Requests are signed with one Ed25519 key that only the dashboard holds (encrypted in app_settings); the
agent has the public key. A request names its node, carries a random id (single use) and expires after
REQUEST_TTL seconds, so it can't be forged by anyone with Proxmox API access or replayed elsewhere.
Actions: ping, upgrade (apt-get update + non-interactive dist-upgrade). Reboots stay on the API.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from proxmoxer.core import ResourceException

from . import crypto

log = logging.getLogger(__name__)

AGENT_VERSION = 1
REQUEST_TTL = 300
KEY_SETTING = "agent_signing_key"
SCRIPT_PATH = Path(__file__).resolve().parent / "agent" / "pmm-agent.pl"
_lock = threading.Lock()
_key_cache: list[Ed25519PrivateKey] = []


class AgentError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Signing key
# --------------------------------------------------------------------------- #

def _private_key() -> Ed25519PrivateKey:
    with _lock:
        if _key_cache:
            return _key_cache[0]
        from sqlalchemy.exc import IntegrityError

        from .database import db_session
        from .models import AppSetting

        with db_session() as db:
            row = db.get(AppSetting, KEY_SETTING)
            if row is None:
                key = Ed25519PrivateKey.generate()
                raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                        serialization.NoEncryption())
                db.add(AppSetting(key=KEY_SETTING, value=crypto.encrypt(base64.b64encode(raw).decode())))
                try:
                    db.flush()
                except IntegrityError:
                    db.rollback()
                    row = db.get(AppSetting, KEY_SETTING)
                else:
                    log.info("created the update agent signing key")
                    _key_cache.append(key)
                    return key
            raw = base64.b64decode(crypto.decrypt(row.value))
            key = Ed25519PrivateKey.from_private_bytes(raw)
            _key_cache.append(key)
            return key


def public_pem() -> str:
    pub = _private_key().public_key()
    return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def public_fingerprint() -> str:
    raw = _private_key().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def make_request(node: str, action: str, now: float | None = None) -> tuple[str, str]:
    """(request id, the line to put into the node's notes)."""
    if action not in ("ping", "upgrade"):
        raise ValueError("unknown agent action")
    rid = secrets.token_hex(12)
    payload = json.dumps({"v": 1, "id": rid, "node": node, "action": action,
                          "exp": int((now or time.time()) + REQUEST_TTL)}, separators=(",", ":"), sort_keys=True).encode()
    sig = _private_key().sign(payload)
    return rid, f"<!-- pmm-agent:v1 {_b64url(payload)}.{_b64url(sig)} -->"


# --------------------------------------------------------------------------- #
# Installer (pasted once into the node's terminal as root)
# --------------------------------------------------------------------------- #

UNIT = """[Unit]
Description=Proxmox Manager update agent (installs updates when the dashboard asks; signed requests only)
After=pve-cluster.service pveproxy.service
Wants=pve-cluster.service

[Service]
Type=simple
ExecStart=/usr/bin/perl /usr/local/lib/pmm-agent/pmm-agent.pl
Restart=always
RestartSec=10
SyslogIdentifier=pmm-agent
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
"""


def installer() -> str:
    script = SCRIPT_PATH.read_text()
    return (
        "# Proxmox Manager update agent v%d - paste into this node's shell as root (once per node)\n"
        "# Dashboard key %s\n"
        "set -e\n"
        "install -d -m 755 /usr/local/lib/pmm-agent /etc/pmm-agent\n"
        "install -d -m 700 /var/lib/pmm-agent\n"
        "cat > /usr/local/lib/pmm-agent/pmm-agent.pl <<'PMM_AGENT_EOF'\n%sPMM_AGENT_EOF\n"
        "chmod 755 /usr/local/lib/pmm-agent/pmm-agent.pl\n"
        "cat > /etc/pmm-agent/dashboard.pub <<'PMM_AGENT_EOF'\n%sPMM_AGENT_EOF\n"
        "chmod 644 /etc/pmm-agent/dashboard.pub\n"
        "cat > /etc/systemd/system/pmm-agent.service <<'PMM_AGENT_EOF'\n%sPMM_AGENT_EOF\n"
        "# the dashboard reads the agent's output from the journal: the PMM role needs Sys.Syslog\n"
        "pveum role list --output-format json | grep -q '\"roleid\":\"PMM\"' && pveum role modify PMM --privs Sys.Syslog --append 1 || true\n"
        "systemctl daemon-reload\n"
        "systemctl enable --now pmm-agent\n"
        "systemctl --no-pager --lines=3 status pmm-agent\n"
        "set +e\n"
    ) % (AGENT_VERSION, public_fingerprint(), script if script.endswith("\n") else script + "\n", public_pem(), UNIT)


UNINSTALL = ("systemctl disable --now pmm-agent\n"
             "rm -rf /usr/local/lib/pmm-agent /etc/pmm-agent /var/lib/pmm-agent /etc/systemd/system/pmm-agent.service\n"
             "systemctl daemon-reload\n")


# --------------------------------------------------------------------------- #
# Talking to the agent through the Proxmox API
# --------------------------------------------------------------------------- #

def _api_err(exc: Exception, what: str, priv: str) -> AgentError:
    if isinstance(exc, ResourceException) and exc.status_code == 403:
        return AgentError(f"Proxmox refused {what} (HTTP 403): the token needs {priv}. "
                          f"On the node: pveum role modify PMM --privs {priv} --append 1")
    if isinstance(exc, ResourceException):
        detail = str(exc.content or exc.status_message or "").strip()[:200]
        return AgentError(f"Proxmox refused {what}: HTTP {exc.status_code} {detail}")
    return AgentError(f"Could not reach the node for {what} ({exc.__class__.__name__}).")


def send(api, node: str, action: str) -> str:
    """Write a signed request into the node's notes. Returns the request id."""
    rid, line = make_request(node, action)
    for attempt in range(3):
        try:
            cfg = api.nodes(node).config.get() or {}
            desc = (cfg.get("description") or "").rstrip()
            new = (desc + "\n\n" if desc else "") + line
            params = {"description": new}
            if cfg.get("digest"):
                params["digest"] = cfg["digest"]
            api.nodes(node).config.put(**params)
            return rid
        except ResourceException as exc:
            txt = f"{exc} {exc.content or ''}".lower()
            if exc.status_code == 500 and ("modified configuration" in txt or "digest" in txt) and attempt < 2:
                time.sleep(0.5)   # someone edited the notes at the same moment: read again
                continue
            raise _api_err(exc, "writing the request to the node's notes", "Sys.Modify") from exc
        except Exception as exc:  # noqa: BLE001
            raise _api_err(exc, "writing the request to the node's notes", "Sys.Modify") from exc
    raise AgentError("The node's notes kept changing; try again.")


_LINE_RE = re.compile(r"pmm-agent(?:\[\d+\])?:\s*\[([0-9a-f]{16,32})\]\s?(.*)$")


def _since() -> str:
    # yesterday (UTC) as a date: covers any node time zone; the service filter keeps it to this agent's lines
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")


def read(api, node: str, rid: str, limit: int = 5000) -> list[str]:
    """The agent's output lines for one request (in order)."""
    try:
        rows = api.nodes(node).syslog.get(service="pmm-agent", since=_since(), limit=limit) or []
    except ResourceException as exc:
        if exc.status_code == 403:
            raise _api_err(exc, "reading the agent's log", "Sys.Syslog") from exc
        try:   # an older Proxmox without the service filter: read the whole log and filter
            rows = api.nodes(node).syslog.get(since=_since(), limit=limit * 4) or []
        except Exception as exc2:  # noqa: BLE001
            raise _api_err(exc2, "reading the agent's log", "Sys.Syslog") from exc2
    except Exception as exc:  # noqa: BLE001
        raise _api_err(exc, "reading the agent's log", "Sys.Syslog") from exc
    out = []
    for r in rows:
        t = r.get("t", "") if isinstance(r, dict) else str(r)
        m = _LINE_RE.search(t)
        if m and m.group(1) == rid:
            out.append(m.group(2))
    return out


RESULT_RE = re.compile(r"^PMM-RESULT\s+(.*)$")


def parse_result(line: str) -> dict[str, str] | None:
    m = RESULT_RE.match(line)
    if not m:
        return None
    return dict(kv.split("=", 1) for kv in m.group(1).split() if "=" in kv)


PING_TIMEOUT = float(os.environ.get("PM_AGENT_PING_TIMEOUT", "45"))


def ping(api, node: str, timeout: float = PING_TIMEOUT) -> dict[str, Any]:
    rid = send(api, node, "ping")
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        time.sleep(2)
        for line in read(api, node, rid, limit=300):
            res = parse_result(line)
            if res and res.get("action") == "ping":
                return {"ok": True, "agent": int(res.get("agent", "0") or 0), "id": rid}
    _cleanup_request(api, node)
    raise AgentError(f"The update agent on {node} didn't answer within {int(timeout)} s. Is it installed and running "
                     f"there? (systemctl status pmm-agent)")


def _cleanup_request(api, node: str) -> None:
    """Remove unanswered request lines so they don't sit in the notes (they would expire anyway)."""
    try:
        cfg = api.nodes(node).config.get() or {}
        desc = cfg.get("description") or ""
        clean = re.sub(r"[ \t]*<!--\s*pmm-agent:v1\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\s*-->[ \t]*\n?", "", desc).rstrip()
        if clean != desc.rstrip():
            params = {"digest": cfg["digest"]} if cfg.get("digest") else {}
            if clean:
                api.nodes(node).config.put(description=clean, **params)
            else:
                api.nodes(node).config.put(delete="description", **params)
    except Exception:  # noqa: BLE001
        log.info("could not remove an unanswered agent request from %s's notes", node)


# --------------------------------------------------------------------------- #
# Which nodes have an agent (host.agent_json: {"node": {"version": 1, "seen_at": iso}})
# --------------------------------------------------------------------------- #

def agents_of(host) -> dict[str, dict]:
    try:
        d = json.loads(host.agent_json or "{}")
    except ValueError:
        return {}
    return d if isinstance(d, dict) else {}


def mark_seen(host_id: int, node: str, version: int) -> None:
    from datetime import datetime, timezone

    from .database import db_session
    from .models import ProxmoxHost

    with db_session() as db:
        h = db.get(ProxmoxHost, host_id)
        if h is None:
            return
        d = agents_of(h)
        d[node] = {"version": version, "seen_at": datetime.now(timezone.utc).isoformat()}
        h.agent_json = json.dumps(d)
