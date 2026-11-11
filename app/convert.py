"""Switch a host from root@pam password to a dedicated API token.

One admin action, run over the Proxmox API with the host's stored root@pam password:

  1. role  PMM      created (or its privileges set) with only what the dashboard uses
  2. user  pmm@pve  created in the Proxmox VE realm with a long random password that is set and then
                    discarded (never shown, never stored): the account can't sign in to the web UI,
                    only its token works
  3. ACL   /  ->  PMM for pmm@pve (propagated)
  4. token pmm@pve!pmm-<timestamp>, privilege separation off (the token has the user's permissions)
  5. check the token sees the same nodes and guests as root@pam and holds every PMM privilege
  6. only then the host entry switches to the token; the stored root@pam password is removed

If any step fails, everything created in this run is removed again (role privileges put back) and
the host entry is not changed. Users, roles and ACLs live in the cluster-wide /etc/pve, so one run
covers every node of a cluster.
"""

from __future__ import annotations

import logging
import secrets
import threading
from datetime import datetime, timezone
from typing import Any

from proxmoxer import ProxmoxAPI
from proxmoxer.core import ResourceException

from . import crypto, tlspin
from .config import settings
from .database import db_session
from .models import ProxmoxHost
from .pve import PveError, _describe, connect

log = logging.getLogger(__name__)

PMM_USER = "pmm@pve"
PMM_ROLE = "PMM"
# Matched to the Proxmox calls the dashboard makes (see README "Switch to API token").
PMM_PRIVS = [
    "Sys.Audit",                # nodes, versions, cluster status, network / DNS, disks / SMART, apt, repos, tasks
    "Sys.Modify",               # apt update (Refresh package list), changelogs, Switch to no-subscription
    "Sys.PowerMgmt",            # Reboot node (API)
    "VM.Audit",                 # guests and their config
    "VM.PowerMgmt",             # start / stop / shutdown / reboot
    "VM.Snapshot",              # snapshots
    "VM.Backup",                # backups
    "VM.Config.Disk",           # expand disk
    "VM.Config.Options",        # start at boot
    "VM.Console",               # VM consoles on the token
    "Datastore.Audit",          # storage list / usage, backup targets
    "Datastore.AllocateSpace",  # backups and disk expansion write to storage
    "Sys.Syslog",               # read the update agent's output from the node's journal
]
COMMENT = "Proxmox Manager dashboard (API token only, no web sign-in)"

_running: set[int] = set()
_run_lock = threading.Lock()


class ConvertError(Exception):
    def __init__(self, message: str, steps: list[dict] | None = None):
        super().__init__(message)
        self.steps = steps or []


def _err(exc: Exception) -> str:
    if isinstance(exc, ResourceException):
        return f"HTTP {exc.status_code} {exc.status_message}: {str(exc.content or exc.errors or '')[:200]}".strip()
    if isinstance(exc, PveError):
        return str(exc)
    return _describe(exc)


def _user_exists(api: ProxmoxAPI, userid: str) -> bool:
    try:
        api.access.users(userid).get()
        return True
    except ResourceException as exc:
        text = f"{exc.status_message} {exc.content}".lower()
        if exc.status_code in (404, 500) and ("no such user" in text or "does not exist" in text or exc.status_code == 404):
            return False
        raise


def _privs_of(api: ProxmoxAPI, roleid: str) -> list[str] | None:
    for r in api.access.roles.get() or []:
        if r.get("roleid") == roleid:
            p = r.get("privs") or ""
            if isinstance(p, dict):
                return sorted(k for k, v in p.items() if v)
            return sorted(x for x in str(p).replace(" ", ",").split(",") if x)
    return None


def _inventory(api: ProxmoxAPI) -> tuple[list[str], list[int]]:
    nodes = sorted(str(n.get("node")) for n in (api.nodes.get() or []) if n.get("node"))
    vmids = sorted(int(r["vmid"]) for r in (api.cluster.resources.get(type="vm") or []) if str(r.get("vmid", "")).isdigit())
    return nodes, vmids


def _token_api(host: ProxmoxHost, token_name: str, value: str) -> ProxmoxAPI:
    return ProxmoxAPI(host=host.host, port=host.port, user=PMM_USER, token_name=token_name, token_value=value,
                      verify_ssl=host.verify_ssl, timeout=settings.PVE_TIMEOUT)


def convert(host_id: int, root_password: str = "", remove_old_token: bool = True) -> dict[str, Any]:
    """Run the switch for one host. Returns a summary (no secrets); raises ConvertError.
    also for hosts on a root@pam API token (the old root token is removed from the host afterwards
    unless remove_old_token is off). root_password (typed, never stored) signs in as root@pam instead of the
    stored credential, e.g. when Proxmox doesn't let the root token create users or tokens."""
    with _run_lock:
        if host_id in _running:
            raise ConvertError("A switch for this host is already running.")
        _running.add(host_id)
    try:
        return _convert(host_id, root_password, remove_old_token)
    finally:
        with _run_lock:
            _running.discard(host_id)


def _convert(host_id: int, root_password: str = "", remove_old_token: bool = True) -> dict[str, Any]:
    steps: list[dict] = []

    def step(name: str, ok: bool = True, detail: str = "") -> None:
        steps.append({"step": name, "ok": ok, "detail": detail})

    with db_session() as db:
        host = db.get(ProxmoxHost, host_id)
        if host is None:
            raise ConvertError("Host not found.")
        if host.pve_user.strip().lower() != "root@pam" or host.auth_type not in ("password", "token"):
            raise ConvertError("Only hosts signed in as root@pam (password or root@pam API token) can be switched.")
        if not host.enabled:
            raise ConvertError("Enable polling for this host first.")
        db.expunge(host)

    old_token = host.token_name if host.auth_type == "token" else ""
    try:
        if root_password:
            # a typed root@pam password (not stored): same address and pinned certificate as the host entry
            via = ProxmoxHost(name=host.name, host=host.host, port=host.port, verify_ssl=host.verify_ssl,
                              tls_fingerprint=host.tls_fingerprint, auth_type="password", pve_user="root@pam",
                              token_name="", secret_enc="")
            root = connect(via, secret=root_password)
            how = "root@pam password (typed)"
        else:
            root = connect(host)   # pins / checks the TLS certificate first (tlspin), like every poll
            how = f"root@pam token {host.pve_user}!{old_token}" if old_token else "stored root@pam password"
        root_nodes, root_vmids = _inventory(root)
        version = (root.version.get() or {}).get("version", "")
    except Exception as exc:  # noqa: BLE001
        raise ConvertError(f"Could not sign in to {host.name} as root@pam: {_err(exc)}") from exc
    step("Signed in as root@pam", detail=f"via the {how}; PVE {version}, {len(root_nodes)} node(s), {len(root_vmids)} guest(s)")

    created_role = created_user = False
    old_role_privs: list[str] | None = None
    token_name = ""
    try:
        # 1. role
        old_role_privs = _privs_of(root, PMM_ROLE)
        if old_role_privs is None:
            root.access.roles.post(roleid=PMM_ROLE, privs=",".join(PMM_PRIVS))
            created_role = True
            step(f"Created role {PMM_ROLE}", detail=", ".join(PMM_PRIVS))
        elif sorted(old_role_privs) != sorted(PMM_PRIVS):
            root.access.roles(PMM_ROLE).put(privs=",".join(PMM_PRIVS))
            step(f"Updated role {PMM_ROLE}", detail="privileges set to: " + ", ".join(PMM_PRIVS))
        else:
            step(f"Role {PMM_ROLE} already up to date")

        # 2. user (a long random password, set and discarded; an existing user is reused as is)
        if _user_exists(root, PMM_USER):
            step(f"User {PMM_USER} already exists (reused, password not changed)")
        else:
            root.access.users.post(userid=PMM_USER, password=secrets.token_urlsafe(48), comment=COMMENT, enable=1)
            created_user = True
            step(f"Created user {PMM_USER}", detail="random 64-character password, not shown or stored")

        # 3. permissions
        root.access.acl.put(path="/", roles=PMM_ROLE, users=PMM_USER, propagate=1)
        step(f"Granted {PMM_ROLE} on / to {PMM_USER}", detail="propagated to all nodes, guests and storage")

        # 4. token
        # timestamp + 4 random hex: two switches in the same second (two hosts of one cluster) can't collide
        token_name = "pmm-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)
        res = root.access.users(PMM_USER).token(token_name).post(privsep=0, comment=COMMENT) or {}
        value = res.get("value") or ""
        if not value:
            raise ConvertError("Proxmox did not return the token's secret.")
        step(f"Created API token {PMM_USER}!{token_name}", detail="privilege separation off (token = user's permissions)")

        # 5. check the token before anything changes in the dashboard
        tok = _token_api(host, token_name, value)
        tok_nodes, tok_vmids = _inventory(tok)
        if tok_nodes != root_nodes or tok_vmids != root_vmids:
            missing = sorted(set(root_nodes) - set(tok_nodes)) + [str(v) for v in sorted(set(root_vmids) - set(tok_vmids))]
            raise ConvertError("The token doesn't see everything root@pam sees (missing: " + ", ".join(missing)[:200] + ").")
        perms_root = (tok.access.permissions.get(path="/") or {}).get("/") or {}
        lacking = [p for p in PMM_PRIVS if not perms_root.get(p)]
        if lacking:
            raise ConvertError("The token is missing privileges on /: " + ", ".join(lacking))
        step("Checked the token", detail=f"sees {len(tok_nodes)} node(s) and {len(tok_vmids)} guest(s); all {len(PMM_PRIVS)} privileges on /")
    except Exception as exc:  # noqa: BLE001
        msg = str(exc) if isinstance(exc, ConvertError) else _err(exc)
        if old_token and not root_password and isinstance(exc, ResourceException) and exc.status_code in (403, 500) \
                and "token" in msg.lower():
            msg += (" Proxmox may not let an API token create users or tokens: run the switch again with the root@pam "
                    "password (typed in the dialog, not stored).")
        step("Failed", ok=False, detail=msg)
        _rollback(root, token_name, created_user, created_role, old_role_privs, step)
        raise ConvertError(msg, steps) from exc

    # 6. switch the host entry (only now)
    with db_session() as db:
        h = db.get(ProxmoxHost, host_id)
        h.auth_type = "token"
        h.pve_user = PMM_USER
        h.token_name = token_name
        h.secret_enc = crypto.encrypt(value)
        h.console_secret_enc = ""          # no root password kept for consoles (typed when needed)
        h.last_error = ""
    step("Switched the dashboard to the token",
         detail=f"stored root@pam {'token' if old_token else 'password'} removed from the dashboard")

    # 7. the old full-root token still works on the host until it is removed there
    old_token_removed = False
    if old_token:
        if remove_old_token:
            try:
                root.access.users("root@pam").token(old_token).delete()
                old_token_removed = True
                step(f"Removed the old token root@pam!{old_token} from the host")
            except Exception as exc:  # noqa: BLE001
                step(f"Could not remove the old token root@pam!{old_token}", ok=False,
                     detail=_err(exc) + f" - remove it by hand: pveum user token remove root@pam {old_token}")
        else:
            step(f"Old token root@pam!{old_token} left on the host (as asked)", ok=False,
                 detail=f"it still has full root access: pveum user token remove root@pam {old_token}")
    log.info("host %s switched to API token %s!%s", host.name, PMM_USER, token_name)
    return {"host": host.name, "user": PMM_USER, "role": PMM_ROLE, "privs": PMM_PRIVS, "token_id": f"{PMM_USER}!{token_name}",
            "nodes": root_nodes, "guests": len(root_vmids), "created_user": created_user, "created_role": created_role,
            "pve_version": version, "steps": steps, "old_token": f"root@pam!{old_token}" if old_token else "",
            "old_token_removed": old_token_removed}


def _rollback(root: ProxmoxAPI, token_name: str, created_user: bool, created_role: bool,
              old_role_privs: list[str] | None, step) -> None:
    """Undo what this run created. Errors are recorded, not raised."""
    def attempt(name: str, fn) -> None:
        try:
            fn()
            step(name)
        except Exception as exc:  # noqa: BLE001
            step(name.replace("Rolled back:", "Could not roll back:"), ok=False,
                 detail=_err(exc) + " - remove it by hand in Datacenter > Permissions")

    if token_name and not created_user:
        attempt(f"Rolled back: deleted token {PMM_USER}!{token_name}", lambda: root.access.users(PMM_USER).token(token_name).delete())
    if created_user:
        # deleting the user also removes its tokens and its ACL entries
        attempt(f"Rolled back: deleted user {PMM_USER}", lambda: root.access.users(PMM_USER).delete())
    if created_role:
        attempt(f"Rolled back: deleted role {PMM_ROLE}", lambda: root.access.roles(PMM_ROLE).delete())
    elif old_role_privs is not None and sorted(old_role_privs) != sorted(PMM_PRIVS):
        attempt(f"Rolled back: role {PMM_ROLE} privileges restored",
                lambda: root.access.roles(PMM_ROLE).put(privs=",".join(old_role_privs)))
