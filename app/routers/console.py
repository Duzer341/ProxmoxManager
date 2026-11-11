"""Console relay routes: create a console, its page, its websocket, and the log."""

import asyncio
import logging
import time
from datetime import timezone
from typing import Literal
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from .. import consoles, crypto, loginconfig, mfa, ratelimit, stepup
from .. import permissions as perms
from ..auth import (SESSION_AMR_KEY, SESSION_AT_KEY, SESSION_USER_KEY, logout_user, require_cap, require_same_origin,
                    require_user, session_id, sso_recheck_due)
from ..database import db_session, get_db
from ..models import ConsoleLog, ProxmoxHost, User
from ..pve import ConsoleAuthError, PveError, console_auth
from ..events import note
from ..templating import render

api = APIRouter(prefix="/api", dependencies=[Depends(require_same_origin)])
pages = APIRouter()
_log = logging.getLogger("app.console")
require_console = require_cap(perms.CONSOLE)


def _ip(request) -> str:
    return request.client.host if request.client else ""


def _iso(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _summary_guest(host: ProxmoxHost, node: str, vmid: int) -> dict:
    import json

    summary = json.loads(host.last_summary_json) if host.last_summary_json else {}
    for g in summary.get("guests") or []:
        try:
            if int(g.get("vmid")) == vmid:
                if g.get("node") != node:
                    raise HTTPException(409, f"Guest {vmid} is on node {g.get('node')} now, not {node}. Refresh the page.")
                if g.get("node_offline"):
                    raise HTTPException(409, f"Node {node} is offline, so guest {vmid} has no console until it is back.")
                return g
        except (TypeError, ValueError):
            continue
    raise HTTPException(404, f"Guest {vmid} is not in the last poll of this host. Refresh the host and try again.")


def _summary_node(host: ProxmoxHost, node: str) -> None:
    import json

    summary = json.loads(host.last_summary_json) if host.last_summary_json else {}
    n = next((n for n in summary.get("nodes") or [] if n.get("node") == node), None)
    if n is None:
        raise HTTPException(404, f"Node {node} is not in the last poll of this host.")
    if n.get("online") is False:
        raise HTTPException(409, f"Node {node} is offline.")


# --------------------------------------------------------------------------- #
# Console re-auth ("step-up"): see app/stepup.py
# --------------------------------------------------------------------------- #

def _require_stepup(request: Request, db: DbSession, user: User) -> str:
    """The browser sign-in id, if this browser has a valid re-auth window (used from the same
    address it was opened from); else StepUpRequired."""
    sid = session_id(request)
    if stepup.valid(user.id, sid, _ip(request)):
        return sid
    cfg = loginconfig.load(db)
    methods = stepup.methods_for(user, cfg)
    if not methods:
        raise stepup.StepUpRequired(stepup.blocked_reason(user, cfg), [])
    raise stepup.StepUpRequired("Verify it's you to open consoles: " + (
        "sign in with Microsoft again." if methods == ["entra"] else "enter a new code from your authenticator app."), methods)


def _stepup_method(user: User, sid: str) -> str:
    st = stepup.status(user.id, sid)
    return st["method"] if st else ""


def _stepup_public(request: Request, db: DbSession, user: User) -> dict:
    cfg = loginconfig.load(db)
    st = stepup.status(user.id, session_id(request), _ip(request))
    return {
        "active": bool(st),
        "remaining": st["remaining"] if st else 0,
        "method": st["method"] if st else "",
        "methods": stepup.methods_for(user, cfg),
        "blocked_reason": "" if stepup.methods_for(user, cfg) else stepup.blocked_reason(user, cfg),
        "window_minutes": round(stepup.window_seconds() / 60, 1),
    }


@api.get("/stepup")
def stepup_get(request: Request, db: DbSession = Depends(get_db), user: User = Depends(require_console)):
    return _stepup_public(request, db, user)


class StepUpIn(BaseModel):
    code: str = Field(default="", max_length=32)


@api.post("/stepup")
def stepup_verify(body: StepUpIn, request: Request, db: DbSession = Depends(get_db), user: User = Depends(require_console)):
    """Verify a fresh authenticator code and open the console window for this browser sign-in."""
    from fastapi.responses import JSONResponse

    cfg = loginconfig.load(db)
    if "totp" not in stepup.methods_for(user, cfg):
        if user.is_sso:
            raise HTTPException(400, "Microsoft accounts verify with a fresh Microsoft sign-in (/auth/entra/stepup).")
        raise HTTPException(400, stepup.blocked_reason(user, cfg))
    ip = _ip(request)
    sid = session_id(request)
    note(request, category="auth", action="stepup")
    if ratelimit.locked(user.username, ip, known_device=True):  # signed in: only per-address limits
        raise HTTPException(429, "Too many wrong codes. Wait a few minutes and try again.")
    u = db.get(User, user.id)
    code = body.code.strip()
    if mfa.looks_like_recovery(code):
        ok, why = False, "Backup codes can't be used for console access. Enter the current code from your authenticator app."
    elif mfa.verify_user_code(u, code):
        ok, why = True, ""
    elif mfa.replayed(u, code):
        ok, why = False, "That code was already used. Wait for the next code in your app."
    else:
        ok, why = False, "Wrong code. Check the time on your phone and try the current code."
    if ok:
        db.commit()
        until = stepup.grant(user.id, sid, "totp", ip)
        ratelimit.success(user.username, ip)
        _log.info("console re-auth ok user=%s method=totp ip=%s", user.username, ip)
        note(request, outcome="ok", details={"method": "totp", "window_minutes": round(stepup.window_seconds() / 60, 1)})
        return {**_stepup_public(request, db, user), "until": until}
    ratelimit.failure(user.username, ip)
    n = stepup.failure(user.id, sid)
    _log.warning("console re-auth failed user=%s ip=%s attempt=%d", user.username, ip, n)
    note(request, outcome="failed", details={"method": "totp", "attempt": n, "reason": (
        "backup code refused" if mfa.looks_like_recovery(code) else "reused code" if "already used" in why else "wrong code")})
    if n >= stepup.MAX_FAILS:
        logout_user(request)
        note(request, details={"signed_out": "too many wrong console re-auth codes"})
        return JSONResponse({"detail": "Too many wrong codes. You have been signed out.", "signed_out": True}, status_code=401)
    raise HTTPException(400, why)


@api.post("/stepup/drop")
def stepup_drop(request: Request, user: User = Depends(require_user)):
    """End this browser's console window now."""
    dropped = stepup.drop(user.id, session_id(request))
    note(request, category="auth", action="stepup.drop", details={"had_window": dropped})
    return {"ok": True, "active": False}


class ConsoleIn(BaseModel):
    kind: Literal["vm", "ct", "shell", "upgrade"]
    node: str = Field(min_length=1, max_length=63, pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")
    vmid: int | None = None
    password: str = Field(default="", max_length=512)
    remember: bool = False


def _password_source(host: ProxmoxHost) -> str:
    if host.auth_type == "password" and host.pve_user.strip().lower() == "root@pam":
        return "host"
    return "saved" if host.console_secret_enc else ""


@api.post("/hosts/{host_id}/consoles", status_code=201)
async def console_create(host_id: int, body: ConsoleIn, request: Request, db: DbSession = Depends(get_db),
                         user: User = Depends(require_console)):
    """Sign in to the host as root@pam (server-side) and prepare a relayed console."""
    sid = _require_stepup(request, db, user)
    host = db.get(ProxmoxHost, host_id)
    if host is None:
        raise HTTPException(404, "Host not found")
    name = ""
    if body.kind in ("vm", "ct"):
        if body.vmid is None:
            raise HTTPException(400, "vmid is required for a guest console")
        g = _summary_guest(host, body.node, body.vmid)
        if g.get("template"):
            raise HTTPException(400, "Templates have no console.")
        if (g.get("type") == "qemu") != (body.kind == "vm"):
            raise HTTPException(400, "Console type doesn't match the guest type.")
        if body.kind == "ct" and g.get("status") != "running":
            raise HTTPException(400, "Start the container first; a stopped container has no console.")
        name = g.get("name", "")
    else:
        _summary_node(host, body.node)

    # VM consoles on a host switched to an API token use the token (no root password),
    # unless a password was typed or the token was refused for a console recently.
    use_token = body.kind == "vm" and not body.password and consoles.token_vm_consoles(host)
    reused = None if (body.password or use_token) else consoles.reuse_ticket(user.id, host.id)
    source = ""
    if use_token:
        ticket, csrf, source = "", "", "api token"
    elif reused:
        ticket, csrf = reused
    else:
        source = _password_source(host)
        if body.password:
            password, source = body.password, "typed"
        elif source == "host":
            password = crypto.decrypt(host.secret_enc)
        elif source == "saved":
            password = crypto.decrypt(host.console_secret_enc)
        else:
            raise HTTPException(409, "Enter the root@pam password for this host.")
        try:
            ticket, csrf = await asyncio.to_thread(console_auth, host, password)
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
    s = await asyncio.to_thread(consoles.create, user, host, body.node, body.vmid if body.kind in ("vm", "ct") else None,
                                body.kind, name, _ip(request), ticket, csrf, sid, _stepup_method(user, sid),
                                request.session.get(SESSION_AT_KEY, 0), "token" if use_token else "ticket")
    note(request, action="console.open", node=body.node, vmid=body.vmid,
         details={"kind": body.kind, "label": s.label, "log_id": s.log_id, "stepup": s.stepup_method,
                  "root_login": source or "saved", "remembered": bool(source == "typed" and body.remember)} if not reused else
         {"kind": body.kind, "label": s.label, "log_id": s.log_id, "stepup": s.stepup_method, "root_login": "reused ticket"})
    return {"id": s.id, "url": f"/console/{s.id}", "label": s.label, "saved": bool(host.console_secret_enc)}


def _own(sid: str, user: User) -> consoles.Session:
    s = consoles.get(sid)
    if s is None or s.user_id != user.id:
        raise HTTPException(404, "This console has ended or doesn't exist. Open it again from the host page.")
    return s


@api.post("/consoles/{sid}/start")
async def console_start(sid: str, request: Request, db: DbSession = Depends(get_db), user: User = Depends(require_console)):
    s = _own(sid, user)
    note(request, action="console.start", node=s.node, vmid=s.vmid, details={"log_id": s.log_id})
    _require_stepup(request, db, user)
    host = db.get(ProxmoxHost, s.host_id)
    if host is None:
        raise HTTPException(404, "Host not found")
    try:
        return await asyncio.to_thread(consoles.start, s, host)
    except consoles.TicketRejected:
        pass
    except consoles.ConsoleError as exc:
        raise HTTPException(502, str(exc)) from exc
    # Proxmox rejected the root@pam ticket (expired, or a cluster node that doesn't accept it).
    # Never reuse it; sign in again once with the stored password and retry, else explain.
    consoles.drop_ticket(s.pve_ticket)
    source = _password_source(host)
    retried = False
    if source:
        try:
            password = crypto.decrypt(host.secret_enc if source == "host" else host.console_secret_enc)
            ticket, csrf = await asyncio.to_thread(console_auth, host, password)
        except (ConsoleAuthError, PveError, ValueError) as exc:
            if isinstance(exc, ConsoleAuthError) and source == "saved":
                host.console_secret_enc = ""     # same as opening a console: a rejected saved password is removed
                db.commit()
            note(request, details={"ticket_rejected": True, "renew_failed": str(exc)[:120]})
        else:
            consoles.renew_ticket(s, ticket, csrf)
            retried = True
            try:
                r = await asyncio.to_thread(consoles.start, s, host)
                note(request, details={"ticket_rejected": True, "renewed": True})
                return r
            except consoles.TicketRejected:
                consoles.drop_ticket(ticket)
            except consoles.ConsoleError as exc:
                raise HTTPException(502, str(exc)) from exc
    msg = await asyncio.to_thread(consoles.ticket_rejected_message, host, s.node, retried)
    note(request, details={"ticket_rejected": True, "renewed": False, "reason": msg[:200]})
    raise HTTPException(502, msg)


@api.post("/consoles/{sid}/reconnect", status_code=201)
async def console_reconnect(sid: str, request: Request, db: DbSession = Depends(get_db), user: User = Depends(require_console)):
    """A fresh console for the same target, reusing the root@pam ticket while it is recent.
    Needs a valid re-auth window like opening a console from the host page."""
    old = _own(sid, user)
    browser_sid = _require_stepup(request, db, user)
    if old.connected and not old.finished:
        raise HTTPException(409, "This console is still open. Close it first; Reconnect is for a console that has ended.")
    host = db.get(ProxmoxHost, old.host_id)
    if host is not None and old.auth == "token" and consoles.token_vm_consoles(host):
        reused, auth = ("", ""), "token"
    else:
        reused, auth = consoles.reuse_ticket(user.id, old.host_id), "ticket"
    if host is None or reused is None:
        raise HTTPException(409, "The sign-in to the host has expired. Open the console again from the host page.")
    s = await asyncio.to_thread(consoles.create, user, host, old.node, old.vmid, old.kind, old.name, _ip(request), *reused,
                                browser_sid, _stepup_method(user, browser_sid), request.session.get(SESSION_AT_KEY, 0), auth)
    consoles.forget(old.id)
    note(request, action="console.reconnect", host_name=host.name, node=old.node, vmid=old.vmid,
         details={"kind": old.kind, "label": s.label, "log_id": s.log_id, "previous_log_id": old.log_id, "stepup": s.stepup_method})
    return {"id": s.id, "url": f"/console/{s.id}"}


@api.get("/consoles/{sid}/status")
def console_status(sid: str, user: User = Depends(require_console)):
    """Countdowns for the console page (idle close, time limit)."""
    return consoles.public_status(_own(sid, user))


@api.post("/consoles/{sid}/keepalive")
def console_keepalive(sid: str, request: Request, user: User = Depends(require_console)):
    """ "Stay connected": counts as activity for the idle close (not for the time limit)."""
    s = _own(sid, user)
    consoles.keepalive(s)
    note(request, action="console.keepalive", node=s.node, vmid=s.vmid, details={"log_id": s.log_id})
    return consoles.public_status(s)


PASTE_MAX_CHARS = 5000


class PasteIn(BaseModel):
    chars: int = Field(ge=1, le=PASTE_MAX_CHARS)
    lines: int = Field(default=0, ge=0, le=PASTE_MAX_CHARS)
    skipped: int = Field(default=0, ge=0, le=PASTE_MAX_CHARS)


@api.post("/consoles/{sid}/paste")
def console_paste(sid: str, body: PasteIn, request: Request, user: User = Depends(require_console)):
    """Paste as keystrokes on a VM console. The browser types the text through the open VNC
    connection; this records who typed how much into which VM (never the text, it is often a password)
    and is asked before typing starts, so nothing is typed into a console that has ended."""
    s = _own(sid, user)
    if s.kind != "vm":
        raise HTTPException(400, "Paste as keystrokes is for VM consoles. Terminals take a normal paste (Ctrl+Shift+V).")
    if s.finished or not s.connected:
        raise HTTPException(409, "This console isn't connected.")
    note(request, action="console.paste", node=s.node, vmid=s.vmid,
         details={"log_id": s.log_id, "characters": body.chars, "lines": body.lines,
                  **({"skipped_characters": body.skipped} if body.skipped else {}), "text": "not recorded"})
    _log.info("console paste id=%s user=%s vmid=%s chars=%d", s.log_id, user.username, s.vmid, body.chars)
    return {"ok": True}


@api.get("/hosts/{host_id}/consoles")
def console_log(host_id: int, db: DbSession = Depends(get_db), user: User = Depends(require_console)):
    rows = (db.query(ConsoleLog).filter(ConsoleLog.host_id == host_id)
            .order_by(ConsoleLog.created_at.desc()).limit(25).all())
    return [{"id": r.id, "username": r.username, "node": r.node, "vmid": r.vmid, "kind": r.kind, "label": r.label,
             "client_ip": r.client_ip, "created_at": _iso(r.created_at), "connected_at": _iso(r.connected_at),
             "ended_at": _iso(r.ended_at), "end_reason": r.end_reason, "bytes_to_host": r.bytes_to_host,
             "bytes_from_host": r.bytes_from_host, "stepup": r.stepup_method or ""} for r in rows]


@pages.get("/console/{sid}")
def console_page(sid: str, request: Request, user: User = Depends(require_console)):
    s = consoles.get(sid)
    if s is None or s.user_id != user.id:
        raise HTTPException(404, "This console has ended or doesn't exist. Open it again from the host page.")
    return render(request, "console.html", {"page": "console", "sid": s.id, "kind": s.kind, "label": consoles.page_title(s),
                                            "xterm": s.kind != "vm", "paste_max": PASTE_MAX_CHARS})


def _ws_user(ws: WebSocket) -> User | None:
    """Same checks as the HTTP pages: signed in, active, allowed consoles, allowed by the login
    mode, and a valid console re-auth window for this browser sign-in."""
    session = ws.scope.get("session") or {}
    uid = session.get(SESSION_USER_KEY)
    if not uid:
        return None
    with db_session() as db:
        user = db.get(User, uid)
        if user is None or not user.is_active or not user.can(perms.CONSOLE):
            return None
        if not stepup.valid(user.id, session.get(stepup.SESSION_SID_KEY, ""), ws.client.host if ws.client else ""):
            return None
        from .. import sessions

        sid = session.get(stepup.SESSION_SID_KEY, "")
        if not sid or sessions.is_revoked(sid) or session.get("uk") != user.session_key:
            return None
        cfg = loginconfig.load(db)
        amr = session.get(SESSION_AMR_KEY, "pwd")
        if (cfg.mfa_required(user) and amr == "pwd") or (user.is_sso and not cfg.sso_enabled):
            return None
        if user.is_sso and sso_recheck_due(session.get(SESSION_AT_KEY)):
            return None   # an aged Microsoft sign-in goes back through Microsoft first
        db.expunge(user)
        return user


@pages.websocket("/console/{sid}/ws")
async def console_ws(ws: WebSocket, sid: str):
    actx = (ws.scope.get("state") or {}).get("audit")
    actx = actx if isinstance(actx, dict) else {}

    async def refuse(why: str):
        actx.update(action="console.ws", details={"reason": why})
        await ws.close(code=1008)

    origin = ws.headers.get("origin", "")
    if not origin or urlparse(origin).netloc != ws.headers.get("host", ""):
        return await refuse("cross-site websocket (Origin doesn't match)")
    user = await asyncio.to_thread(_ws_user, ws)
    s = consoles.get(sid)
    if user is None:
        return await refuse("not signed in, not allowed consoles, or no valid console re-auth")
    actx["user_ident"] = (user.id, user.username, user.role)
    if s is None or s.user_id != user.id:
        return await refuse("unknown console or someone else's console")
    if s.browser_sid and (ws.scope.get("session") or {}).get(stepup.SESSION_SID_KEY, "") != s.browser_sid:
        return await refuse("console belongs to another browser sign-in")
    if s.connected or s.finished:
        return await refuse("console already used")
    if not s.started or time.time() - s.started > consoles.START_TO_CONNECT_SECONDS:
        return await refuse("console not started, or connected too late after start")
    actx["vmid"], actx["node"] = s.vmid, s.node
    with db_session() as db:
        host = db.get(ProxmoxHost, s.host_id)
        if host is None:
            await ws.close(code=1008)
            return
        db.expunge(host)
    await ws.accept(subprotocol="binary" if "binary" in (ws.scope.get("subprotocols") or []) else None)
    await consoles.relay(ws, s, host)
