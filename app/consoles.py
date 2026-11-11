"""Console relay.

Consoles run through the dashboard instead of the browser talking to each Proxmox host:

    browser  --wss 443-->  dashboard /console/<id>/ws  --wss 8006-->  host .../vncwebsocket

1. An admin asks for a console (POST /api/hosts/{id}/consoles). The dashboard signs in to the
   host as root@pam (saved, host or typed password) and keeps the ticket server-side.
2. The console page calls /api/consoles/<id>/start right before connecting. The dashboard asks
   Proxmox for a one-off console port: vncproxy (VMs, noVNC) or termproxy (containers, node
   shell, upgrade shell, xterm.js). Proxmox only waits a few seconds for the connection.
3. The page opens its websocket to the dashboard, which opens the matching websocket to the
   host with the root@pam cookie and relays bytes both ways until either side closes.

For xterm.js consoles the dashboard does the termproxy handshake itself ("user:ticket\\n" ->
"OK"), so the browser never sees a Proxmox ticket. For VNC the browser needs the one-off VNC
password Proxmox returns (it only works on that console port, which only the dashboard can
reach). Every session is written to the console_log table and the event log.

Opening a console needs a fresh re-auth (app/stepup.py). A session closes after
PM_CONSOLE_IDLE_MINUTES without activity (terminals: keystrokes or output, so a running upgrade
stays open; VMs: keyboard / mouse input) and after PM_CONSOLE_MAX_SECONDS at the latest. The
console page polls /status for the countdowns and can send a keep-alive ("Stay connected").
"""

import asyncio
import re
import logging
import secrets
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import quote, urlencode

import requests
from starlette.websockets import WebSocket, WebSocketDisconnect

from . import events, tlspin
from .config import settings
from .database import db_session
from .models import node_names_of
from .models import ConsoleLog, ProxmoxHost

log = logging.getLogger("app.console")

KINDS = ("vm", "ct", "shell", "upgrade")
TICKET_REUSE_SECONDS = 90 * 60     # root@pam tickets are valid for 2 hours
START_TO_CONNECT_SECONDS = 20      # Proxmox closes an unused console port after ~10 s
RECONNECT_SECONDS = 30 * 60        # an ended console can be reconnected from its tab this long
HTTP_TIMEOUT = 20


class ConsoleError(Exception):
    """Message is safe to show to the user."""


class TicketRejected(ConsoleError):
    """Proxmox answered 401 to the root@pam ticket (expired, or not accepted by that cluster node)."""


@dataclass
class Session:
    id: str
    user_id: int
    username: str
    host_id: int
    node: str
    vmid: int | None
    kind: str
    label: str
    client_ip: str
    pve_ticket: str
    csrf: str
    ticket_ts: float
    log_id: int
    name: str = ""
    created: float = field(default_factory=time.time)
    started: float = 0.0
    port: str = ""
    vncticket: str = ""
    pve_user: str = ""
    connected: bool = False
    finished: bool = False
    finished_at: float = 0.0
    browser_sid: str = ""          # the browser sign-in this console belongs to (re-auth window)
    stepup_method: str = ""        # how that re-auth was done: totp | entra
    host_name: str = ""
    node_label: str = ""           # the node's friendly name from the host settings
    signin_at: float = 0.0         # when the browser sign-in happened (Microsoft re-check)
    role: str = ""
    user_key: str = ""             # the user's session key at creation; a change (signed out everywhere) ends the console
    connected_at: float = 0.0      # wall clock (logs)
    last_activity: float = 0.0     # monotonic
    deadline: float = 0.0          # monotonic hard cap (connect + PM_CONSOLE_MAX_SECONDS)
    end_reason: str = ""
    kick: str = ""                 # set to end the session from outside (e.g. the user was disabled)
    auth: str = "ticket"           # "ticket" (root@pam sign-in) or "token" (VM console on the host's API token)


_lock = threading.Lock()
_sessions: dict[str, Session] = {}


def label_for(kind: str, node: str, vmid: int | None, name: str = "") -> str:
    if kind == "vm":
        return f"Console VM {vmid}" + (f" ({name})" if name else "")
    if kind == "ct":
        return f"Console CT {vmid}" + (f" ({name})" if name else "")
    if kind == "shell":
        return f"Terminal on {node}"
    return f"Upgrade shell on {node}"


def page_title(s: "Session") -> str:
    """Console tab / bar title: the label, the node for guest consoles, the node's
    friendly name and the host's name, e.g. 'Terminal on pve1 (Branch office)',
    'Terminal on pve1 (Main server) · Branch office', 'Console VM 102 (DC1) on pve1 (Branch office)'."""
    title = s.label
    if s.kind in ("vm", "ct") and s.node:
        title += f" on {s.node}"
    nl = (s.node_label or "").strip()
    hn = (s.host_name or "").strip()
    same = {(s.node or "").lower(), nl.lower()}
    if nl and nl.lower() != (s.node or "").lower():
        title += f" ({nl})"
        if hn and hn.lower() not in same:
            title += f" · {hn}"
    elif hn and hn.lower() not in same:
        title += f" ({hn})"
    return title


def _cleanup() -> None:
    now = time.time()
    with _lock:
        stale = [k for k, s in _sessions.items()
                 if (s.finished and now - s.finished_at > RECONNECT_SECONDS)
                 or (not s.connected and not s.finished and now - s.created > settings.CONSOLE_CONNECT_SECONDS)]
        gone = [_sessions.pop(sid) for sid in stale]
    for s in gone:
        if not s.finished:
            s.finished, s.finished_at = True, now
            _end_log(s.log_id, "page never connected")
            _event_end(s, "page never connected", 0, 0)


def idle_seconds() -> float:
    return max(10.0, settings.CONSOLE_IDLE_MINUTES * 60)


def create(user, host: ProxmoxHost, node: str, vmid: int | None, kind: str, name: str, client_ip: str,
           ticket: str, csrf: str, browser_sid: str = "", stepup_method: str = "", signin_at: float = 0.0,
           auth: str = "ticket") -> Session:
    _cleanup()
    label = label_for(kind, node, vmid, name)
    with db_session() as db:
        row = ConsoleLog(user_id=user.id, username=user.username, host_id=host.id, host_name=host.name, node=node,
                         vmid=vmid, kind=kind, label=label, client_ip=client_ip or "", stepup_method=stepup_method or "")
        db.add(row)
        db.flush()
        log_id = row.id
    # A reused ticket keeps the time it was issued (Proxmox tickets live 2 hours), so reuse can't
    # stretch it past that.
    with _lock:
        issued = min((x.ticket_ts for x in _sessions.values() if ticket and x.pve_ticket == ticket and x.ticket_ts > 0),
                     default=time.time() if ticket else 0.0)
    s = Session(id=secrets.token_urlsafe(24), user_id=user.id, username=user.username, host_id=host.id, node=node,
                vmid=vmid, kind=kind, label=label, client_ip=client_ip or "", pve_ticket=ticket, csrf=csrf,
                ticket_ts=issued, log_id=log_id, name=name or "", browser_sid=browser_sid or "",
                stepup_method=stepup_method or "", host_name=host.name, role=user.role, user_key=user.session_key or "",
                node_label=node_names_of(host).get(node, ""), signin_at=float(signin_at or 0), auth=auth)
    with _lock:
        _sessions[s.id] = s
    log.info("console requested id=%d user=%s host=%s %s ip=%s", log_id, user.username, host.name, label, client_ip)
    return s


def reuse_ticket(user_id: int, host_id: int) -> tuple[str, str] | None:
    """A recent root@pam ticket this user already obtained for this host (for Reconnect)."""
    now = time.time()
    with _lock:
        best = None
        for s in _sessions.values():
            if s.user_id == user_id and s.host_id == host_id and s.pve_ticket and now - s.ticket_ts < TICKET_REUSE_SECONDS:
                if best is None or s.ticket_ts > best.ticket_ts:
                    best = s
        return (best.pve_ticket, best.csrf) if best else None


# --------------------------------------------------------------------------- #
# VM consoles on the host's API token (hosts switched to a pmm@pve token)
# --------------------------------------------------------------------------- #

TOKEN_BLOCK_SECONDS = 3600
_token_blocked: dict[int, tuple[float, str]] = {}


def token_vm_consoles(host: ProxmoxHost) -> bool:
    """VM consoles can use the host's API token: token auth, and the token wasn't refused for a
    console in the last hour (then the root password is asked for, as before)."""
    if host.auth_type != "token" or not host.secret_enc:
        return False
    with _lock:
        hit = _token_blocked.get(host.id)
    return not (hit and time.time() - hit[0] < TOKEN_BLOCK_SECONDS)


def block_token(host_id: int, why: str) -> None:
    with _lock:
        _token_blocked[host_id] = (time.time(), why)


def unblock_token(host_id: int) -> None:
    with _lock:
        _token_blocked.pop(host_id, None)


def _token_header(host: ProxmoxHost) -> str:
    from . import crypto

    return f"PVEAPIToken={host.pve_user}!{host.token_name}={crypto.decrypt(host.secret_enc)}"


def drop_ticket(ticket: str) -> None:
    """Never reuse a root@pam ticket Proxmox has rejected (Reconnect / opening another console)."""
    with _lock:
        for s in _sessions.values():
            if s.pve_ticket == ticket:
                s.ticket_ts = 0.0


def renew_ticket(s: Session, ticket: str, csrf: str) -> None:
    s.pve_ticket, s.csrf, s.ticket_ts = ticket, csrf, time.time()


def _fmt_secs(sec: int) -> str:
    sec = abs(int(sec))
    if sec >= 3600:
        return f"{sec // 3600} h {sec % 3600 // 60} min"
    if sec >= 60:
        return f"{sec // 60} min {sec % 60} s"
    return f"{sec} s"


def ticket_rejected_message(host: ProxmoxHost, node: str, retried: bool) -> str:
    """Explain a 401 from Proxmox for this node, checking the clocks live."""
    from .pve import clock_check

    try:
        c = clock_check(host, node)
    except Exception:  # noqa: BLE001
        c = {"entry": "", "node_offset": None, "entry_offset": None}
    entry = c.get("entry") or ""
    no, eo = c.get("node_offset"), c.get("entry_offset")
    if entry and entry != node and no is not None and eo is not None and abs(no - eo) >= 240:
        d = no - eo
        return (f"{node} refused the root@pam sign-in issued by {entry}: {node}'s clock is {_fmt_secs(d)} "
                f"{'ahead of' if d > 0 else 'behind'} {entry}'s. Proxmox only accepts a sign-in from another cluster "
                f"node when the clocks agree within 5 minutes. Fix time sync on {node} (chronyc tracking / "
                f"timedatectl), then open the console again.")
    clock = ""
    if no is not None and abs(no) >= 240:
        clock = f" {node}'s clock is {_fmt_secs(no)} {'ahead of' if no > 0 else 'behind'} the dashboard; fix time sync there."
    if not retried:
        return (f"{node} refused the root@pam sign-in (HTTP 401)." + clock +
                " Close this tab and open the console again; you'll be asked for the root password.")
    via = f" issued by {entry}" if entry and entry != node else ""
    return (f"{node} refused the root@pam sign-in{via} (HTTP 401), even with a fresh sign-in." + clock +
            (f" If {node} joined the cluster recently, restart its API services on it "
             f"(systemctl restart pvedaemon pveproxy) and check its clock." if not clock else ""))


def get(sid: str) -> Session | None:
    with _lock:
        return _sessions.get(sid)


def _host_base(host: ProxmoxHost) -> str:
    h = f"[{host.host}]" if ":" in host.host and not host.host.startswith("[") else host.host
    return f"{h}:{host.port}"


def _paths(s: Session) -> tuple[str, dict, str]:
    """(proxy API path, its parameters, websocket path) for the session's console kind."""
    n = quote(s.node, safe="")
    if s.kind == "vm":
        base = f"/api2/json/nodes/{n}/qemu/{s.vmid}"
        return base + "/vncproxy", {"websocket": 1}, base + "/vncwebsocket"
    if s.kind == "ct":
        base = f"/api2/json/nodes/{n}/lxc/{s.vmid}"
        return base + "/termproxy", {}, base + "/vncwebsocket"
    base = f"/api2/json/nodes/{n}"
    return base + "/termproxy", ({"cmd": "upgrade"} if s.kind == "upgrade" else {}), base + "/vncwebsocket"


def start(s: Session, host: ProxmoxHost) -> dict:
    """Ask Proxmox for a console port. Returns what the page needs (VNC password for noVNC)."""
    if s.started:
        raise ConsoleError("This console was already started. Use Reconnect.")
    path, params, _ = _paths(s)
    try:
        tlspin.prepare(host)   # certificate pin
    except (OSError, tlspin.PinError) as exc:
        raise ConsoleError(f"Could not reach {host.name} securely: {exc}") from exc
    if s.auth == "token":
        auth_kw = {"headers": {"Authorization": _token_header(host)}}
    else:
        auth_kw = {"cookies": {"PVEAuthCookie": s.pve_ticket}, "headers": {"CSRFPreventionToken": s.csrf}}
    try:
        r = requests.post(f"https://{_host_base(host)}{path}", data=params, timeout=HTTP_TIMEOUT,
                          verify=host.verify_ssl, **auth_kw)
    except requests.RequestException as exc:
        if "fingerprints did not match" in str(exc).lower():
            raise ConsoleError(tlspin.explain(exc, host) or str(exc)) from exc
        raise ConsoleError(f"Could not reach {host.name} ({exc.__class__.__name__}).") from exc
    if s.auth == "token" and r.status_code in (401, 403):
        msg = (r.reason or "").strip()
        try:
            msg = (r.json() or {}).get("message", msg) or msg
        except ValueError:
            pass
        block_token(s.host_id, f"HTTP {r.status_code} {str(msg).strip()[:160]}")
        raise ConsoleError(f"Proxmox refused the API token for this console (HTTP {r.status_code} {str(msg).strip()[:160]}). "
                           "Close this tab and open the console again: the dashboard will ask for the root password "
                           "for this host's consoles for the next hour.")
    if r.status_code == 401:
        raise TicketRejected("The root@pam session on the host expired. Close this tab and open the console again.")
    if r.status_code != 200:
        msg = (r.reason or "").strip()
        try:
            msg = (r.json() or {}).get("message", msg) or msg
        except ValueError:
            pass
        raise ConsoleError(f"Proxmox refused to open the console: HTTP {r.status_code} {str(msg).strip()[:200]}")
    data = (r.json() or {}).get("data") or {}
    if not data.get("port") or not data.get("ticket"):
        raise ConsoleError("Proxmox didn't return a console port.")
    user = str(data.get("user") or "root@pam")
    if not re.fullmatch(r"[^\s:@]{1,64}@[A-Za-z0-9.-]{1,64}(![A-Za-z0-9._-]{1,64})?", user):
        user = "root@pam"   # a host-reported value goes into the termproxy handshake line
    s.port, s.vncticket, s.pve_user = str(data["port"]), str(data["ticket"]), user
    if not re.fullmatch(r"\d{1,5}", s.port) or any(c in s.vncticket for c in "\r\n"):
        raise ConsoleError("Proxmox returned an invalid console port or ticket.")
    s.started = time.time()
    return {"password": s.vncticket} if s.kind == "vm" else {}


def _ssl_context(host: ProxmoxHost) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not host.verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _end_log(log_id: int, reason: str, up: int = 0, down: int = 0, connected_at: datetime | None = None) -> None:
    try:
        with db_session() as db:
            row = db.get(ConsoleLog, log_id)
            if row and row.ended_at is None:
                row.ended_at = datetime.now(timezone.utc)
                row.end_reason = reason[:200]
                row.bytes_to_host = up
                row.bytes_from_host = down
                if connected_at and not row.connected_at:
                    row.connected_at = connected_at
    except Exception:  # noqa: BLE001
        log.exception("could not write console log %s", log_id)


def _mark_connected(log_id: int) -> datetime:
    now = datetime.now(timezone.utc)
    with db_session() as db:
        row = db.get(ConsoleLog, log_id)
        if row:
            row.connected_at = now
    return now


def close_orphans() -> int:
    """At startup: console_log rows left open by a stop / crash get an end reason."""
    n = 0
    with db_session() as db:
        for row in db.query(ConsoleLog).filter(ConsoleLog.ended_at.is_(None)).all():
            row.ended_at = datetime.now(timezone.utc)
            row.end_reason = "service stopped or restarted while open"
            n += 1
    if n:
        events.event("system", "console_log.orphans_closed", "info", details={"count": n})
    return n


def _is_activity_from_browser(s: Session, data) -> bool:
    """Does this browser->host message mean someone is at the keyboard?

    Terminals (termproxy): "0:<n>:<data>" is input; "1:..." (resize) and "2" (keep-alive ping) are not.
    VNC: noVNC keeps asking for screen updates (FramebufferUpdateRequest, 10 bytes, type 3) on
    its own; anything else (keys, pointer, clipboard, handshake) counts.
    """
    if s.kind != "vm":
        head = data[:2] if isinstance(data, str) else bytes(data[:2]).decode("latin-1")
        return head == "0:"
    b = data.encode("latin-1", "replace") if isinstance(data, str) else bytes(data)
    if not b:
        return False
    return not (len(b) % 10 == 0 and all(b[i] == 3 for i in range(0, len(b), 10)))


def keepalive(s: Session) -> None:
    """The user clicked "Stay connected" on the console page."""
    if s.connected and not s.finished:
        s.last_activity = time.monotonic()


def public_status(s: Session) -> dict:
    now = time.monotonic()
    d = {"connected": s.connected, "finished": s.finished, "end_reason": s.end_reason,
         "idle_limit": int(idle_seconds()), "max_seconds": int(settings.CONSOLE_MAX_SECONDS)}
    if s.connected and not s.finished:
        d["idle_remaining"] = max(0, int(idle_seconds() - (now - s.last_activity)))
        d["max_remaining"] = max(0, int(s.deadline - now))
    return d


def kick_user(user_id: int, reason: str) -> int:
    """End every open console of a user (disabled, deleted, demoted). Returns how many."""
    n = 0
    with _lock:
        for s in _sessions.values():
            if s.user_id == user_id and not s.finished:
                s.kick = reason
                n += 1
    return n


def _still_allowed(s: Session) -> str:
    """'' if the console's owner may still use it, else why not (checked every 20 s while open,
    so a change made anywhere - web UI, manage.py, Entra role at sign-in - ends it)."""
    from . import permissions, sessions
    from .models import User

    if s.browser_sid and sessions.is_revoked(s.browser_sid):
        return "signed out"
    with db_session() as db:
        u = db.get(User, s.user_id)
        if u is None:
            return "account deleted"
        if u.is_sso:
            from .auth import sso_recheck_due

            if sso_recheck_due(s.signin_at):
                # the Entra app role is re-read at the Microsoft re-check; don't keep a console past it
                return "Microsoft sign-in re-check due (app role)"
        if not u.is_active:
            return "account disabled"
        if not permissions.role_can(u.role, permissions.CONSOLE):
            return "account changed: role no longer allows consoles"
        if s.user_key and u.session_key != s.user_key:
            return "account changed: signed out everywhere (password, authenticator, role or access)"
    return ""


def _event_end(s: Session, reason: str, up: int, down: int) -> None:
    dur = int(time.time() - s.connected_at) if s.connected_at else 0
    det = {"log_id": s.log_id, "kind": s.kind, "label": s.label, "reason": reason, "duration_seconds": dur,
           "bytes_to_host": up, "bytes_from_host": down, "stepup": s.stepup_method}
    outcome = "ok" if reason in ("browser closed", "host closed", "closed") else "info"
    if reason.startswith(("error", "could not", "host refused", "The host refused", "Proxmox")):
        outcome = "error"
    events.event("console", "console.end", outcome, username=s.username, client_ip=s.client_ip, host_id=s.host_id,
                 host_name=s.host_name, node=s.node, vmid=s.vmid, details=det)


async def relay(ws: WebSocket, s: Session, host: ProxmoxHost) -> None:
    """Connect to the host's console websocket and pipe both ways until one side closes, the
    session goes idle, or it reaches its time limit."""
    from websockets.asyncio.client import connect
    from websockets.exceptions import ConnectionClosed, InvalidStatus

    _, _, ws_path = _paths(s)
    url = f"wss://{_host_base(host)}{ws_path}?" + urlencode({"port": s.port, "vncticket": s.vncticket})
    up_bytes = down_bytes = 0
    reason = "closed"
    connected_at = None
    term = s.kind != "vm"
    try:
        # the root@pam cookie only goes to the pinned certificate (checked before the upgrade request)
        expected = "" if host.verify_ssl else await asyncio.to_thread(tlspin.prepare, host)
        upstream_auth = ({"Authorization": await asyncio.to_thread(_token_header, host)} if s.auth == "token"
                         else {"Cookie": "PVEAuthCookie=" + quote(s.pve_ticket, safe="")})
        async with connect(url, additional_headers=upstream_auth,
                           subprotocols=["binary"], ssl=_ssl_context(host), max_size=None, ping_interval=None,
                           create_connection=None if host.verify_ssl else tlspin.pinned_connection(expected),
                           open_timeout=15, close_timeout=5, proxy=None) as upstream:  # always direct to the host
            if term:
                # termproxy handshake: the dashboard authenticates, the browser only sees the shell.
                await upstream.send(f"{s.pve_user}:{s.vncticket}\n")
                first = await asyncio.wait_for(upstream.recv(), timeout=15)
                if (first.decode(errors="replace") if isinstance(first, bytes) else first).strip() != "OK":
                    raise ConsoleError("The host refused the terminal session.")
            connected_at = await asyncio.to_thread(_mark_connected, s.log_id)
            s.connected = True
            s.connected_at = time.time()
            s.last_activity = time.monotonic()
            s.deadline = s.last_activity + settings.CONSOLE_MAX_SECONDS
            log.info("console connected id=%d user=%s %s", s.log_id, s.username, s.label)
            events.event("console", "console.connect", "ok", username=s.username, client_ip=s.client_ip,
                         host_id=s.host_id, host_name=s.host_name, node=s.node, vmid=s.vmid,
                         details={"log_id": s.log_id, "kind": s.kind, "label": s.label, "stepup": s.stepup_method})

            async def browser_to_host():
                nonlocal up_bytes
                while True:
                    msg = await ws.receive()
                    if msg["type"] == "websocket.disconnect":
                        return "browser closed"
                    data = msg.get("bytes") if msg.get("bytes") is not None else msg.get("text")
                    if data is None:
                        continue
                    up_bytes += len(data)
                    if _is_activity_from_browser(s, data):
                        s.last_activity = time.monotonic()
                    await upstream.send(data)

            async def host_to_browser():
                nonlocal down_bytes
                try:
                    async for m in upstream:
                        down_bytes += len(m)
                        if term:
                            s.last_activity = time.monotonic()   # output keeps a terminal open (running upgrade)
                        if isinstance(m, bytes):
                            await ws.send_bytes(m)
                        else:
                            await ws.send_text(m)
                except ConnectionClosed:
                    pass
                return "host closed"

            async def watchdog():
                idle = idle_seconds()
                next_check = time.monotonic() + 20
                while True:
                    await asyncio.sleep(1)
                    now = time.monotonic()
                    if s.kick:
                        return s.kick
                    if now >= next_check:
                        next_check = now + 20
                        why = await asyncio.to_thread(_still_allowed, s)
                        if why:
                            return why
                    if now >= s.deadline:
                        return f"time limit reached ({int(settings.CONSOLE_MAX_SECONDS // 60)} min)"
                    if now - s.last_activity >= idle:
                        return f"idle timeout ({settings.CONSOLE_IDLE_MINUTES:g} min without activity)"

            tasks = [asyncio.create_task(c()) for c in (browser_to_host, host_to_browser, watchdog)]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            for t in done:
                try:
                    reason = t.result() or reason
                except (WebSocketDisconnect, ConnectionClosed):
                    reason = "connection closed"
                except Exception as exc:  # noqa: BLE001
                    reason = f"error: {exc.__class__.__name__}"
            if reason.startswith(("idle timeout", "time limit", "signed out", "account")):
                await _close_with(ws, 4000, reason)
    except (ConsoleError, tlspin.PinError) as exc:
        reason = str(exc)
        await _close_with(ws, 4002, reason)
    except InvalidStatus as exc:
        code = exc.response.status_code
        reason = f"host refused the console websocket (HTTP {code})"
        if s.auth == "token" and code in (401, 403):
            block_token(s.host_id, f"websocket HTTP {code}")
            reason += (": the API token was refused for the console websocket. Close this tab and open the console "
                       "again; the dashboard will ask for the root password")
        elif code == 401:
            drop_ticket(s.pve_ticket)
            reason += ": the root@pam sign-in was rejected. Close this tab and open the console again"
        await _close_with(ws, 4002, reason)
    except (OSError, asyncio.TimeoutError, ConnectionClosed) as exc:
        reason = f"could not connect to the host ({exc.__class__.__name__})"
        await _close_with(ws, 4002, reason)
    finally:
        s.finished, s.finished_at = True, time.time()
        s.end_reason = reason
        try:
            await ws.close()
        except Exception:  # noqa: BLE001
            pass
        await asyncio.to_thread(_end_log, s.log_id, reason, up_bytes, down_bytes, connected_at)
        _event_end(s, reason, up_bytes, down_bytes)
        log.info("console ended id=%d user=%s %s reason=%s bytes up=%d down=%d", s.log_id, s.username, s.label,
                 reason, up_bytes, down_bytes)


async def _close_with(ws: WebSocket, code: int, reason: str) -> None:
    try:
        await ws.close(code=code, reason=reason[:120])
    except Exception:  # noqa: BLE001
        pass


def forget(sid: str) -> None:
    with _lock:
        _sessions.pop(sid, None)
