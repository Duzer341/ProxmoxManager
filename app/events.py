"""Security and activity events, written to the service journal (logger ``app.events``).

Endpoints describe what a request did through ``note(request, ...)`` / ``note_current(...)``:

    action, category, outcome    what happened (e.g. "login.mfa", "auth", "ok")
    details                      non-secret facts (what was changed, why it failed)
    user (object), username, host_name, target_user, node, vmid

``EventLogMiddleware`` writes one line per request that noted an action, every other
state-changing request (POST / PUT / PATCH / DELETE, named after its endpoint), every refused
request (401 / 403) and refused websockets. Page views and background polling (GET) are not
logged. Other code calls
``event(...)`` directly (service start, console connect / end, job results).

Secrets never reach the journal: values under credential-looking names are dropped and
values that look like keys, tokens, tickets or passwords are replaced.

    journalctl -u proxmox-manager | grep app.events
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import hmac
import json
import logging
import re
import threading
import time

log = logging.getLogger("app.events")

# The current request's event dict, for helpers that don't get the request (e.g. job starts).
CURRENT: contextvars.ContextVar[dict | None] = contextvars.ContextVar("pm_event_ctx", default=None)

_SECRET_KEY_RE = re.compile(r"(?i)(.*_)?(passwords?|passwd|secrets?|tokens?|codes?|tickets?|keys?|otp|totp|cookies?|vnctickets?)")
# secrets are also recognised by what they look like, wherever they are
_SECRET_VALUE_RES = [
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|$)", re.S), "[private key removed]"),
    (re.compile(r"(?i)PVEAPIToken=\S+"), "PVEAPIToken=[removed]"),
    (re.compile(r"(?i)PVEAuthCookie=[^;\s]+"), "PVEAuthCookie=[removed]"),
    (re.compile(r"PVE(?:VNC)?:[^:\s]+:[0-9A-Fa-f]{8}::\S+"), "[ticket removed]"),
    (re.compile(r"(?i)\b(authorization|bearer|basic)\s*[:=]?\s+[A-Za-z0-9._~+/=-]{16,}"), r"\1 [removed]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "[token removed]"),
    (re.compile(r"\bgAAAAA[A-Za-z0-9_=-]{40,}"), "[encrypted value removed]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token_value|client_secret)=([^&\s]+)"), r"\1=[removed]"),
]
_NEVER = re.compile(r"^/(static/|healthz$|favicon\.ico$)")


def _scrub_value(v: str) -> str:
    for rx, repl in _SECRET_VALUE_RES:
        v = rx.sub(repl, v)
    return v


def _clean_value(k: str, v, depth: int = 0):
    """None means: leave this entry out."""
    if _SECRET_KEY_RE.fullmatch(k) and not isinstance(v, (bool, int, float)) and v is not None:
        return None   # nothing but a plain number / flag under a credential-looking name
    if isinstance(v, (bytes, bytearray)):
        return None
    if isinstance(v, str):
        v = _scrub_value(v)
        return v[:500] + "…" if len(v) > 500 else v
    if isinstance(v, dict):
        if depth >= 3:
            return "…"
        out = {}
        for kk, vv in list(v.items())[:50]:
            c = _clean_value(str(kk), vv, depth + 1)
            if c is not None:
                out[str(kk)[:64]] = c
        return out
    if isinstance(v, (list, tuple, set)):
        if depth >= 3:
            return "…"
        return [c for c in (_clean_value("", x, depth + 1) for x in list(v)[:50]) if c is not None]
    if v is None or isinstance(v, (bool, int, float)):
        return v
    return _scrub_value(str(v))[:500]


def clean_details(d: dict | None) -> dict:
    out = {}
    for k, v in (d or {}).items():
        c = _clean_value(str(k), v)
        if c is not None:
            out[str(k)[:64]] = c
    return out


def mask_username(typed: str) -> str:
    """For failed sign-ins with a username that doesn't exist (people type passwords there): no
    characters are kept, only a length range and a keyed tag so repeated attempts can be linked."""
    typed = (typed or "").strip()
    if not typed:
        return ""
    from . import crypto

    n = len(typed)
    bucket = "1-4" if n <= 4 else "5-8" if n <= 8 else "9-16" if n <= 16 else "17+"
    tag = hmac.new(crypto.derive_key("pm-username-mask/v1"), ("user:" + typed.lower()).encode("utf-8", "replace"),
                   hashlib.sha256).hexdigest()[:8]
    return f"unknown account #{tag} ({bucket} chars)"


def event(category: str, action: str, outcome: str = "ok", *, user=None, username: str = "", client_ip: str = "",
          host_id: int | None = None, host_name: str = "", node: str = "", vmid: int | None = None,
          target_user: str = "", details: dict | None = None, method: str = "", path: str = "", status: int | None = None,
          user_id: int | None = None, **_ignored) -> None:
    """Write one event line to the journal."""
    if user is not None:
        username = username or getattr(user, "username", "") or ""
        user_id = user_id if user_id is not None else getattr(user, "id", None)
    rec = {"category": category, "action": action, "outcome": outcome}
    for k, v in (("user", username), ("user_id", user_id), ("ip", client_ip), ("host_id", host_id), ("host", host_name), ("node", node),
                 ("vmid", vmid), ("target_user", target_user), ("method", method), ("path", path), ("status", status)):
        if v not in (None, ""):
            rec[k] = v
    det = clean_details(details)
    if det:
        rec["details"] = det
    line = json.dumps(rec, ensure_ascii=False, default=str)[:4000]
    (log.warning if outcome in ("failed", "denied", "error") else log.info)("%s", line)


# --------------------------------------------------------------------------- #
# Per-request notes
# --------------------------------------------------------------------------- #

_names_lock = threading.Lock()
_host_names: dict[int, tuple[float, str]] = {}


def _host_name(host_id) -> str:
    """A host's name for the event line, cached for a minute (misses aren't cached)."""
    try:
        host_id = int(host_id)
    except (TypeError, ValueError):
        return ""
    now = time.time()
    with _names_lock:
        hit = _host_names.get(host_id)
    if hit and now - hit[0] < 60:
        return hit[1]
    from .database import db_session
    from .models import ProxmoxHost

    try:
        with db_session() as db:
            h = db.get(ProxmoxHost, host_id)
            name = h.name if h else ""
    except Exception:  # noqa: BLE001
        name = ""
    if name:
        with _names_lock:
            if len(_host_names) > 5000:
                _host_names.clear()
            _host_names[host_id] = (now, name)
    return name


def _outcome(code: int | None) -> str:
    if code is None or code >= 500:
        return "error"
    if code < 400:
        return "ok"
    return "denied" if code in (401, 403) else "failed"


class EventLogMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket") or _NEVER.match(scope.get("path", "")):
            return await self.app(scope, receive, send)
        ctx: dict = {}
        scope.setdefault("state", {})["audit"] = ctx
        st: dict = {"code": None, "ws": None}

        async def _send(msg):
            t = msg["type"]
            if t == "http.response.start":
                st["code"] = msg["status"]
            elif t == "websocket.accept":
                st["ws"] = "accepted"
            elif t == "websocket.close" and st["ws"] is None:
                st["ws"] = "refused"
                st["close_code"] = msg.get("code")
            await send(msg)

        token = CURRENT.set(ctx)
        try:
            await self.app(scope, receive, _send)
        except Exception:
            if st["code"] is None:
                st["code"] = 500
            raise
        finally:
            CURRENT.reset(token)
            try:
                # off the event loop: may look up the host name in the database
                await asyncio.to_thread(self._write, scope, ctx, st)
            except Exception:  # noqa: BLE001
                log.exception("could not write the event for %s", scope.get("path", ""))

    @staticmethod
    def _write(scope, ctx: dict, st: dict) -> None:
        is_ws = scope["type"] == "websocket"
        refused_ws = is_ws and st["ws"] == "refused"
        method = "WS" if is_ws else scope.get("method", "")
        code = 403 if refused_ws else (101 if is_ws else st["code"])
        changing = method in ("POST", "PUT", "PATCH", "DELETE")
        if ctx.get("skip") or not (ctx.get("action") or refused_ws or changing or code in (401, 403)):
            return
        endpoint = getattr(scope.get("endpoint"), "__name__", "") or ("not_found" if code == 404 else "request")
        ident = ctx.get("user_ident") or (scope.get("state") or {}).get("user_ident")
        details = dict(ctx.get("details") or {})
        if refused_ws and st.get("close_code"):
            details.setdefault("close_code", st["close_code"])
        signed_out = (scope.get("state") or {}).get("signed_out")
        if signed_out:
            details.setdefault("signed_out", signed_out)
        pp = scope.get("path_params") or {}
        client = scope.get("client") or ("", 0)
        host_id = ctx.get("host_id", pp.get("host_id"))
        host_name = ctx.get("host_name") or (_host_name(host_id) if host_id is not None and code not in (401, 404) else "")
        event(ctx.get("category") or ("denied" if code in (401, 403) else "action"),
              ctx.get("action") or ("console.ws" if is_ws else endpoint), ctx.get("outcome") or _outcome(code),
              username=ctx.get("username") or (ident[1] if ident else ""), user_id=ident[0] if ident else None,
              client_ip=client[0] or "",
              host_id=host_id, host_name=host_name,
              node=ctx.get("node", pp.get("node", "")) or "", vmid=ctx.get("vmid", pp.get("vmid")),
              target_user=ctx.get("target_user", ""), details=details, method=method, path=scope.get("path", ""),
              status=code)


def ctx_of(request) -> dict:
    """The event dict of the current request (a throwaway dict outside the middleware)."""
    try:
        d = request.state.audit
        if isinstance(d, dict):
            return d
    except AttributeError:
        pass
    return {}


def ident(user) -> tuple | None:
    """(id, username, role) read now, so a detached ORM object is never touched later."""
    if user is None:
        return None
    return (user.id, user.username, user.role)


def _merge(d: dict, kw: dict) -> None:
    if "user" in kw:
        kw["user_ident"] = ident(kw.pop("user"))
    det = kw.pop("details", None)
    d.update(kw)
    if det:
        d.setdefault("details", {}).update(det)


def note(request, **kw) -> None:
    """Add to the current request's event. details=... merges into the existing details;
    user=<User> attributes the event to that account."""
    _merge(ctx_of(request), kw)


def note_current(**kw) -> None:
    """note() for code that has no request object (runs inside the request's context)."""
    d = CURRENT.get()
    if d is not None:
        _merge(d, kw)
