"""Fresh re-auth before consoles ("step-up").

Every console (VM, container, node terminal, upgrade shell) needs a recent re-auth on top of
the normal sign-in:

    local accounts   a fresh 6-digit authenticator code (TOTP). Backup / recovery codes are
                     refused here, and a code that was already used (e.g. at sign-in) is refused.
    Entra accounts   a forced fresh Microsoft sign-in (prompt=login, max_age=0), optionally with
                     a Conditional Access authentication context (PM_ENTRA_STEPUP_ACR).

A successful re-auth opens a fixed window (PM_STEPUP_MINUTES, default 15) for that browser
sign-in, from the address it was done from, only. Using consoles does not extend it. Times use
a monotonic clock, so a clock change can't stretch the window. The window is kept here in memory, keyed by
user id + a random per-sign-in id stored in the session cookie, because the session cookie
itself can't be revoked server-side: signing out, a service restart or another browser never
carries the window over. Five wrong codes in a row sign the browser out.
"""

import threading
import time

from .config import settings

SESSION_SID_KEY = "sid"
MAX_FAILS = 5

_lock = threading.Lock()
_grants: dict[tuple[int, str], dict] = {}   # (user_id, sid) -> {"until", "at", "method", "ip"} (monotonic times)
_fails: dict[tuple[int, str], int] = {}


class StepUpRequired(Exception):
    """Raised by console endpoints; main.py turns it into 403 {"detail", "stepup_required", "methods"}."""

    def __init__(self, message: str, methods: list[str]):
        super().__init__(message)
        self.message, self.methods = message, methods


def window_seconds() -> int:
    return max(30, int(settings.STEPUP_MINUTES * 60))


def methods_for(user, cfg) -> list[str]:
    """How this user can re-auth for consoles ([] = can't, see blocked_reason)."""
    if user.is_sso:
        return ["entra"] if cfg.sso_enabled and cfg.entra_ready else []
    if user.mfa_enabled and user.mfa_secret_enc:
        return ["totp"]
    return []


def blocked_reason(user, cfg) -> str:
    if user.is_sso:
        return "Microsoft sign-in is not configured on this dashboard, so the console re-auth can't run."
    if cfg.mfa_available:
        return "Consoles need an authenticator app. Set one up on your Account page first."
    return ("Consoles need a fresh check with an authenticator app or a Microsoft sign-in, but this dashboard "
            "signs in with a password only. An admin can change that with manage.py configure-login.")


def _purge(now: float) -> None:
    for k in [k for k, g in _grants.items() if g["until"] <= now]:
        _grants.pop(k, None)


def grant(user_id: int, sid: str, method: str, ip: str = "") -> float:
    """Open the window; returns its end as wall-clock time (for display only)."""
    if not sid:
        raise ValueError("no browser sign-in id")
    now = time.monotonic()
    with _lock:
        _purge(now)
        _grants[(user_id, sid)] = {"until": now + window_seconds(), "at": now, "method": method, "ip": ip or ""}
        _fails.pop((user_id, sid), None)
    return time.time() + window_seconds()


def status(user_id: int, sid: str, ip: str | None = None) -> dict | None:
    """The window of this browser sign-in, if open (and, with ip, used from the same address)."""
    if not sid:
        return None
    now = time.monotonic()
    with _lock:
        g = _grants.get((user_id, sid))
        if not g or g["until"] <= now:
            return None
        if ip is not None and g["ip"] and ip != g["ip"]:
            return None
        return {"method": g["method"], "remaining": int(g["until"] - now)}


def valid(user_id: int, sid: str, ip: str | None = None) -> bool:
    return status(user_id, sid, ip) is not None


def drop(user_id: int, sid: str) -> bool:
    with _lock:
        return _grants.pop((user_id, sid), None) is not None


def drop_session(sid: str) -> None:
    if not sid:
        return
    with _lock:
        for k in [k for k in _grants if k[1] == sid]:
            _grants.pop(k, None)
        for k in [k for k in _fails if k[1] == sid]:
            _fails.pop(k, None)


def drop_user(user_id: int) -> None:
    with _lock:
        for k in [k for k in _grants if k[0] == user_id]:
            _grants.pop(k, None)


def failure(user_id: int, sid: str) -> int:
    with _lock:
        n = _fails.get((user_id, sid), 0) + 1
        _fails[(user_id, sid)] = n
        return n
