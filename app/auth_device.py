"""Known-device cookie.

After a complete local sign-in the browser gets a long-lived, HttpOnly cookie per account, signed with
a key derived from PM_SECRET_KEY and bound to the account's session key (a password or authenticator
reset, role change or disable invalidates it). A browser that presents it is exempt from the
per-account slow-down in ratelimit.py, so failed attempts from other addresses can't keep the real
user out. Per-address limits still apply to it. The cookie grants no access by itself.
"""

from __future__ import annotations

import hashlib
import hmac
import time

from .config import settings

PREFIX = "pm_dev_"
MAX_AGE = 90 * 86400


def _name(username: str) -> str:
    return PREFIX + hashlib.sha256(("dev:" + username.strip().lower()).encode()).hexdigest()[:12]


def _mac(username: str, issued: int, session_key: str) -> str:
    from . import crypto

    msg = f"{username.strip().lower()}|{issued}|{session_key}".encode()
    return hmac.new(crypto.derive_key("pm-device-cookie/v1"), msg, hashlib.sha256).hexdigest()


def issue(response, user) -> None:
    if not user or user.is_sso or not user.session_key:
        return
    issued = int(time.time())
    response.set_cookie(_name(user.username), f"{issued}.{_mac(user.username, issued, user.session_key)}",
                        max_age=MAX_AGE, path="/", httponly=True, samesite="lax", secure=settings.SESSION_COOKIE_SECURE)


def known(request, user) -> bool:
    if user is None or not user.session_key:
        return False
    raw = request.cookies.get(_name(user.username), "")
    issued_s, _, mac = raw.partition(".")
    if not issued_s.isdigit() or not mac:
        return False
    issued = int(issued_s)
    if not 0 <= time.time() - issued <= MAX_AGE:
        return False
    return hmac.compare_digest(mac, _mac(user.username, issued, user.session_key))
