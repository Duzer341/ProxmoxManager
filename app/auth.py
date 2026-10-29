"""Password hashing, session handling and role guards."""

import secrets
import time

import bcrypt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from . import sessions
from .database import get_db
from .models import User

SESSION_USER_KEY = "uid"
SESSION_AMR_KEY = "amr"  # how the session was authenticated: pwd | mfa | sso
SESSION_SID_KEY = "sid"  # random id of this browser sign-in
SESSION_UK_KEY = "uk"    # the user's session key at sign-in
SESSION_AT_KEY = "at"    # when this sign-in happened (unix time)
SSO_RECHECK_KEY = "sso_recheck"   # set after an Entra sign-in aged out: the login page goes straight to Microsoft


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def validate_password_strength(password: str) -> str | None:
    """Return an error message, or None if the password is acceptable."""
    if len(password) < 10:
        return "Password must be at least 10 characters."
    if len(password) > 128:
        return "Password is too long."
    return None


def login_user(request: Request, user: User, amr: str = "pwd") -> None:
    from . import stepup

    old = request.session.get(stepup.SESSION_SID_KEY, "")
    if old:
        stepup.drop_session(old)
        sessions.revoke(old)
    request.session.clear()  # also drops any half-finished MFA / SSO state
    request.session[SESSION_USER_KEY] = user.id
    request.session[SESSION_AMR_KEY] = amr
    # Random id of this sign-in: revocation, console re-auth windows and audit entries are tied to it.
    request.session[stepup.SESSION_SID_KEY] = secrets.token_urlsafe(18)
    request.session[SESSION_UK_KEY] = user.session_key
    request.session[SESSION_AT_KEY] = int(time.time())


def logout_user(request: Request) -> None:
    """Sign this browser out for good: the sign-in id is revoked server-side, so a copy of the
    cookie stops working too."""
    from . import stepup

    sid = request.session.get(stepup.SESSION_SID_KEY, "")
    if sid:
        stepup.drop_session(sid)
        sessions.revoke(sid)
    request.session.clear()


def session_id(request: Request, create: bool = False) -> str:
    """This browser sign-in's random id ('' if none: such sessions are refused anyway)."""
    from . import stepup

    return request.session.get(stepup.SESSION_SID_KEY, "")


def get_current_user_optional(request: Request, db: Session = Depends(get_db)) -> User | None:
    request.state.user = None
    uid = request.session.get(SESSION_USER_KEY)
    if not uid:
        return None
    user = db.get(User, uid)
    if user is None or not user.is_active:
        logout_user(request)
        request.state.signed_out = "account disabled or deleted"
        return None
    # the sign-in must carry its random id (sessions from older versions sign in again
    # once), must not be revoked, and must match the user's current session key.
    sid = request.session.get(SESSION_SID_KEY, "")
    if not sid or sessions.is_revoked(sid) or not user.session_key or request.session.get(SESSION_UK_KEY) != user.session_key:
        why = ("sign-in from an older version" if not sid else "signed out" if sessions.is_revoked(sid)
               else "account changed (password, authenticator, role or access) - signed out everywhere")
        logout_user(request)
        request.state.signed_out = why
        return None
    # a password set by an administrator is replaced at sign-in before a session starts; a
    # session can only exist with the flag set if it was set later, so sign that browser out.
    if user.must_change_password and not user.is_sso:
        logout_user(request)
        request.state.signed_out = "password set by an administrator - the user sets a new one at sign-in"
        return None
    # Sessions created before the login mode changed must meet the current rules:
    # an admin signed in with only a password when MFA is now required, or an Entra
    # account after SSO was switched off, has to sign in again.
    from . import loginconfig

    cfg = loginconfig.load(db)
    amr = request.session.get(SESSION_AMR_KEY, "pwd")
    if (cfg.mfa_required(user) and amr == "pwd") or (user.is_sso and not cfg.sso_enabled):
        logout_user(request)
        request.state.signed_out = "the sign-in rules changed"
        return None
    # the role of a Microsoft account comes from its Entra app role, read at sign-in. Send
    # the browser back through Microsoft regularly so a removed or lowered role takes effect.
    if user.is_sso:
        if sso_recheck_due(request.session.get(SESSION_AT_KEY)):
            logout_user(request)
            request.session[SSO_RECHECK_KEY] = 1
            request.state.signed_out = "Microsoft sign-in re-check (app role)"
            return None
    request.state.user = user
    request.state.user_ident = (user.id, user.username, user.role)  # for the event log
    request.state.amr = amr
    return user


def sso_recheck_due(signed_in_at) -> bool:
    """A Microsoft sign-in older than PM_ENTRA_RECHECK_MINUTES has to go through Microsoft again."""
    from .config import settings

    try:
        at = float(signed_in_at or 0)
    except (TypeError, ValueError):
        at = 0.0
    return time.time() - at > max(0.05, settings.ENTRA_RECHECK_MINUTES) * 60


def _wants_html(request: Request) -> bool:
    return not request.url.path.startswith("/api/")


class NotAuthenticated(Exception):
    """Raised for browser requests so the handler can redirect to /login."""


def require_user(request: Request, user: User | None = Depends(get_current_user_optional)) -> User:
    if user is None:
        if _wants_html(request):
            raise NotAuthenticated()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not logged in")
    return user


def require_admin(user: User = Depends(require_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return user


def require_cap(cap: str):
    """Dependency factory: the signed-in user's role must grant `cap` (see app/permissions.py)."""

    def _dep(user: User = Depends(require_user)) -> User:
        if not user.can(cap):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Your role doesn't allow this" + (" (admins only)" if cap not in _TECH else ""))
        return user

    _dep.__name__ = "require_" + cap.replace(".", "_")
    return _dep


def _tech_caps() -> frozenset:
    from .permissions import CAPS

    return CAPS["technician"]


_TECH = _tech_caps()


def require_same_origin(request: Request) -> None:
    """Light CSRF guard for state-changing JSON calls: the browser must send a
    matching Origin/Referer, and the session cookie is SameSite=Lax anyway."""
    origin = request.headers.get("origin") or request.headers.get("referer")
    if not origin:
        return  # non-browser client (curl etc.) with a valid session cookie
    host = request.headers.get("host", "")
    from urllib.parse import urlparse

    parsed = urlparse(origin)
    if parsed.netloc and parsed.netloc != host:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-origin request blocked")
