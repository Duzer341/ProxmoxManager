"""Password hashing, session handling and role guards."""

import bcrypt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .database import get_db
from .models import User

SESSION_USER_KEY = "uid"


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


def login_user(request: Request, user: User) -> None:
    request.session.clear()
    request.session[SESSION_USER_KEY] = user.id


def logout_user(request: Request) -> None:
    request.session.clear()


def get_current_user_optional(request: Request, db: Session = Depends(get_db)) -> User | None:
    request.state.user = None
    uid = request.session.get(SESSION_USER_KEY)
    if not uid:
        return None
    user = db.get(User, uid)
    if user is None or not user.is_active:
        request.session.clear()
        return None
    request.state.user = user
    return user


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
