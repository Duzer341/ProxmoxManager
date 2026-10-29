"""Revoked browser sign-ins. See models.RevokedSession."""

import logging
import threading
from datetime import datetime, timedelta, timezone

from .config import settings

log = logging.getLogger("app.auth")
_lock = threading.Lock()
_revoked: set[str] = set()
_loaded = [False]


def _load() -> None:
    if _loaded[0]:
        return
    from .database import db_session
    from .models import RevokedSession

    with db_session() as db:
        rows = [r.sid for r in db.query(RevokedSession.sid).all()]
    with _lock:
        _revoked.update(rows)
        _loaded[0] = True


def is_revoked(sid: str) -> bool:
    if not sid:
        return True
    _load()
    with _lock:
        return sid in _revoked


def revoke(sid: str) -> None:
    if not sid:
        return
    _load()
    with _lock:
        if sid in _revoked:
            return
        _revoked.add(sid)
    from .database import db_session
    from .models import RevokedSession

    try:
        with db_session() as db:
            if db.get(RevokedSession, sid) is None:
                db.add(RevokedSession(sid=sid))
    except Exception:  # noqa: BLE001
        log.exception("could not store a revoked session")


def prune() -> int:
    """Forget revocations older than the longest a session cookie can live."""
    from .database import db_session
    from .models import RevokedSession

    cut = datetime.now(timezone.utc) - timedelta(seconds=settings.SESSION_MAX_AGE + 3600)
    with db_session() as db:
        old = [r.sid for r in db.query(RevokedSession).filter(RevokedSession.revoked_at < cut).all()]
        if old:
            db.query(RevokedSession).filter(RevokedSession.sid.in_(old)).delete(synchronize_session=False)
    with _lock:
        _revoked.difference_update(old)
    return len(old)
