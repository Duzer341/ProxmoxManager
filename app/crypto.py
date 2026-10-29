"""Encrypt / decrypt Proxmox credentials at rest using a key derived from PM_SECRET_KEY.

Before 1.3.0 the key was a single unsalted SHA-256 of PM_SECRET_KEY, so a leaked database with a
weak secret could be brute-forced offline. Keys are now derived with scrypt (N=2^15, r=8, p=1) and
a random salt stored in the database (app_settings "crypto_kdf_salt"), then split per use with
HKDF: stored credentials, the session cookie signature, the known-device cookie and the username
mask in the event log. Stored credentials written by older versions are re-encrypted with the new
key at startup (migrate()); the old key stays only as a decrypt fallback.
PM_SECRET_KEY must be at least 32 characters with some variety (config.py).
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import threading

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import settings

log = logging.getLogger(__name__)

SALT_KEY = "crypto_kdf_salt"
_lock = threading.Lock()
_master: bytes | None = None
_cache: dict[str, MultiFernet] = {}


def _legacy(prefix: str) -> Fernet:
    digest = hashlib.sha256((prefix + settings.SECRET_KEY).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def _salt() -> bytes:
    """The database's KDF salt, created on first use (it travels with the database and its backups)."""
    from sqlalchemy.exc import IntegrityError

    from .database import Base, db_session, engine
    from .models import AppSetting

    Base.metadata.create_all(bind=engine, tables=[AppSetting.__table__])
    with db_session() as db:
        row = db.get(AppSetting, SALT_KEY)
        if row is not None and row.value:
            return base64.b64decode(row.value)
        if _has_new_format_secrets(db):
            raise RuntimeError(
                "The database holds credentials encrypted with a salted key, but its key salt (app_settings "
                f"'{SALT_KEY}') is missing. A new salt would make them unreadable, so the service stops. Restore "
                "the database (with its app_settings table) from a backup.")
    try:
        with db_session() as db:
            db.add(AppSetting(key=SALT_KEY, value=base64.b64encode(secrets.token_bytes(16)).decode()))
    except IntegrityError:
        pass   # created concurrently: use that one
    with db_session() as db:
        return base64.b64decode(db.get(AppSetting, SALT_KEY).value)


def _has_new_format_secrets(db) -> bool:
    """True if any stored encrypted value can't be read with the old (unsalted) key. Plain SQL on the
    columns that exist: this runs at import, before the schema is brought up to date."""
    from sqlalchemy import inspect, text

    legacy = _legacy("pm-credential-key:")
    insp = inspect(db.get_bind())
    wanted = {"proxmox_hosts": ("secret_enc", "ssh_secret_enc", "console_secret_enc"),
              "users": ("mfa_secret_enc", "mfa_pending_secret_enc"), "app_settings": ("value",)}
    vals = []
    for table, cols in wanted.items():
        if not insp.has_table(table):
            continue
        have = [c for c in cols if c in {x["name"] for x in insp.get_columns(table)}]
        for col in have:
            vals += [r[0] for r in db.execute(text(f'SELECT "{col}" FROM "{table}"'))]
    for v in vals:
        if not v or not str(v).startswith("gAAAAA"):
            continue
        try:
            legacy.decrypt(str(v).encode())
        except InvalidToken:
            return True
    return False


def _master_key() -> bytes:
    global _master
    with _lock:
        if _master is None:
            _master = hashlib.scrypt(settings.SECRET_KEY.encode(), salt=_salt(), n=2 ** 15, r=8, p=1,
                                     maxmem=64 * 1024 * 1024, dklen=32)
        return _master


def keyring(purpose: str, legacy_prefix: str) -> MultiFernet:
    """MultiFernet that encrypts with the scrypt/HKDF key for `purpose` and still decrypts values
    written with the old SHA-256 derivation (`legacy_prefix`)."""
    with _lock:
        mf = _cache.get(purpose)
    if mf is not None:
        return mf
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=purpose.encode()).derive(_master_key())
    mf = MultiFernet([Fernet(base64.urlsafe_b64encode(key)), _legacy(legacy_prefix)])
    with _lock:
        _cache[purpose] = mf
    return mf


def _fernet() -> MultiFernet:
    return keyring("pm-credential-key/v2", "pm-credential-key:")


def encrypt(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise ValueError(
            "Stored credential could not be decrypted. PM_SECRET_KEY has probably changed "
            "since this host was added; edit the host and re-enter its token/password."
        ) from exc


def is_legacy(ciphertext: str) -> bool:
    """True if the value can only be read with the old SHA-256 key (not migrated yet)."""
    try:
        _legacy("pm-credential-key:").decrypt(ciphertext.encode())
        return True
    except InvalidToken:
        return False


def migrate() -> int:
    """Re-encrypt every stored credential that still uses the old key. Returns how many changed."""
    from .database import db_session
    from .models import AppSetting, ProxmoxHost, User

    mf = _fernet()
    changed = 0

    def rotate(value: str) -> str | None:
        nonlocal changed
        if not value or not is_legacy(value):
            return None
        changed += 1
        return mf.rotate(value.encode()).decode()

    with db_session() as db:
        for h in db.query(ProxmoxHost).all():
            for col in ("secret_enc", "ssh_secret_enc", "console_secret_enc"):
                new = rotate(getattr(h, col) or "")
                if new:
                    setattr(h, col, new)
        for u in db.query(User).all():
            for col in ("mfa_secret_enc", "mfa_pending_secret_enc"):
                new = rotate(getattr(u, col) or "")
                if new:
                    setattr(u, col, new)
        for s in db.query(AppSetting).all():
            if s.key != SALT_KEY and (s.value or "").startswith("gAAAAA"):
                new = rotate(s.value)
                if new:
                    s.value = new
    if changed:
        log.info("re-encrypted %d stored credential(s) with the scrypt-derived key", changed)
    return changed


def derive_key(purpose: str) -> bytes:
    """A 32-byte key for `purpose`, derived from the scrypt master (HMAC keys, cookie signing)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=purpose.encode()).derive(_master_key())
