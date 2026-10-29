"""TOTP (authenticator app) second factor and recovery codes.

RFC 6238 codes: 6 digits, 30-second steps, SHA-1, as used by Google Authenticator,
Microsoft Authenticator and most others. A code is accepted for the current step and one
step either side (clock drift), and never twice: the last accepted step is stored per user.
"""

import hashlib
import json
import secrets
import time
from datetime import datetime, timezone

import pyotp
import segno

from . import crypto
from .models import User

ISSUER = "Proxmox Manager"
RECOVERY_CODES = 10
_RC_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O, 1/I


def new_secret() -> str:
    return pyotp.random_base32()  # 160 bits


def provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)


def qr_svg(uri: str) -> str:
    """Inline SVG QR code (rendered on the server, no external service)."""
    return segno.make(uri, error="m").svg_inline(scale=5, border=3, dark="#000000", light="#ffffff")


def _norm(code: str) -> str:
    return "".join(ch for ch in code if not ch.isspace())


def _step(t: float | None = None) -> int:
    return int((time.time() if t is None else t) // 30)


def check_code(secret: str, code: str, last_step: int) -> int | None:
    """Return the matching step if code is valid and newer than last_step, else None."""
    code = _norm(code)
    if len(code) != 6 or not code.isdigit():
        return None
    totp = pyotp.TOTP(secret)
    now = _step()
    for step in (now - 1, now, now + 1):
        if step > last_step and secrets.compare_digest(totp.at(step * 30), code):
            return step
    return None


def code_was_used(secret: str, code: str, last_step: int) -> bool:
    """True if code is valid for a step that was already consumed (replay)."""
    code = _norm(code)
    if len(code) != 6 or not code.isdigit():
        return False
    totp = pyotp.TOTP(secret)
    now = _step()
    return any(step <= last_step and secrets.compare_digest(totp.at(step * 30), code)
               for step in (now - 1, now, now + 1))


def verify_user_code(user: User, code: str) -> bool:
    """Check a TOTP code for an enrolled user and consume its step."""
    if not user.mfa_enabled or not user.mfa_secret_enc:
        return False
    step = check_code(crypto.decrypt(user.mfa_secret_enc), code, user.mfa_last_step or 0)
    if step is None:
        return False
    # Claim the step in the database itself: of two requests racing with the same code only one wins.
    from sqlalchemy import update
    from sqlalchemy.orm import object_session

    sess = object_session(user)
    if sess is not None and user.id is not None:
        res = sess.execute(update(User).where(User.id == user.id, User.mfa_last_step < step).values(mfa_last_step=step)
                           .execution_options(synchronize_session=False))
        if res.rowcount != 1:
            return False
    user.mfa_last_step = step
    return True


def replayed(user: User, code: str) -> bool:
    if not user.mfa_enabled or not user.mfa_secret_enc:
        return False
    return code_was_used(crypto.decrypt(user.mfa_secret_enc), code, user.mfa_last_step or 0)


# --------------------------------------------------------------------------- #
# Enrollment
# --------------------------------------------------------------------------- #

def start_enrollment(user: User) -> str:
    """Create (or reuse) a pending secret for user and return it."""
    if user.mfa_pending_secret_enc:
        try:
            return crypto.decrypt(user.mfa_pending_secret_enc)
        except ValueError:
            pass
    secret = new_secret()
    user.mfa_pending_secret_enc = crypto.encrypt(secret)
    return secret


def finish_enrollment(user: User, code: str) -> list[str] | None:
    """Confirm the pending secret with a code. Returns new recovery codes, or None."""
    if not user.mfa_pending_secret_enc:
        return None
    secret = crypto.decrypt(user.mfa_pending_secret_enc)
    step = check_code(secret, code, 0)
    if step is None:
        return None
    user.mfa_secret_enc = user.mfa_pending_secret_enc
    user.mfa_pending_secret_enc = ""
    user.mfa_enabled = True
    user.mfa_last_step = step
    user.mfa_enabled_at = datetime.now(timezone.utc)
    return new_recovery_codes(user)


def disable(user: User) -> None:
    user.mfa_enabled = False
    user.mfa_secret_enc = ""
    user.mfa_pending_secret_enc = ""
    user.mfa_last_step = 0
    user.mfa_recovery_json = "[]"
    user.mfa_enabled_at = None


# --------------------------------------------------------------------------- #
# Recovery codes
# --------------------------------------------------------------------------- #

def _rc_hash(code: str) -> str:
    return hashlib.sha256(("pm-recovery:" + _norm(code).upper().replace("-", "")).encode()).hexdigest()


def new_recovery_codes(user: User) -> list[str]:
    codes = []
    for _ in range(RECOVERY_CODES):
        raw = "".join(secrets.choice(_RC_ALPHABET) for _ in range(10))  # ~50 bits
        codes.append(raw[:5] + "-" + raw[5:])
    user.mfa_recovery_json = json.dumps([_rc_hash(c) for c in codes])
    return codes


def recovery_left(user: User) -> int:
    try:
        return len(json.loads(user.mfa_recovery_json or "[]"))
    except ValueError:
        return 0


def use_recovery_code(user: User, code: str) -> bool:
    """Consume a recovery code. Each code works once."""
    if not user.mfa_enabled:
        return False
    try:
        hashes = json.loads(user.mfa_recovery_json or "[]")
    except ValueError:
        return False
    h = _rc_hash(code)
    old = user.mfa_recovery_json or "[]"
    for stored in hashes:
        if secrets.compare_digest(stored, h):
            hashes.remove(stored)
            new = json.dumps(hashes)
            # consume the code in the database itself (compare-and-swap on the list),
            # so two requests racing with the same code can't both succeed.
            from sqlalchemy import update
            from sqlalchemy.orm import object_session

            sess = object_session(user)
            if sess is not None and user.id is not None:
                res = sess.execute(update(User).where(User.id == user.id, User.mfa_recovery_json == old)
                                   .values(mfa_recovery_json=new).execution_options(synchronize_session=False))
                if res.rowcount != 1:
                    return False
            user.mfa_recovery_json = new
            return True
    return False


def looks_like_recovery(code: str) -> bool:
    c = _norm(code).replace("-", "")
    return len(c) == 10 and c.isalnum() and not c.isdigit()


# --------------------------------------------------------------------------- #
# Enrollment codes
# --------------------------------------------------------------------------- #
# An admin or technician who must use an authenticator can only set it up for the first time with a
# one-time code from an administrator (given out of band), so a stolen password alone can't be
# used to enroll the attacker's own phone before the real user does.

ENROLL_CODE_DAYS = 7
_EC_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _ec_hash(code: str) -> str:
    c = "".join(ch for ch in (code or "").upper() if ch.isalnum())
    return hashlib.sha256(("pm-enroll:" + c).encode()).hexdigest()


def new_enroll_code(user: User) -> str:
    """Set a fresh enrollment code (replaces any earlier one). Returns it for showing once."""
    from datetime import datetime, timedelta, timezone

    raw = "".join(secrets.choice(_EC_ALPHABET) for _ in range(10))
    user.enroll_code_hash = _ec_hash(raw)
    user.enroll_code_expires = datetime.now(timezone.utc) + timedelta(days=ENROLL_CODE_DAYS)
    return raw[:5] + "-" + raw[5:]


def enroll_code_pending(user: User) -> bool:
    from datetime import datetime, timezone

    exp = user.enroll_code_expires
    if not user.enroll_code_hash or exp is None:
        return False
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    return exp > datetime.now(timezone.utc)


def check_enroll_code(user: User, code: str) -> bool:
    return enroll_code_pending(user) and secrets.compare_digest(user.enroll_code_hash, _ec_hash(code))


def clear_enroll_code(user: User) -> None:
    user.enroll_code_hash = ""
    user.enroll_code_expires = None
