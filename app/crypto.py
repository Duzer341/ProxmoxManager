"""Encrypt / decrypt Proxmox credentials at rest using a key derived from PM_SECRET_KEY."""

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from .config import settings


def _fernet() -> Fernet:
    digest = hashlib.sha256(("pm-credential-key:" + settings.SECRET_KEY).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


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
