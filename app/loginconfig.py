"""Sign-in configuration: which login mode is active and the Entra ID settings.

Stored in the app_settings table so it can be changed with `manage.py configure-login`
without editing .env. The Entra client secret is Fernet-encrypted like other credentials.

Modes:
    local  username and password only
    mfa    username and password plus an authenticator-app code (TOTP); required for
           admins and technicians, optional for viewers
    entra  "Sign in with Microsoft" (Entra ID, OpenID Connect). Local accounts remain
           available as break-glass and follow the mfa rules.
"""

import re
from dataclasses import dataclass

from sqlalchemy.orm import Session

from . import crypto
from .models import AppSetting, User

MODES = ("local", "mfa", "entra")
MODE_LABELS = {
    "local": "Username and password",
    "mfa": "Username and password with authenticator app (MFA)",
    "entra": "Microsoft Entra ID single sign-on",
}
DEFAULT_AUTHORITY = "https://login.microsoftonline.com"
CALLBACK_PATH = "/auth/entra/callback"

GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
DOMAIN_RE = re.compile(r"^(?=.{3,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")

_KEYS = {
    "mode": "login_mode",
    "tenant": "entra_tenant",
    "client_id": "entra_client_id",
    "secret": "entra_client_secret_enc",
    "redirect_uri": "entra_redirect_uri",
    "authority": "entra_authority",
}


@dataclass
class LoginConfig:
    mode: str = "local"
    configured: bool = False  # False until configure-login has run once
    tenant: str = ""
    client_id: str = ""
    client_secret: str = ""
    redirect_uri: str = ""
    authority: str = DEFAULT_AUTHORITY

    @property
    def mfa_available(self) -> bool:
        return self.mode in ("mfa", "entra")

    @property
    def sso_enabled(self) -> bool:
        return self.mode == "entra"

    @property
    def entra_ready(self) -> bool:
        return bool(self.tenant and self.client_id and self.client_secret and self.redirect_uri)

    def mfa_required(self, user: User) -> bool:
        """Local admins and technicians must use MFA in the mfa and entra modes."""
        return self.mfa_available and not user.is_sso and user.role in ("admin", "technician")


def _get(db: Session, key: str) -> str | None:
    row = db.get(AppSetting, key)
    return row.value if row else None


def _set(db: Session, key: str, value: str) -> None:
    row = db.get(AppSetting, key)
    if row is None:
        db.add(AppSetting(key=key, value=value))
    else:
        row.value = value


def load(db: Session) -> LoginConfig:
    mode = _get(db, _KEYS["mode"])
    cfg = LoginConfig(mode=mode if mode in MODES else "local", configured=mode in MODES)
    cfg.tenant = _get(db, _KEYS["tenant"]) or ""
    cfg.client_id = _get(db, _KEYS["client_id"]) or ""
    enc = _get(db, _KEYS["secret"]) or ""
    if enc:
        try:
            cfg.client_secret = crypto.decrypt(enc)
        except ValueError:
            cfg.client_secret = ""
    cfg.redirect_uri = _get(db, _KEYS["redirect_uri"]) or ""
    cfg.authority = (_get(db, _KEYS["authority"]) or DEFAULT_AUTHORITY).rstrip("/")
    return cfg


def validate_entra(tenant: str, client_id: str, redirect_uri: str, authority: str = DEFAULT_AUTHORITY) -> str | None:
    """Return an error message, or None if the Entra settings are usable."""
    if tenant.lower() in ("common", "organizations", "consumers"):
        return "Use your own tenant ID (single tenant), not 'common', 'organizations' or 'consumers'."
    if not (GUID_RE.match(tenant) or DOMAIN_RE.match(tenant)):
        return "Tenant must be the directory (tenant) ID, e.g. 00000000-0000-0000-0000-000000000000, or a verified domain."
    if not GUID_RE.match(client_id):
        return "Client ID must be the application (client) ID GUID from the app registration."
    if not redirect_uri.startswith("https://") or not redirect_uri.endswith(CALLBACK_PATH):
        return f"Redirect URI must be https://<dashboard address>{CALLBACK_PATH}."
    if not authority.startswith("https://"):
        return "Authority must be an https URL."
    return None


def save(db: Session, mode: str, tenant: str = "", client_id: str = "", client_secret: str | None = None,
         redirect_uri: str = "", authority: str = "") -> None:
    """Persist the configuration. client_secret None keeps the stored secret."""
    if mode not in MODES:
        raise ValueError(f"Mode must be one of {', '.join(MODES)}")
    _set(db, _KEYS["mode"], mode)
    if mode == "entra" or tenant or client_id:
        _set(db, _KEYS["tenant"], tenant.strip())
        _set(db, _KEYS["client_id"], client_id.strip())
        _set(db, _KEYS["redirect_uri"], redirect_uri.strip())
        _set(db, _KEYS["authority"], (authority or DEFAULT_AUTHORITY).strip().rstrip("/"))
    if client_secret is not None:
        _set(db, _KEYS["secret"], crypto.encrypt(client_secret) if client_secret else "")
    db.commit()


def redirect_uri_for(base_url: str) -> str:
    return base_url.strip().rstrip("/") + CALLBACK_PATH
