"""Application settings, loaded from environment variables / .env file."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Tiny .env loader so we don't need python-dotenv. Does not override existing env."""
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        os.environ.setdefault(key, value)


_load_dotenv(Path(os.environ.get("PM_ENV_FILE", BASE_DIR / ".env")))


def _bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


class Settings:
    # Used to sign session cookies AND to derive the key that encrypts stored
    # Proxmox credentials. Changing it invalidates sessions and makes stored
    # credentials unreadable, so keep it stable and keep it secret.
    SECRET_KEY: str = os.environ.get("PM_SECRET_KEY", "")

    DATA_DIR: Path = Path(os.environ.get("PM_DATA_DIR", BASE_DIR / "data"))
    DATABASE_URL: str = os.environ.get("PM_DATABASE_URL", "")

    HOST: str = os.environ.get("PM_HOST", "0.0.0.0")
    PORT: int = _int("PM_PORT", 8080)

    # Seconds between background polls of every Proxmox host.
    POLL_INTERVAL: int = _int("PM_POLL_INTERVAL", 60)
    # Microsoft (Entra) sign-ins go back through Microsoft after this many minutes, so a
    # removed or lowered app role takes effect (normally seamless while the Microsoft session is valid)
    ENTRA_RECHECK_MINUTES: float = _float("PM_ENTRA_RECHECK_MINUTES", 60.0)
    # How often each guest's config is re-read for its full disk list (seconds)
    GUEST_DISK_REFRESH: int = _int("PM_GUEST_DISK_REFRESH", 300)
    # Per-request timeout to a Proxmox host, seconds.
    PVE_TIMEOUT: int = _int("PM_PVE_TIMEOUT", 15)
    # How many hosts to poll concurrently.
    POLL_WORKERS: int = _int("PM_POLL_WORKERS", 8)
    # Keep stat samples for this many hours (used for rolling averages).
    SAMPLE_RETENTION_HOURS: int = _int("PM_SAMPLE_RETENTION_HOURS", 24)
    # Window for the "average" figures shown on the dashboard, minutes.
    AVERAGE_WINDOW_MINUTES: int = _int("PM_AVERAGE_WINDOW_MINUTES", 60)

    # Session cookie settings. Secure (HTTPS only) by default; set false only for a plain-HTTP test setup.
    SESSION_COOKIE_SECURE: bool = _bool("PM_SESSION_COOKIE_SECURE", True)
    SESSION_MAX_AGE: int = _int("PM_SESSION_MAX_AGE", 12 * 3600)

    # Optional: create this admin on first start if no users exist yet.
    INITIAL_ADMIN_USERNAME: str = os.environ.get("PM_INITIAL_ADMIN_USERNAME", "")
    INITIAL_ADMIN_PASSWORD: str = os.environ.get("PM_INITIAL_ADMIN_PASSWORD", "")

    LOG_LEVEL: str = os.environ.get("PM_LOG_LEVEL", "INFO")

    # Show "Open PVE web UI" links (browsers then go to the hosts directly). Set false when
    # browsers can't reach the hosts and everything goes through the dashboard.
    SHOW_PVE_LINKS: bool = _bool("PM_SHOW_PVE_LINKS", True)
    # Console relay: seconds a console page has to connect, and the longest a session may run.
    CONSOLE_CONNECT_SECONDS: int = _int("PM_CONSOLE_CONNECT_SECONDS", 120)
    # Hard cap and idle close. Idle = no keystrokes and no output
    # for terminals / container consoles (a running upgrade keeps it open), no keyboard or
    # mouse input for VM consoles.
    CONSOLE_MAX_SECONDS: int = _int("PM_CONSOLE_MAX_SECONDS", 2 * 3600)
    CONSOLE_IDLE_MINUTES: float = _float("PM_CONSOLE_IDLE_MINUTES", 15)

    # --- Fresh re-auth ("step-up") before any console ---
    # After a re-auth (authenticator code, or a forced fresh Microsoft sign-in) consoles can be
    # opened for this many minutes. The window does not extend with use.
    STEPUP_MINUTES: float = _float("PM_STEPUP_MINUTES", 15)
    # Optional: Entra Conditional Access authentication context ID (e.g. c1) to demand at the
    # console re-auth. Needs Entra ID P1 and a CA policy targeting that context. Empty = a
    # forced fresh sign-in (prompt=login, max_age=0) is required instead.
    ENTRA_STEPUP_ACR: str = os.environ.get("PM_ENTRA_STEPUP_ACR", "").strip()

    # Console log rows (who opened which console, when, for how long) are kept this many days.
    CONSOLE_LOG_RETENTION_DAYS: int = _int("PM_CONSOLE_LOG_RETENTION_DAYS", 365)

    def __init__(self) -> None:
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        if not self.DATABASE_URL:
            self.DATABASE_URL = f"sqlite:///{self.DATA_DIR / 'proxmox-manager.db'}"
        if not self.SECRET_KEY:
            raise RuntimeError(
                "PM_SECRET_KEY is not set. Generate one with: "
                "python3 -c 'import secrets; print(secrets.token_urlsafe(48))' "
                "and put it in the .env file."
            )
        if len(self.SECRET_KEY) < 32 or len(set(self.SECRET_KEY)) < 12:
            # stored client credentials are encrypted with a key derived from it
            raise RuntimeError(
                "PM_SECRET_KEY is too short or too simple (at least 32 characters, 12 different). It protects the stored Proxmox "
                "credentials. Changing it makes them unreadable, so if this is an existing installation "
                "re-enter the host credentials afterwards. Generate one with: "
                "python3 -c 'import secrets; print(secrets.token_urlsafe(48))'"
            )


settings = Settings()
