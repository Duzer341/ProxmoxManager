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
    # Per-request timeout to a Proxmox host, seconds.
    PVE_TIMEOUT: int = _int("PM_PVE_TIMEOUT", 15)
    # How many hosts to poll concurrently.
    POLL_WORKERS: int = _int("PM_POLL_WORKERS", 8)
    # Keep stat samples for this many hours (used for rolling averages).
    SAMPLE_RETENTION_HOURS: int = _int("PM_SAMPLE_RETENTION_HOURS", 24)
    # Window for the "average" figures shown on the dashboard, minutes.
    AVERAGE_WINDOW_MINUTES: int = _int("PM_AVERAGE_WINDOW_MINUTES", 60)

    # Session cookie settings. Set SECURE to true once you're behind HTTPS.
    SESSION_COOKIE_SECURE: bool = _bool("PM_SESSION_COOKIE_SECURE", False)
    SESSION_MAX_AGE: int = _int("PM_SESSION_MAX_AGE", 12 * 3600)

    # Optional: create this admin on first start if no users exist yet.
    INITIAL_ADMIN_USERNAME: str = os.environ.get("PM_INITIAL_ADMIN_USERNAME", "")
    INITIAL_ADMIN_PASSWORD: str = os.environ.get("PM_INITIAL_ADMIN_PASSWORD", "")

    LOG_LEVEL: str = os.environ.get("PM_LOG_LEVEL", "INFO")

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


settings = Settings()
