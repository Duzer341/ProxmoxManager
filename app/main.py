"""FastAPI application entry point.

Run with:  uvicorn app.main:app --host 0.0.0.0 --port 8080
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from . import __version__, events, stepup
from .auth import NotAuthenticated, hash_password
from .config import settings
from .database import db_session, init_db
from .models import User
from .poller import poller
from .routers import api, auth, console, pages
from .templating import render

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("app")


def _bootstrap_admin() -> None:
    """Create the initial admin from env vars if the users table is empty."""
    with db_session() as db:
        if db.query(User).count() > 0:
            return
        if settings.INITIAL_ADMIN_USERNAME and settings.INITIAL_ADMIN_PASSWORD:
            db.add(
                User(
                    username=settings.INITIAL_ADMIN_USERNAME,
                    password_hash=hash_password(settings.INITIAL_ADMIN_PASSWORD),
                    role="admin",
                )
            )
            log.warning(
                "Created initial admin user '%s' from PM_INITIAL_ADMIN_*; remove those lines from .env now.",
                settings.INITIAL_ADMIN_USERNAME,
            )
        else:
            log.warning("No users exist yet. Create one with: python manage.py create-admin <username>")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _single_instance_lock()
    init_db()
    from . import crypto

    crypto.migrate()          # re-encrypt credentials still using the pre-1.3.0 key derivation
    _bootstrap_admin()
    from .consoles import close_orphans

    close_orphans()
    await poller.start()
    log.info("Proxmox Manager %s started on %s:%s", __version__, settings.HOST, settings.PORT)
    events.event("system", "service.start", "info", details={"version": __version__, "listen": f"{settings.HOST}:{settings.PORT}",
                                                             "stepup_minutes": settings.STEPUP_MINUTES,
                                                             "console_idle_minutes": settings.CONSOLE_IDLE_MINUTES,
                                                             "console_max_seconds": settings.CONSOLE_MAX_SECONDS})
    try:
        yield
    finally:
        await poller.stop()
        events.event("system", "service.stop", "info", details={"version": __version__})


_instance_lock_file = None


def _session_signing_key() -> str:
    from . import crypto

    return crypto.derive_key("pm-session-cookie/v1").hex()


def _single_instance_lock() -> None:
    """Sign-in throttling, session revocation, console re-auth windows and open
    consoles live in this process. A second process (uvicorn --workers N, or a second service on the
    same data directory) would not see them, so it refuses to start."""
    import fcntl

    global _instance_lock_file
    f = open(Path(settings.DATA_DIR) / ".instance.lock", "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        raise RuntimeError("Another Proxmox Manager process is already running on this data directory. Run a single "
                           "process (no --workers): sign-in limits, session revocation and consoles are kept in memory.")
    _instance_lock_file = f


app = FastAPI(title="Proxmox Manager", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None,
              openapi_url=None)   # no unauthenticated API map / version

# Order (outermost first): SecurityHeaders -> Session -> EventLog -> routes. The event log sits
# inside the session middleware so it knows who is signed in.
app.add_middleware(events.EventLogMiddleware)
app.add_middleware(
    SessionMiddleware,
    # signed with a key derived through scrypt, so a session cookie can't be used to test guesses
    # of PM_SECRET_KEY at full speed
    secret_key=_session_signing_key(),
    session_cookie="pm_session",
    max_age=settings.SESSION_MAX_AGE,
    same_site="lax",
    https_only=settings.SESSION_COOKIE_SECURE,
)


class SecurityHeadersMiddleware:
    """Every response carries a Content-Security-Policy. Pages rendered from
    templates set their own (with the per-request script nonce); everything else (JSON, redirects,
    static files, refusals) gets a policy that allows nothing to run or embed it."""

    DEFAULT = b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def _send(msg):
            if msg["type"] == "http.response.start":
                headers = list(msg.get("headers") or [])
                if not any(k.lower() == b"content-security-policy" for k, _ in headers):
                    headers.append((b"content-security-policy", self.DEFAULT))
                msg["headers"] = headers
            await send(msg)

        await self.app(scope, receive, _send)


app.add_middleware(SecurityHeadersMiddleware)

app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

app.include_router(auth.router)
app.include_router(pages.router)
app.include_router(api.router)
app.include_router(console.api)
app.include_router(console.pages)


@app.exception_handler(NotAuthenticated)
async def _not_authenticated(request: Request, _exc: NotAuthenticated):
    nxt = request.url.path
    if request.url.query:
        nxt += "?" + request.url.query
    return RedirectResponse(f"/login?next={quote(nxt, safe='')}", status_code=303)


@app.exception_handler(stepup.StepUpRequired)
async def _stepup_required(request: Request, exc: stepup.StepUpRequired):
    return JSONResponse({"detail": exc.message, "stepup_required": True, "methods": exc.methods,
                         "window_minutes": round(stepup.window_seconds() / 60, 1)}, status_code=403)


@app.exception_handler(StarletteHTTPException)
async def _http_error(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))
    if exc.status_code in (403, 404):
        return render(
            request,
            "error.html",
            {"status_code": exc.status_code, "detail": exc.detail, "page": "error"},
            status_code=exc.status_code,
        )
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


@app.get("/healthz", include_in_schema=False)
def healthz(request: Request):
    # the exact version only for checks on the server itself (install.sh, monitoring there)
    client = (request.client.host if request.client else "") or ""
    if client in ("127.0.0.1", "::1"):
        return {"ok": True, "version": __version__}
    return {"ok": True}
