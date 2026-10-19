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

from . import __version__
from .auth import NotAuthenticated, hash_password
from .config import settings
from .database import db_session, init_db
from .models import User
from .poller import poller
from .routers import api, auth, pages
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
    init_db()
    _bootstrap_admin()
    await poller.start()
    log.info("Proxmox Manager %s started on %s:%s", __version__, settings.HOST, settings.PORT)
    try:
        yield
    finally:
        await poller.stop()


app = FastAPI(title="Proxmox Manager", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    session_cookie="pm_session",
    max_age=settings.SESSION_MAX_AGE,
    same_site="lax",
    https_only=settings.SESSION_COOKIE_SECURE,
)

app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

app.include_router(auth.router)
app.include_router(pages.router)
app.include_router(api.router)


@app.exception_handler(NotAuthenticated)
async def _not_authenticated(request: Request, _exc: NotAuthenticated):
    nxt = request.url.path
    if request.url.query:
        nxt += "?" + request.url.query
    return RedirectResponse(f"/login?next={quote(nxt, safe='')}", status_code=303)


@app.exception_handler(StarletteHTTPException)
async def _http_error(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    if exc.status_code in (403, 404):
        return render(
            request,
            "error.html",
            {"status_code": exc.status_code, "detail": exc.detail, "page": "error"},
            status_code=exc.status_code,
        )
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"ok": True, "version": __version__}
