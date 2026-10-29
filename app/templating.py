"""Jinja2 setup and shared template helpers."""

from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

from . import __version__
from .config import settings

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def fmt_bytes(num: float | int | None) -> str:
    if not num:
        return "0 B"
    num = float(num)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(num) < 1024.0:
            return f"{num:.1f} {unit}" if unit not in ("B",) else f"{int(num)} {unit}"
        num /= 1024.0
    return f"{num:.1f} EiB"


def fmt_uptime(seconds: int | None) -> str:
    if not seconds:
        return "-"
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


templates.env.filters["bytes"] = fmt_bytes
templates.env.filters["uptime"] = fmt_uptime
def _asset_tag() -> str:
    """Cache-busting tag for app.css / app.js: a hash of their content, so pages (including the
    sign-in page) don't reveal the version."""
    import hashlib

    h = hashlib.sha256()
    for name in ("app.css", "app.js"):
        try:
            h.update((Path(__file__).parent / "static" / name).read_bytes())
        except OSError:
            h.update(__version__.encode())
    return h.hexdigest()[:12]


templates.env.globals["app_version"] = _asset_tag()
templates.env.globals["show_pve_links"] = settings.SHOW_PVE_LINKS


THEMES = ("dark", "light", "system")
THEME_COOKIE = "pm_theme"   # copy of the account's theme, only so the sign-in page matches


def clean_theme(value) -> str:
    return value if value in THEMES else "dark"


def theme_cookie(response, theme: str) -> None:
    response.set_cookie(THEME_COOKIE, clean_theme(theme), max_age=365 * 86400, path="/", httponly=True,
                        samesite="lax", secure=settings.SESSION_COOKIE_SECURE)


def csp_for_page(nonce: str) -> str:
    """Defence in depth: only the dashboard's own scripts and the inline
    scripts of this page (nonce) run; no framing, no plugins, no foreign form targets."""
    return ("default-src 'self'; script-src 'self' 'nonce-" + nonce + "'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'")


def render(request: Request, name: str, context: dict | None = None, status_code: int = 200):
    import secrets

    nonce = secrets.token_urlsafe(16)
    ctx = {"request": request, "csp_nonce": nonce}
    user = getattr(request.state, "user", None)
    ctx["current_user"] = user
    # One-time notice set during sign-in (e.g. "you used a recovery code").
    ctx["notice"] = request.session.pop("notice", None) if user is not None and "session" in request.scope else None
    if context:
        ctx.update(context)
    user = ctx.get("current_user")
    cookie_theme = request.cookies.get(THEME_COOKIE)
    ctx["theme"] = clean_theme(getattr(user, "theme", None) if user is not None else cookie_theme)
    resp = templates.TemplateResponse(request, name, ctx, status_code=status_code)
    resp.headers["Content-Security-Policy"] = csp_for_page(nonce)
    if user is not None and cookie_theme != ctx["theme"]:
        theme_cookie(resp, ctx["theme"])
    return resp
