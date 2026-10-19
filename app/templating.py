"""Jinja2 setup and shared template helpers."""

from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

from . import __version__

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
templates.env.globals["app_version"] = __version__


def render(request: Request, name: str, context: dict | None = None, status_code: int = 200):
    ctx = {"request": request}
    user = getattr(request.state, "user", None)
    ctx["current_user"] = user
    if context:
        ctx.update(context)
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)
