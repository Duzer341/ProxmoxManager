"""HTML pages. All data is loaded client-side from /api/*."""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..auth import require_admin, require_user
from ..database import get_db
from ..models import ProxmoxHost, User
from ..templating import render

router = APIRouter()


@router.get("/")
def dashboard(request: Request, user: User = Depends(require_user)):
    return render(request, "dashboard.html", {"page": "dashboard"})


@router.get("/hosts/{host_id}")
def host_page(request: Request, host_id: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    host = db.get(ProxmoxHost, host_id)
    if host is None:
        raise HTTPException(404, "Host not found")
    return render(request, "host.html", {"page": "host", "host": host})


@router.get("/manage/hosts")
def manage_hosts(request: Request, user: User = Depends(require_admin)):
    return render(request, "hosts.html", {"page": "hosts"})


@router.get("/manage/users")
def manage_users(request: Request, user: User = Depends(require_admin)):
    return render(request, "users.html", {"page": "users"})


@router.get("/account")
def account(request: Request, user: User = Depends(require_user)):
    return render(request, "account.html", {"page": "account"})
