"""Login / logout pages."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..auth import get_current_user_optional, login_user, logout_user, verify_password
from ..database import get_db
from ..models import User
from ..templating import render

router = APIRouter()


@router.get("/login")
def login_page(request: Request, user: User | None = Depends(get_current_user_optional)):
    if user:
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html", {"error": "", "next": request.query_params.get("next", "/")})


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form("/"),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == username.strip()).first()
    if not user or not user.is_active or not verify_password(password, user.password_hash):
        return render(
            request,
            "login.html",
            {"error": "Invalid username or password.", "next": next},
            status_code=401,
        )
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    login_user(request, user)
    # Only allow local redirects.
    target = next if next.startswith("/") and not next.startswith("//") else "/"
    return RedirectResponse(target, status_code=303)


@router.post("/logout")
def logout(request: Request):
    logout_user(request)
    return RedirectResponse("/login", status_code=303)
