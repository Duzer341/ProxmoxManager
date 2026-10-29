"""Sign-in pages: password, authenticator-app (TOTP) step, MFA enrollment, Entra ID SSO."""

import logging
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from urllib.parse import quote

from .. import auth_device, entra, events, loginconfig, mfa, ratelimit, stepup
from ..events import note
from ..auth import (SSO_RECHECK_KEY, get_current_user_optional, hash_password, login_user, logout_user, session_id,
                    validate_password_strength, verify_password)
from ..config import settings
from ..permissions import role_can
from ..database import get_db
from ..models import User
from ..templating import render

router = APIRouter()
log = logging.getLogger("app.auth")

MFA_PENDING_KEY = "mfa_pending"   # {"uid", "ts", "next", "fails", "enroll"}
SSO_PENDING_KEY = "sso_pending"   # {"state", "nonce", "verifier", "ts", "next"}
PW_PENDING_KEY = "pw_pending"     # {"uid", "ts", "next", "amr", "uk"} (new password after sign-in)
MFA_PENDING_SECONDS = 5 * 60
PW_PENDING_SECONDS = 15 * 60
SSO_PENDING_SECONDS = 10 * 60
MFA_MAX_FAILS = 5


def _safe_next(nxt: str | None) -> str:
    nxt = nxt or "/"
    return nxt if nxt.startswith("/") and not nxt.startswith("//") and "\\" not in nxt else "/"


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _login_page(request: Request, cfg: loginconfig.LoginConfig, error: str = "", nxt: str = "/",
                show_local: bool | None = None, status_code: int = 200, username: str = ""):
    if show_local is None:
        show_local = not cfg.sso_enabled or request.query_params.get("local") == "1"
    return render(request, "login.html", {
        "error": error, "next": _safe_next(nxt), "sso": cfg.sso_enabled, "sso_ready": cfg.entra_ready,
        "show_local": show_local, "username": username,
    }, status_code=status_code)


def _finish(request: Request, db: Session, user: User, amr: str, nxt: str) -> RedirectResponse:
    """Password (and authenticator) proven. A password set by an administrator is replaced first."""
    if user.must_change_password and not user.is_sso:
        ratelimit.success(user.username, _ip(request))
        request.session.clear()
        request.session[PW_PENDING_KEY] = {"uid": user.id, "ts": int(time.time()), "next": _safe_next(nxt),
                                           "amr": amr, "uk": user.session_key}
        log.info("sign-in needs a new password user=%s method=%s ip=%s", user.username, amr, _ip(request))
        note(request, category="auth", action="login.password", outcome="ok", user=user,
             details={"next_step": "set a new password (set by an administrator)"})
        return RedirectResponse("/login/password", status_code=303)
    return _complete(request, db, user, amr, nxt)


def _complete(request: Request, db: Session, user: User, amr: str, nxt: str) -> RedirectResponse:
    user.last_login_at = datetime.now(timezone.utc)
    if not user.session_key:
        user.rotate_session_key()
    db.commit()
    ratelimit.success(user.username, _ip(request))
    login_user(request, user, amr)
    log.info("sign-in ok user=%s method=%s ip=%s", user.username, amr, _ip(request))
    note(request, category="auth", action={"pwd": "login", "mfa": "login.mfa", "sso": "login.entra"}.get(amr, "login"),
         outcome="ok", user=user, details={"method": {"pwd": "password", "mfa": "password + authenticator",
                                                       "sso": "Microsoft Entra ID"}.get(amr, amr)})
    resp = RedirectResponse(_safe_next(nxt), status_code=303)
    auth_device.issue(resp, user)
    return resp


def _who(db: Session, typed: str) -> dict:
    """Audit identity for a sign-in attempt: the account if it exists, else a masked username."""
    u = db.query(User).filter(User.username == typed).first() if typed else None
    return {"user": u} if u else {"username": events.mask_username(typed)}


def _pending(request: Request, db: Session) -> tuple[dict | None, User | None]:
    p = request.session.get(MFA_PENDING_KEY)
    if not p or time.time() - p.get("ts", 0) > MFA_PENDING_SECONDS:
        request.session.pop(MFA_PENDING_KEY, None)
        return None, None
    user = db.get(User, p.get("uid"))
    if user is None or not user.is_active or user.is_sso:
        request.session.pop(MFA_PENDING_KEY, None)
        return None, None
    return p, user


# --------------------------------------------------------------------------- #
# Password
# --------------------------------------------------------------------------- #

@router.get("/login")
def login_page(request: Request, user: User | None = Depends(get_current_user_optional), db: Session = Depends(get_db)):
    if user:
        return RedirectResponse("/", status_code=303)
    cfg = loginconfig.load(db)
    nxt = request.query_params.get("next", "/")
    if request.session.pop(SSO_RECHECK_KEY, None) and cfg.sso_enabled and cfg.entra_ready:
        # an aged-out Microsoft sign-in goes straight back through Microsoft
        note(request, category="auth", action="login.entra.recheck")
        return RedirectResponse("/auth/entra/login?next=" + quote(_safe_next(nxt), safe=""), status_code=303)
    return _login_page(request, cfg, nxt=nxt)


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form("/"),
    db: Session = Depends(get_db),
):
    cfg = loginconfig.load(db)
    username = username.strip()
    ip = _ip(request)
    note(request, category="auth", action="login.failed")
    user = db.query(User).filter(User.username == username).first()
    wait = ratelimit.locked(username, ip, known_device=auth_device.known(request, user))
    if wait:
        log.warning("sign-in blocked (rate limit) user=%s ip=%s", events.mask_username(username), ip)
        note(request, outcome="denied", details={"reason": "locked out after too many failed attempts", "wait_seconds": wait},
             **_who(db, username))
        when = f"{wait} seconds" if wait < 120 else f"{wait // 60} minutes"
        return _login_page(request, cfg, f"Too many failed sign-in attempts. Try again in {when}.",
                           next, show_local=True, status_code=429, username=username)
    if not user or not user.is_active or user.is_sso or not verify_password(password, user.password_hash):
        ratelimit.failure(username, ip)
        log.warning("sign-in failed user=%s ip=%s", username if user else events.mask_username(username), ip)
        why = ("unknown username" if not user else "account disabled" if not user.is_active
               else "Microsoft account tried the password form" if user.is_sso else "wrong password")
        note(request, outcome="failed", details={"reason": why}, **({"user": user} if user else _who(db, username)))
        msg = "Invalid username or password."
        if user and user.is_sso and user.is_active:
            msg = "This account signs in with Microsoft. Use “Sign in with Microsoft”."
        return _login_page(request, cfg, msg, next, show_local=True, status_code=401, username=username)

    if cfg.mfa_available and (user.mfa_enabled or cfg.mfa_required(user)):
        request.session.clear()
        request.session[MFA_PENDING_KEY] = {"uid": user.id, "ts": int(time.time()), "next": _safe_next(next),
                                            "fails": 0, "enroll": not user.mfa_enabled}
        note(request, action="login.password", outcome="ok", user=user,
             details={"next_step": "authenticator code" if user.mfa_enabled else "authenticator enrollment (required)"})
        return RedirectResponse("/login/mfa/setup" if not user.mfa_enabled else "/login/mfa", status_code=303)
    return _finish(request, db, user, "pwd", next)


# --------------------------------------------------------------------------- #
# Authenticator code
# --------------------------------------------------------------------------- #

@router.get("/login/mfa")
def mfa_page(request: Request, db: Session = Depends(get_db)):
    p, user = _pending(request, db)
    if not p or p.get("enroll"):
        return RedirectResponse("/login/mfa/setup" if p else "/login", status_code=303)
    return render(request, "login_mfa.html", {"error": "", "username": user.username})


@router.post("/login/mfa")
def mfa_submit(request: Request, code: str = Form(""), db: Session = Depends(get_db)):
    p, user = _pending(request, db)
    if not p or p.get("enroll"):
        note(request, category="auth", action="login.mfa.failed", outcome="denied", details={"reason": "no pending sign-in"})
        return RedirectResponse("/login", status_code=303)
    ip = _ip(request)
    note(request, category="auth", action="login.mfa.failed", user=user)
    if ratelimit.locked(user.username, ip, known_device=auth_device.known(request, user)):
        note(request, outcome="denied", details={"reason": "locked out after too many failed attempts"})
        request.session.clear()
        return _login_page(request, loginconfig.load(db), "Too many failed sign-in attempts. Try again later.",
                           p.get("next", "/"), show_local=True, status_code=429)
    code = code.strip()
    used_recovery = False
    if mfa.looks_like_recovery(code):
        ok = used_recovery = mfa.use_recovery_code(user, code)
    else:
        ok = mfa.verify_user_code(user, code)
    if ok:
        db.commit()
        if used_recovery:
            log.warning("recovery code used user=%s left=%d ip=%s", user.username, mfa.recovery_left(user), ip)
        resp = _finish(request, db, user, "mfa", p.get("next", "/"))
        if used_recovery:
            note(request, details={"recovery_code_used": True, "recovery_codes_left": mfa.recovery_left(user)})
            request.session["notice"] = (f"You signed in with a recovery code. {mfa.recovery_left(user)} left. "
                                         "Create new ones on your Account page if you are running low.")
        return resp
    replay = mfa.replayed(user, code)
    ratelimit.failure(user.username, ip)
    p["fails"] = p.get("fails", 0) + 1
    log.warning("mfa failed user=%s ip=%s%s", user.username, ip, " (code reused)" if replay else "")
    note(request, outcome="failed", details={"reason": "invalid recovery code" if mfa.looks_like_recovery(code)
                                             else "reused code" if replay else "wrong code", "attempt": p["fails"]})
    if p["fails"] >= MFA_MAX_FAILS:
        note(request, details={"signed_out": "too many wrong codes"})
        request.session.clear()
        return _login_page(request, loginconfig.load(db), "Too many wrong codes. Sign in again.", p.get("next", "/"),
                           show_local=True, status_code=401)
    request.session[MFA_PENDING_KEY] = p
    if mfa.looks_like_recovery(code):
        err = "That recovery code isn't valid or was already used."
    elif replay:
        err = "That code was already used. Wait for the next code in your app."
    else:
        err = "Wrong code. Check the time on your phone and try the current code."
    return render(request, "login_mfa.html", {"error": err, "username": user.username}, status_code=401)


# --------------------------------------------------------------------------- #
# Forced enrollment (admins in the mfa / entra modes)
# --------------------------------------------------------------------------- #

@router.get("/login/mfa/setup")
def mfa_setup_page(request: Request, db: Session = Depends(get_db)):
    p, user = _pending(request, db)
    if not p:
        return RedirectResponse("/login", status_code=303)
    if not p.get("enroll"):
        return RedirectResponse("/login/mfa", status_code=303)
    if not mfa.enroll_code_pending(user):
        # first setup of a required authenticator needs an admin-issued enrollment code
        note(request, category="auth", action="mfa.enroll.blocked", outcome="denied", user=user,
             details={"reason": "no valid enrollment code"})
        request.session.pop(MFA_PENDING_KEY, None)
        return render(request, "login_mfa_setup.html", {"no_code": True, "username": user.username}, status_code=403)
    secret = mfa.start_enrollment(user)
    db.commit()
    uri = mfa.provisioning_uri(secret, user.username)
    return render(request, "login_mfa_setup.html", {"error": "", "username": user.username, "secret": secret,
                                                     "qr": mfa.qr_svg(uri)})


@router.post("/login/mfa/setup")
def mfa_setup_submit(request: Request, code: str = Form(""), enroll_code: str = Form(""), db: Session = Depends(get_db)):
    p, user = _pending(request, db)
    if not p or not p.get("enroll"):
        return RedirectResponse("/login", status_code=303)
    if not mfa.enroll_code_pending(user):
        note(request, category="auth", action="mfa.enroll.blocked", outcome="denied", user=user,
             details={"reason": "no valid enrollment code"})
        request.session.pop(MFA_PENDING_KEY, None)
        return render(request, "login_mfa_setup.html", {"no_code": True, "username": user.username}, status_code=403)
    if ratelimit.locked(user.username, _ip(request), known_device=auth_device.known(request, user)):
        request.session.clear()
        return _login_page(request, loginconfig.load(db), "Too many failed sign-in attempts. Try again later.", "/",
                           show_local=True, status_code=429)
    code_ok = mfa.check_enroll_code(user, enroll_code)
    codes = mfa.finish_enrollment(user, code) if code_ok else None
    if codes is None:
        note(request, category="auth", action="mfa.enroll.failed", outcome="failed", user=user,
             details={"reason": "wrong code" if code_ok else "wrong enrollment code"})
        p["fails"] = p.get("fails", 0) + 1
        ratelimit.failure(user.username, _ip(request))
        if p["fails"] >= MFA_MAX_FAILS:
            request.session.clear()
            return _login_page(request, loginconfig.load(db), "Too many wrong codes. Sign in again.", "/",
                               show_local=True, status_code=401)
        request.session[MFA_PENDING_KEY] = p
        secret = mfa.start_enrollment(user)
        db.commit()
        return render(request, "login_mfa_setup.html", {
            "error": ("That code didn't match. Make sure you scanned this QR code and enter the current 6-digit code."
                      if code_ok else "That enrollment code isn't valid. Check it with your administrator."),
            "username": user.username, "secret": secret,
            "qr": mfa.qr_svg(mfa.provisioning_uri(secret, user.username))}, status_code=400)
    mfa.clear_enroll_code(user)   # works once
    db.commit()
    log.info("mfa enrolled user=%s ip=%s", user.username, _ip(request))
    nxt = p.get("next", "/")
    _finish(request, db, user, "mfa", nxt)
    note(request, details={"authenticator_enrolled": True})
    if request.session.get(PW_PENDING_KEY):
        # recovery codes first, then the new password (the device cookie comes with the session)
        return render(request, "mfa_codes.html", {"codes": codes, "next": "/login/password", "first": True})
    resp = render(request, "mfa_codes.html", {"codes": codes, "next": _safe_next(nxt), "first": True})
    auth_device.issue(resp, user)
    return resp


# --------------------------------------------------------------------------- #
# New password after sign-in (password set by an administrator)
# --------------------------------------------------------------------------- #

def _pw_pending(request: Request, db: Session) -> tuple[dict | None, User | None]:
    p = request.session.get(PW_PENDING_KEY)
    if not p or time.time() - p.get("ts", 0) > PW_PENDING_SECONDS:
        request.session.pop(PW_PENDING_KEY, None)
        return None, None
    user = db.get(User, p.get("uid"))
    # the account must be unchanged since the password (and code) were checked
    if (user is None or not user.is_active or user.is_sso or not user.must_change_password
            or user.session_key != p.get("uk")):
        request.session.pop(PW_PENDING_KEY, None)
        return None, None
    return p, user


@router.get("/login/password")
def new_password_page(request: Request, db: Session = Depends(get_db)):
    p, user = _pw_pending(request, db)
    if not p:
        return RedirectResponse("/login", status_code=303)
    return render(request, "login_password.html", {"error": "", "username": user.username})


@router.post("/login/password")
def new_password_submit(request: Request, new_password: str = Form(""), confirm_password: str = Form(""),
                        db: Session = Depends(get_db)):
    p, user = _pw_pending(request, db)
    if not p:
        note(request, category="auth", action="login.password_set.failed", outcome="denied",
             details={"reason": "no pending sign-in"})
        request.session.pop(PW_PENDING_KEY, None)
        return RedirectResponse("/login", status_code=303)
    err = validate_password_strength(new_password)
    if not err and new_password != confirm_password:
        err = "The two passwords don't match."
    if not err and verify_password(new_password, user.password_hash):
        err = "Choose a password different from the one your administrator gave you."
    if not err and new_password.strip().lower() == user.username.strip().lower():
        err = "The password can't be your username."
    if err:
        note(request, category="auth", action="login.password_set.failed", outcome="failed", user=user,
             details={"reason": err})
        return render(request, "login_password.html", {"error": err, "username": user.username}, status_code=400)
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    user.rotate_session_key()   # any other browser of this account is signed out
    db.commit()
    log.info("password set at sign-in user=%s ip=%s", user.username, _ip(request))
    resp = _complete(request, db, user, p.get("amr", "pwd"), p.get("next", "/"))
    note(request, details={"password_changed": "replaced the password set by an administrator"})
    return resp


# --------------------------------------------------------------------------- #
# Microsoft Entra ID
# --------------------------------------------------------------------------- #

@router.get("/auth/entra/login")
def entra_login(request: Request, db: Session = Depends(get_db)):
    cfg = loginconfig.load(db)
    nxt = _safe_next(request.query_params.get("next"))
    if not cfg.sso_enabled or not cfg.entra_ready:
        return _login_page(request, cfg, "Microsoft sign-in is not configured. Run manage.py configure-login on the server.",
                           nxt, show_local=True, status_code=400)
    try:
        url, pending = entra.begin(cfg)
    except entra.EntraError as exc:
        log.warning("entra begin failed: %s", exc)
        return _login_page(request, cfg, str(exc), nxt, show_local=True, status_code=502)
    request.session.pop(MFA_PENDING_KEY, None)
    request.session[SSO_PENDING_KEY] = {**pending, "next": nxt}
    note(request, category="auth", action="login.entra.start")
    return RedirectResponse(url, status_code=303)


@router.get("/auth/entra/stepup")
def entra_stepup(request: Request, db: Session = Depends(get_db), user: User | None = Depends(get_current_user_optional)):
    """Console re-auth for Microsoft accounts: a forced fresh sign-in, then back to `next`."""
    nxt = _safe_next(request.query_params.get("next"))
    if user is None:
        return RedirectResponse("/login?next=" + quote(nxt, safe=""), status_code=303)
    cfg = loginconfig.load(db)
    note(request, category="auth", action="stepup.entra.start")
    if not user.is_sso or not user.can("console") or not cfg.sso_enabled or not cfg.entra_ready:
        note(request, outcome="failed", details={"reason": "not a Microsoft account allowed consoles, or SSO off"})
        request.session["notice"] = "The Microsoft re-auth is only for Microsoft accounts that can open consoles."
        return RedirectResponse(nxt, status_code=303)
    try:
        url, pending = entra.begin(cfg, stepup=True, acr=settings.ENTRA_STEPUP_ACR, login_hint=user.username)
    except entra.EntraError as exc:
        note(request, outcome="error", details={"reason": str(exc)[:200]})
        request.session["notice"] = str(exc)
        return RedirectResponse(nxt, status_code=303)
    request.session[SSO_PENDING_KEY] = {**pending, "next": nxt, "stepup": True, "uid": user.id}
    return RedirectResponse(url, status_code=303)


def _stepup_callback(request: Request, db: Session, cfg, pending: dict, q) -> RedirectResponse:
    """Finish a console re-auth started by /auth/entra/stepup (the browser stays signed in)."""
    nxt = _safe_next(pending.get("next"))
    note(request, category="auth", action="stepup")
    user = get_current_user_optional(request, db)

    def fail(msg: str):
        log.warning("console re-auth (entra) failed user=%s ip=%s: %s", user.username if user else "-", _ip(request), msg)
        note(request, outcome="failed", details={"method": "entra", "reason": msg[:200]})
        request.session["notice"] = "Microsoft re-auth failed: " + msg
        return RedirectResponse(nxt, status_code=303)

    if user is None or user.id != pending.get("uid"):
        return fail("you are no longer signed in as the same user.")
    if q.get("error"):
        return fail((q.get("error_description") or q.get("error") or "").splitlines()[0][:200])
    if time.time() - pending.get("ts", 0) > SSO_PENDING_SECONDS:
        return fail("it took too long. Try again.")
    if not q.get("state") or q.get("state") != pending.get("state") or not q.get("code"):
        return fail("the response doesn't match this browser session.")
    try:
        claims = entra.finish(cfg, q["code"], pending)
    except entra.EntraError as exc:
        return fail(str(exc))
    if claims["oid"] != user.entra_oid:
        return fail(f"you signed in as {claims['username']}, not {user.username}.")
    if not role_can(claims["role"], "console"):
        # The Entra app role was lowered or removed since this browser signed in: apply it now.
        if claims["role"] and claims["role"] != user.role:
            note(request, details={"role_changed": f"{user.role} -> {claims['role']}"})
            user.role = claims["role"]
        user.rotate_session_key()
        db.commit()
        stepup.drop_user(user.id)
        from .. import consoles

        consoles.kick_user(user.id, "account changed: Microsoft Entra role no longer allows consoles")
        msg = "Your Microsoft account no longer has a Proxmox Manager role that can open consoles. Sign in again."
        log.warning("console re-auth (entra) refused, role lowered user=%s ip=%s", user.username, _ip(request))
        note(request, outcome="failed", details={"method": "entra", "reason": "Entra role no longer allows consoles",
                                                 "signed_out": True})
        logout_user(request)
        return _login_page(request, cfg, msg, "/", status_code=403)
    # Freshness comes from auth_time only: iat is always "now" and prompt=login can be removed
    # from the URL by the browser, so without auth_time the re-auth proves nothing.
    auth_time = claims.get("auth_time")
    if not auth_time:
        return fail("Microsoft didn't say when you signed in (auth_time). An administrator has to add the optional "
                    "claim auth_time to the ID token of the app registration (Token configuration).")
    started = int(pending.get("ts", 0))
    if auth_time < started - 60:
        return fail("Microsoft didn't ask for your sign-in again (the sign-in is older than this request).")
    acr = settings.ENTRA_STEPUP_ACR
    if acr and acr not in claims.get("acrs", []):
        return fail(f"the required Conditional Access check ({acr}) wasn't completed.")
    stepup.grant(user.id, session_id(request), "entra", _ip(request))
    log.info("console re-auth ok user=%s method=entra ip=%s", user.username, _ip(request))
    note(request, outcome="ok", user=user, details={"method": "entra", "amr": ",".join(claims.get("amr") or []),
                                                    "acr": acr or "", "window_minutes": round(stepup.window_seconds() / 60, 1)})
    request.session["notice"] = (f"Verified. You can open consoles for the next {stepup.window_seconds() // 60} minutes "
                                 "from this browser.")
    return RedirectResponse(nxt, status_code=303)


@router.get(loginconfig.CALLBACK_PATH)
def entra_callback(request: Request, db: Session = Depends(get_db)):
    cfg = loginconfig.load(db)
    q = request.query_params
    pending = request.session.pop(SSO_PENDING_KEY, None)
    if pending and pending.get("stepup"):
        return _stepup_callback(request, db, cfg, pending, q)
    nxt = (pending or {}).get("next", "/")
    ip = _ip(request)

    def fail(msg: str, code: int = 401):
        log.warning("entra sign-in failed ip=%s: %s", ip, msg)
        note(request, category="auth", action="login.entra.failed", outcome="failed", details={"reason": msg[:300]})
        return _login_page(request, cfg, msg, nxt, status_code=code)

    if not cfg.sso_enabled or not cfg.entra_ready:
        return fail("Microsoft sign-in is not enabled.", 400)
    if q.get("error"):
        desc = (q.get("error_description") or q.get("error") or "").splitlines()[0][:300]
        if q.get("error") == "access_denied" and "AADSTS50105" in desc:
            return fail("Your account isn't assigned to Proxmox Manager. Ask an administrator to assign you "
                        "the Admin, Technician or Viewer role in Entra ID (Enterprise applications).", 403)
        return fail("Microsoft sign-in was cancelled or refused: " + desc)
    if not pending or time.time() - pending.get("ts", 0) > SSO_PENDING_SECONDS:
        return fail("The sign-in took too long or was started in another browser. Try again.", 400)
    if not q.get("state") or q.get("state") != pending.get("state"):
        return fail("The sign-in response doesn't match this browser session (state). Try again.", 400)
    if not q.get("code"):
        return fail("Microsoft didn't return an authorization code.", 400)
    try:
        claims = entra.finish(cfg, q["code"], pending)
    except entra.EntraError as exc:
        return fail(str(exc))
    if not claims["role"]:
        return fail(f"{claims['username']} has no Proxmox Manager role. Ask an administrator to assign the Admin, "
                    "Technician or Viewer app role in Entra ID (Enterprise applications → Proxmox Manager → Users and groups).", 403)

    user = db.query(User).filter(User.auth_source == "entra", User.entra_oid == claims["oid"]).first()
    if user is None:
        clash = db.query(User).filter(User.username == claims["username"]).first()
        if clash:
            return fail(f"A local account named {claims['username']} already exists. An administrator has to "
                        "rename or delete it before this Microsoft account can sign in.", 409)
        user = User(username=claims["username"], password_hash="!", role=claims["role"], auth_source="entra",
                    entra_oid=claims["oid"], entra_tid=claims["tid"], display_name=claims["name"], is_active=True)
        db.add(user)
        db.flush()
        log.info("entra account created user=%s role=%s", user.username, user.role)
        note(request, details={"account_created": True, "role": user.role})
    else:
        if not user.is_active:
            return fail("Your account is disabled in Proxmox Manager.", 403)
        clash = db.query(User).filter(User.username == claims["username"], User.id != user.id).first()
        if not clash:
            user.username = claims["username"]
        if user.role != claims["role"]:
            log.info("entra role changed user=%s %s -> %s", user.username, user.role, claims["role"])
            note(request, details={"role_changed": f"{user.role} -> {claims['role']}"})
            user.rotate_session_key()   # the old role's other sign-ins end
        user.role = claims["role"]
        user.display_name = claims["name"]
    return _finish(request, db, user, "sso", nxt)


@router.post("/logout")
def logout(request: Request):
    note(request, category="auth", action="logout")
    logout_user(request)
    return RedirectResponse("/login", status_code=303)
