#!/usr/bin/env python3
"""Admin CLI for Proxmox Manager.

    python manage.py create-admin <username>          # prompts for password
    python manage.py reset-password <username> [--no-change-required]
                                                      # prompts for password; the user sets a new one at next
                                                      # sign-in unless --no-change-required (your own account)
    python manage.py list-users
    python manage.py set-role <username> admin|technician|viewer
    python manage.py disable-user <username>
    python manage.py enable-user <username>
    python manage.py reset-mfa <username>             # remove a user's authenticator app
    python manage.py enroll-code <username>           # one-time code for a first authenticator setup
    python manage.py configure-login                  # choose the sign-in mode (asks questions)
    python manage.py configure-login --mode local|mfa|entra [--tenant ID --client-id ID --url https://...]
    python manage.py show-login
"""

import getpass
import os
import sys

from app import loginconfig, mfa
from app.auth import hash_password, validate_password_strength
from app.database import db_session, init_db
from app.models import User


def _prompt_password() -> str:
    while True:
        pw = getpass.getpass("Password: ")
        err = validate_password_strength(pw)
        if err:
            print(err)
            continue
        if pw != getpass.getpass("Confirm password: "):
            print("Passwords do not match.")
            continue
        return pw


def create_admin(username: str) -> None:
    with db_session() as db:
        if db.query(User).filter_by(username=username).first():
            sys.exit(f"User '{username}' already exists.")
        u = User(username=username, password_hash=hash_password(_prompt_password()), role="admin")
        db.add(u)
        code = _enroll_code_if_needed(db, u)
    print(f"Admin user '{username}' created.")
    if code:
        print(f"Enrollment code for the first authenticator setup (works once, 7 days): {code}")


def _enroll_code_if_needed(db, u: User) -> str:
    cfg = loginconfig.load(db)
    if u.is_sso or u.mfa_enabled or not cfg.mfa_available or not cfg.mfa_required(u):
        return ""
    return mfa.new_enroll_code(u)


def enroll_code(username: str) -> None:
    """Print a one-time enrollment code for a user who must set up an authenticator."""
    with db_session() as db:
        user = db.query(User).filter_by(username=username).first()
        if not user:
            sys.exit(f"User '{username}' not found.")
        if user.is_sso:
            sys.exit(f"'{username}' signs in with Microsoft; two-step sign-in is managed in Entra ID.")
        if user.mfa_enabled:
            sys.exit(f"'{username}' already has an authenticator (reset-mfa first to move it to a new phone).")
        code = _enroll_code_if_needed(db, user)
        if not code:
            sys.exit(f"'{username}' doesn't need an authenticator in the current sign-in mode.")
    print(f"Enrollment code for '{username}' (works once, valid 7 days): {code}")


def reset_password(username: str, change_required: bool = True) -> None:
    with db_session() as db:
        user = db.query(User).filter_by(username=username).first()
        if not user:
            sys.exit(f"User '{username}' not found.")
        if user.is_sso:
            sys.exit(f"'{username}' signs in with Microsoft and has no password here.")
        user.password_hash = hash_password(_prompt_password())
        user.must_change_password = change_required
        user.rotate_session_key()  # signed out of every browser
    print(f"Password for '{username}' updated."
          + (" They choose a new one at their next sign-in." if change_required else ""))


def list_users() -> None:
    with db_session() as db:
        for u in db.query(User).order_by(User.username).all():
            state = "active" if u.is_active else "disabled"
            source = "microsoft" if u.is_sso else "local"
            second = "mfa" if u.mfa_enabled else ("-" if u.is_sso else "no-mfa")
            pw = "  (sets a new password at next sign-in)" if u.must_change_password and not u.is_sso else ""
            print(f"{u.username:32} {u.role:8} {state:9} {source:10} {second}{pw}")


def reset_mfa(username: str) -> None:
    with db_session() as db:
        user = db.query(User).filter_by(username=username).first()
        if not user:
            sys.exit(f"User '{username}' not found.")
        if user.is_sso:
            sys.exit(f"'{username}' signs in with Microsoft; two-step sign-in is managed in Entra ID.")
        mfa.disable(user)
        user.rotate_session_key()
        code = _enroll_code_if_needed(db, user)
    print(f"Authenticator removed for '{username}'. They set up a new one at their next sign-in "
          "(admins and technicians must, in the mfa and entra modes).")
    if code:
        print(f"Enrollment code for that setup (works once, 7 days): {code}")


def _ask(prompt: str, default: str = "") -> str:
    val = input(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
    return val or default


def show_login() -> None:
    with db_session() as db:
        cfg = loginconfig.load(db)
    print(f"Login mode:   {cfg.mode} ({loginconfig.MODE_LABELS[cfg.mode]}){'' if cfg.configured else '  [not configured yet]'}")
    if cfg.mode == "entra" or cfg.tenant:
        print(f"Tenant:       {cfg.tenant or '-'}")
        print(f"Client ID:    {cfg.client_id or '-'}")
        print(f"Secret:       {'set' if cfg.client_secret else 'NOT SET'}")
        print(f"Redirect URI: {cfg.redirect_uri or '-'}")
        if cfg.authority != loginconfig.DEFAULT_AUTHORITY:
            print(f"Authority:    {cfg.authority}")


def _test_entra(cfg: loginconfig.LoginConfig) -> None:
    from app import entra

    try:
        doc = entra.discovery(cfg, refresh=True)
        print(f"OK: reached the tenant's OpenID configuration (issuer {doc['issuer']}).")
    except entra.EntraError as exc:
        print(f"WARNING: {exc}")


def configure_login(args: list[str]) -> None:
    opts = {}
    it = iter(args)
    for a in it:
        if a in ("--mode", "--tenant", "--client-id", "--url", "--authority"):
            opts[a[2:]] = next(it, "")
        else:
            sys.exit(__doc__)
    with db_session() as db:
        cur = loginconfig.load(db)
    interactive = "mode" not in opts
    if interactive:
        print("How should people sign in to the dashboard?")
        print("  1) Username and password")
        print("  2) Username and password plus an authenticator app (MFA; required for admins and technicians)")
        print("  3) Microsoft Entra ID single sign-on (local accounts kept as break-glass, with MFA)")
        default = str(loginconfig.MODES.index(cur.mode) + 1) if cur.configured else "2"
        choice = _ask("Choose 1, 2 or 3", default)
        if choice not in ("1", "2", "3"):
            sys.exit("Please choose 1, 2 or 3.")
        mode = loginconfig.MODES[int(choice) - 1]
    else:
        mode = opts["mode"]
        if mode not in loginconfig.MODES:
            sys.exit("--mode must be local, mfa or entra.")

    tenant, client_id, redirect, authority, secret = cur.tenant, cur.client_id, cur.redirect_uri, cur.authority, None
    if mode == "entra":
        if interactive:
            print()
            print("Entra ID app registration (Entra admin center > App registrations):")
            tenant = _ask("Directory (tenant) ID", cur.tenant)
            client_id = _ask("Application (client) ID", cur.client_id)
            base = redirect[: -len(loginconfig.CALLBACK_PATH)] if redirect.endswith(loginconfig.CALLBACK_PATH) else ""
            base = _ask("Dashboard address people use (e.g. https://pm.example.com)", base)
            redirect = loginconfig.redirect_uri_for(base)
            entered = getpass.getpass("Client secret value (Enter keeps the current one): " if cur.client_secret
                                      else "Client secret value: ")
            secret = entered if entered else None
        else:
            tenant = opts.get("tenant", cur.tenant)
            client_id = opts.get("client-id", cur.client_id)
            if opts.get("url"):
                redirect = loginconfig.redirect_uri_for(opts["url"])
            authority = opts.get("authority", cur.authority)
            env_secret = os.environ.get("PM_ENTRA_CLIENT_SECRET")
            secret = env_secret if env_secret else None
        err = loginconfig.validate_entra(tenant, client_id, redirect, authority)
        if err:
            sys.exit(err)
        if secret is None and not cur.client_secret:
            sys.exit("A client secret is required (interactive prompt, or PM_ENTRA_CLIENT_SECRET in the environment).")

    with db_session() as db:
        loginconfig.save(db, mode, tenant, client_id, secret, redirect, authority)
        cfg = loginconfig.load(db)
        # admins / technicians who must now set up an authenticator get an enrollment code
        codes = {}
        for u in db.query(User).filter(User.role.in_(("admin", "technician")), User.auth_source == "local",
                                       User.is_active.is_(True), User.mfa_enabled.is_(False)).all():
            if mfa.enroll_code_pending(u):
                codes[u.username] = "(code already issued)"
            else:
                code = _enroll_code_if_needed(db, u)
                if code:
                    codes[u.username] = code
    print()
    print(f"Login mode set to: {loginconfig.MODE_LABELS[mode]}")
    if mode == "entra":
        print(f"Redirect URI to register (Web platform): {cfg.redirect_uri}")
        print("App roles needed on the registration: values 'Admin', 'Technician' and 'Viewer'.")
        _test_entra(cfg)
    if mode in ("mfa", "entra") and codes:
        print("These local accounts set up an authenticator app at their next sign-in, with this one-time enrollment")
        print("code (works once, 7 days; give it to them another way, or use 'manage.py enroll-code <user>' later):")
        for name, code in codes.items():
            print(f"  {name:32} {code}")
    print("Signed-in sessions that no longer meet the rules are signed out automatically.")


def login_configured() -> None:
    with db_session() as db:
        sys.exit(0 if loginconfig.load(db).configured else 1)


def set_role(username: str, role: str) -> None:
    if role not in ("admin", "technician", "viewer"):
        sys.exit("Role must be 'admin', 'technician' or 'viewer'.")
    with db_session() as db:
        user = db.query(User).filter_by(username=username).first()
        if not user:
            sys.exit(f"User '{username}' not found.")
        promoted = user.role == "viewer" and role in ("admin", "technician")
        user.role = role
        user.rotate_session_key()
        code = ""
        if promoted and not user.is_sso:
            # an authenticator a viewer set up without a code is not trusted for a privileged role
            mfa.disable(user)
            code = _enroll_code_if_needed(db, user)
    print(f"'{username}' is now {role}.")
    if code:
        print(f"They set up their authenticator again at the next sign-in with this enrollment code (works once, 7 days): {code}")


def set_active(username: str, active: bool) -> None:
    with db_session() as db:
        user = db.query(User).filter_by(username=username).first()
        if not user:
            sys.exit(f"User '{username}' not found.")
        user.is_active = active
        user.rotate_session_key()
    print(f"'{username}' {'enabled' if active else 'disabled'}.")


def main(argv: list[str]) -> None:
    init_db()
    if len(argv) < 2:
        sys.exit(__doc__)
    cmd, args = argv[1], argv[2:]
    try:
        if cmd == "create-admin" and len(args) == 1:
            create_admin(args[0])
        elif cmd == "reset-password" and len(args) == 1:
            reset_password(args[0])
        elif cmd == "reset-password" and len(args) == 2 and "--no-change-required" in args:
            reset_password(next(a for a in args if a != "--no-change-required"), change_required=False)
        elif cmd == "list-users":
            list_users()
        elif cmd == "set-role" and len(args) == 2:
            set_role(args[0], args[1])
        elif cmd == "disable-user" and len(args) == 1:
            set_active(args[0], False)
        elif cmd == "enable-user" and len(args) == 1:
            set_active(args[0], True)
        elif cmd == "reset-mfa" and len(args) == 1:
            reset_mfa(args[0])
        elif cmd == "enroll-code" and len(args) == 1:
            enroll_code(args[0])
        elif cmd == "configure-login":
            configure_login(args)
        elif cmd == "show-login":
            show_login()
        elif cmd == "login-configured":
            login_configured()
        else:
            sys.exit(__doc__)
    except KeyboardInterrupt:
        print()
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)
