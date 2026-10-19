#!/usr/bin/env python3
"""Admin CLI for Proxmox Manager.

    python manage.py create-admin <username>          # prompts for password
    python manage.py reset-password <username>        # prompts for password
    python manage.py list-users
    python manage.py set-role <username> admin|viewer
    python manage.py disable-user <username>
    python manage.py enable-user <username>
"""

import getpass
import sys

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
        db.add(User(username=username, password_hash=hash_password(_prompt_password()), role="admin"))
    print(f"Admin user '{username}' created.")


def reset_password(username: str) -> None:
    with db_session() as db:
        user = db.query(User).filter_by(username=username).first()
        if not user:
            sys.exit(f"User '{username}' not found.")
        user.password_hash = hash_password(_prompt_password())
    print(f"Password for '{username}' updated.")


def list_users() -> None:
    with db_session() as db:
        for u in db.query(User).order_by(User.username).all():
            state = "active" if u.is_active else "disabled"
            print(f"{u.username:24} {u.role:8} {state}")


def set_role(username: str, role: str) -> None:
    if role not in ("admin", "viewer"):
        sys.exit("Role must be 'admin' or 'viewer'.")
    with db_session() as db:
        user = db.query(User).filter_by(username=username).first()
        if not user:
            sys.exit(f"User '{username}' not found.")
        user.role = role
    print(f"'{username}' is now {role}.")


def set_active(username: str, active: bool) -> None:
    with db_session() as db:
        user = db.query(User).filter_by(username=username).first()
        if not user:
            sys.exit(f"User '{username}' not found.")
        user.is_active = active
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
        elif cmd == "list-users":
            list_users()
        elif cmd == "set-role" and len(args) == 2:
            set_role(args[0], args[1])
        elif cmd == "disable-user" and len(args) == 1:
            set_active(args[0], False)
        elif cmd == "enable-user" and len(args) == 1:
            set_active(args[0], True)
        else:
            sys.exit(__doc__)
    except KeyboardInterrupt:
        print()
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)
