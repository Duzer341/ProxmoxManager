"""Roles and what each one may do.

One table decides everything role-related: the API guards (auth.require_cap), the console
websocket check and the templates (current_user.can(...) / the CAN object on the host page)
all read it, so hiding a button and refusing the request can't drift apart.

    admin       everything
    technician  viewer + guest power, snapshot, backup, expand disk, start at boot
                (no consoles, no node actions, no host / user / sign-in settings)
    viewer      read-only: dashboard, host pages, refresh, SMART scans, job output
"""

ROLES = ("admin", "technician", "viewer")
ROLE_LABELS = {"admin": "Admin", "technician": "Technician", "viewer": "Viewer"}
ROLE_RANK = {"viewer": 0, "technician": 1, "admin": 2}

# Capabilities
GUEST_POWER = "guest.power"        # start / shut down / restart / power off
GUEST_SNAPSHOT = "guest.snapshot"
GUEST_BACKUP = "guest.backup"      # incl. listing the backup storages
GUEST_DISK = "guest.disk"          # expand disk (incl. listing the guest's disks)
GUEST_ONBOOT = "guest.onboot"      # start at boot
GUEST_DETAILS = "guest.details"    # the More dialog: boot order, network adapters
CONSOLE = "console"                # VM / CT consoles, node terminal, upgrade shell, saved root password, console log
NODE_ACTIONS = "node.actions"      # update / check updates / reboot / switch repos / refresh package list
HOSTS_MANAGE = "hosts.manage"      # add / edit / delete / test hosts, host credentials, SSH keys
USERS_MANAGE = "users.manage"      # users, roles, authenticator resets, sign-in settings

GUEST_CAPS = frozenset({GUEST_POWER, GUEST_SNAPSHOT, GUEST_BACKUP, GUEST_DISK, GUEST_ONBOOT, GUEST_DETAILS})

CAPS: dict[str, frozenset[str]] = {
    "admin": GUEST_CAPS | {CONSOLE, NODE_ACTIONS, HOSTS_MANAGE, USERS_MANAGE},
    "technician": GUEST_CAPS,
    "viewer": frozenset(),
}


def role_can(role: str, cap: str) -> bool:
    return cap in CAPS.get(role or "", frozenset())


def caps_for(role: str) -> list[str]:
    return sorted(CAPS.get(role or "", frozenset()))


def highest(roles: list[str]) -> str:
    """The most powerful of several dashboard roles ('' if none)."""
    known = [r for r in roles if r in ROLE_RANK]
    return max(known, key=lambda r: ROLE_RANK[r]) if known else ""
