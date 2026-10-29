"""In-memory sign-in throttling.

A username used to be locked after 5 failures from anywhere, so anyone who could reach the
sign-in page could keep an admin locked out. Now:

- a username + client address pair is locked for LOCK_SECONDS after PAIR_LIMIT failures (the
  attacker's address, not the account, is locked);
- a client address is locked after IP_LIMIT failures for any usernames;
- across all addresses a username only slows down: from USER_SOFT_LIMIT failures within the window,
  each further attempt has to wait 2, 4, 8 ... up to USER_MAX_DELAY seconds after the last failure.
  The slow-down does not apply to a browser that already signed in to that account (a signed
  "known device" cookie, see auth_device.py), so attempts from many addresses can't keep the
  real admin out.

Failures are wrong passwords and wrong authenticator / re-auth codes. Counters live in this process
(single-instance service, see main._single_instance_lock) and reset on restart.
"""

import threading
import time

WINDOW_SECONDS = 15 * 60
LOCK_SECONDS = 15 * 60
PAIR_LIMIT = 5
IP_LIMIT = 20
USER_SOFT_LIMIT = 10
USER_MAX_DELAY = 60

_lock = threading.Lock()
_fails: dict[str, list[float]] = {}
_locked_until: dict[str, float] = {}


def _net(ip: str) -> str:
    """IPv6 clients are grouped by /64 (one host usually owns the whole prefix); IPv4-mapped
    addresses (::ffff:a.b.c.d) count as the IPv4 address."""
    if ip and ip.lower().startswith("::ffff:") and "." in ip:
        return ip[7:]
    if ip and ":" in ip:
        import ipaddress

        try:
            return str(ipaddress.ip_network(ip + "/64", strict=False))
        except ValueError:
            return ip
    return ip or ""


def _user(username: str | None) -> str:
    return (username or "").strip().lower()


def _hard_keys(username: str | None, ip: str | None) -> list[tuple[str, int]]:
    keys = []
    u, n = _user(username), _net(ip or "")
    if u:
        keys.append(("p:" + u + "|" + n, PAIR_LIMIT))
    if n:
        keys.append(("ip:" + n, IP_LIMIT))
    return keys


def _recent(key: str, now: float) -> list[float]:
    return [t for t in _fails.get(key, []) if now - t < WINDOW_SECONDS]


def locked(username: str | None, ip: str | None, known_device: bool = False) -> int:
    """Seconds until a sign-in attempt is allowed again, 0 if it is allowed now. known_device: the
    browser signed in to this account before, so the per-account slow-down doesn't apply to it."""
    now = time.monotonic()
    with _lock:
        wait = 0.0
        for key, _limit in _hard_keys(username, ip):
            until = _locked_until.get(key, 0)
            if until > now:
                wait = max(wait, until - now)
            elif key in _locked_until:
                del _locked_until[key]
        u = _user(username)
        if u and not known_device:
            hits = _recent("u:" + u, now)
            over = len(hits) - USER_SOFT_LIMIT
            if over >= 0 and hits:
                delay = min(USER_MAX_DELAY, 2 ** (over + 1))
                wait = max(wait, hits[-1] + delay - now)
        return int(wait) + 1 if wait > 0 else 0


def failure(username: str | None, ip: str | None) -> None:
    now = time.monotonic()
    with _lock:
        for key, limit in _hard_keys(username, ip):
            hits = _recent(key, now)
            hits.append(now)
            _fails[key] = hits
            if len(hits) >= limit:
                _locked_until[key] = now + LOCK_SECONDS
                _fails[key] = []
        u = _user(username)
        if u:
            hits = _recent("u:" + u, now)
            hits.append(now)
            _fails["u:" + u] = hits[-100:]


def success(username: str | None, ip: str | None = None) -> None:
    """A correct sign-in clears that user's counters for this address (and the slow-down)."""
    u = _user(username)
    if not u:
        return
    with _lock:
        _fails.pop("u:" + u, None)
        if ip is not None:
            key = "p:" + u + "|" + _net(ip)
            _fails.pop(key, None)
            _locked_until.pop(key, None)


def reset() -> None:
    with _lock:
        _fails.clear()
        _locked_until.clear()
