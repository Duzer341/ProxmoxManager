"""Limits on the admin "Test connection" / "Test SSH" endpoints.

Those endpoints connect from the dashboard (an address client firewalls trust) to a caller-chosen address
with a typed password / token. Without limits an admin session could spray passwords or map open ports.

- An address that isn't a managed host (host address, cluster node IP or SSH address override) needs a
  fresh re-auth (the console step-up) before it can be tested.
- Per admin: at most PER_ADMIN_MAX tests in WINDOW seconds (all targets).
- Per target: TARGET_FAIL_MAX failed sign-ins in WINDOW blocks further tests of that address:port for
  TARGET_BLOCK seconds.
- Alerts : one admin testing
  DISTINCT_ALERT or more different unmanaged addresses in WINDOW, or a target reaching the failure limit.

State is in memory (per process); a restart resets the counters, which is fine for this purpose.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque

log = logging.getLogger(__name__)

WINDOW = 600
PER_ADMIN_MAX = 30
TARGET_FAIL_MAX = 5
TARGET_BLOCK = 900
DISTINCT_ALERT = 5

_lock = threading.Lock()
_admin_hits: dict[int, deque] = {}
_target_fails: dict[str, deque] = {}
_target_blocked: dict[str, float] = {}
_admin_targets: dict[int, dict[str, float]] = {}
_alerted: dict[tuple, float] = {}


class Throttled(Exception):
    def __init__(self, message: str, retry_after: int):
        super().__init__(message)
        self.retry_after = retry_after


def _norm(address: str) -> str:
    return (address or "").strip().strip("[]").rstrip(".").lower()


def target_key(kind: str, address: str, port: int) -> str:
    return f"{kind}:{_norm(address)}:{int(port or 0)}"


def managed_addresses(db) -> set[str]:
    """Every address the dashboard already manages: host addresses, cluster node IPs, SSH overrides."""
    import json

    from .models import ProxmoxHost

    out: set[str] = set()
    for h in db.query(ProxmoxHost).all():
        out.add(_norm(h.host))
        try:
            s = json.loads(h.last_summary_json) if h.last_summary_json else {}
        except ValueError:
            s = {}
        for n in (s or {}).get("nodes") or []:
            if n.get("ip"):
                out.add(_norm(str(n["ip"])))
        try:
            addrs = json.loads(h.ssh_node_addrs) if h.ssh_node_addrs else {}
        except ValueError:
            addrs = {}
        if isinstance(addrs, dict):
            out.update(_norm(str(v)) for v in addrs.values() if v)
    out.discard("")
    return out


def is_managed(db, address: str) -> bool:
    return _norm(address) in managed_addresses(db)


def _prune(dq: deque, now: float) -> None:
    while dq and now - dq[0] > WINDOW:
        dq.popleft()


def check(user_id: int, key: str) -> None:
    """Raise Throttled if this admin or this target is over its limit. Counts the attempt."""
    now = time.time()
    with _lock:
        until = _target_blocked.get(key, 0)
        if until > now:
            raise Throttled("Too many failed sign-ins to this address from the dashboard. Tests of it are paused "
                            f"for {int((until - now) // 60) + 1} min.", int(until - now) + 1)
        hits = _admin_hits.setdefault(user_id, deque())
        _prune(hits, now)
        if len(hits) >= PER_ADMIN_MAX:
            wait = int(WINDOW - (now - hits[0])) + 1
            raise Throttled(f"Too many connection tests ({PER_ADMIN_MAX} in {WINDOW // 60} min). Try again in "
                            f"{wait // 60 + 1} min.", wait)
        hits.append(now)


def record(user_id: int, username: str, key: str, outcome: str, managed: bool, client_ip: str = "") -> None:
    """outcome: ok | auth_failed | error | confirm. Raises nothing; writes alerts to the event log."""
    now = time.time()
    alerts: list[tuple[str, dict]] = []
    with _lock:
        if not managed:
            seen = _admin_targets.setdefault(user_id, {})
            for k in [k for k, t in seen.items() if now - t > WINDOW]:
                seen.pop(k)
            seen[key] = now
            if len(seen) >= DISTINCT_ALERT and now - _alerted.get(("distinct", user_id), 0) > WINDOW:
                _alerted[("distinct", user_id)] = now
                alerts.append(("many unmanaged targets", {"targets": sorted(seen)[:20], "count": len(seen),
                                                          "window_min": WINDOW // 60}))
        if outcome == "auth_failed":
            dq = _target_fails.setdefault(key, deque())
            _prune(dq, now)
            dq.append(now)
            if len(dq) >= TARGET_FAIL_MAX:
                _target_blocked[key] = now + TARGET_BLOCK
                dq.clear()
                alerts.append(("repeated failed sign-ins", {"target": key, "failures": TARGET_FAIL_MAX,
                                                            "blocked_min": TARGET_BLOCK // 60}))
        elif outcome == "ok":
            _target_fails.pop(key, None)
    for what, det in alerts:
        log.warning("outbound alert (%s) by %s: %s", what, username, det)
        try:
            from . import events

            events.event("action", "outbound.alert", "denied", username=username, client_ip=client_ip,
                        details={"alert": what, **det})
        except Exception:  # noqa: BLE001
            log.exception("could not write the outbound alert")


def reset() -> None:
    """Tests only."""
    with _lock:
        for d in (_admin_hits, _target_fails, _target_blocked, _admin_targets, _alerted):
            d.clear()
