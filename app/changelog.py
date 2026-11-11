"""Update notes for pending apt packages.

The changelog of a pending package is read through the Proxmox API (GET /nodes/{node}/apt/changelog,
the node downloads it from its repository) and reduced to the entries between the installed and the
new version: version, date, urgency, the first line of each change, and every CVE ID mentioned.
CVE IDs in older entries (the installed version and before) are kept separately, so a lookup can
say "already fixed in what is installed".

Debian version ordering follows dpkg (epoch, upstream version, revision; '~' sorts before
everything, letters before non-letters).
"""

from __future__ import annotations

import re
import threading
import time
from typing import Any

CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.I)
_HEADER_RE = re.compile(r"^(?P<src>[a-z0-9][a-z0-9+.-]*) \((?P<ver>[^()\s]+)\) (?P<dist>[^;]*);(?P<opts>.*)$")
_TRAILER_RE = re.compile(r"^ -- (?P<who>.*?)  (?P<date>\S.*)$")
PACKAGE_RE = re.compile(r"[a-z0-9][a-z0-9+.-]{0,99}")
VERSION_RE = re.compile(r"[A-Za-z0-9.+~:-]{1,100}")

SUB = "\u2013 "              # prefix of a sub-item line (shown indented)
MAX_TEXT = 2_000_000        # characters of changelog read
MAX_NEW_ENTRIES = 40        # entries shown between installed and new
MAX_ITEMS = 16              # change lines per entry
MAX_ITEM_LEN = 240
MAX_OLD_ENTRIES = 400       # older entries scanned for CVE IDs already fixed


# --------------------------------------------------------------------------- #
# dpkg version comparison
# --------------------------------------------------------------------------- #

def _order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split(v: str) -> tuple[int, str, str]:
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    if "-" in v:
        up, rev = v.rsplit("-", 1)
    else:
        up, rev = v, ""
    return epoch, up, rev


def compare_versions(a: str, b: str) -> int:
    """<0 if a < b, 0 if equal, >0 if a > b (dpkg --compare-versions)."""
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return ea - eb
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


# --------------------------------------------------------------------------- #
# Debian changelog parsing
# --------------------------------------------------------------------------- #

def normalize_cve(s: str) -> str | None:
    m = CVE_RE.search(s or "")
    return f"CVE-{m.group(1)}-{m.group(2)}" if m else None


def _cves(text: str) -> list[str]:
    seen: list[str] = []
    for m in CVE_RE.finditer(text):
        c = f"CVE-{m.group(1)}-{m.group(2)}"
        if c not in seen:
            seen.append(c)
    return seen


def parse(text: str) -> list[dict[str, Any]]:
    """Entries of a Debian changelog, newest first: version, dist, urgency, date, items (change
    lines, continuation lines joined), text (the whole entry body)."""
    entries: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    item: list[str] | None = None

    def close_item():
        nonlocal item
        if cur is not None and item:
            cur["items"].append(" ".join(item))
        item = None

    for raw in (text or "")[:MAX_TEXT].splitlines():
        line = raw.rstrip()
        h = _HEADER_RE.match(line)
        if h:
            close_item()
            urg = re.search(r"urgency=(\w+)", h.group("opts"))
            cur = {"version": h.group("ver"), "dist": h.group("dist").strip(), "urgency": (urg.group(1).lower() if urg else ""),
                   "date": "", "items": [], "body": []}
            entries.append(cur)
            continue
        if cur is None:
            continue
        t = _TRAILER_RE.match(line)
        if t:
            close_item()
            cur["date"] = t.group("date").strip()
            cur = None
            continue
        cur["body"].append(line)
        s = line.strip()
        if not s:
            close_item()
            continue
        if s.startswith("[") and s.endswith("]"):      # [ Author Name ] section headers
            close_item()
            continue
        if s[:1] in ("*", "-", "+") and s[1:2] == " ":
            # a sub-item ("    - CVE-...") nested under "  * " becomes its own line, marked with SUB
            indent = len(line) - len(line.lstrip())
            close_item()
            item = [(SUB if s[0] != "*" and indent > 2 else "") + s[2:].strip()]
        elif item is not None:
            item.append(s)
        else:
            item = [s]
    close_item()
    for e in entries:
        e["text"] = "\n".join(e.pop("body"))
    return entries


def _short(s: str) -> str:
    s = " ".join(s.split())
    return s if len(s) <= MAX_ITEM_LEN else s[: MAX_ITEM_LEN - 1].rstrip() + "…"


def notes(text: str, old: str, new: str) -> dict[str, Any]:
    """Cliff notes for an update from `old` (installed, may be "") to `new`."""
    entries = parse(text)
    pending, older = [], []
    for e in entries:
        v = e["version"]
        try:
            newer_than_old = not old or compare_versions(v, old) > 0
            not_after_new = compare_versions(v, new) <= 0
        except Exception:  # noqa: BLE001
            continue
        if newer_than_old and not_after_new:
            pending.append(e)
        elif not newer_than_old:
            older.append(e)
    shown = []
    all_cves: list[str] = []
    for e in pending[:MAX_NEW_ENTRIES]:
        cves = _cves(e["text"])
        all_cves += [c for c in cves if c not in all_cves]
        items = [_short(i) for i in e["items"]]
        shown.append({
            "version": e["version"], "dist": e["dist"], "urgency": e["urgency"], "date": e["date"],
            "items": items[:MAX_ITEMS], "more_items": max(0, len(items) - MAX_ITEMS), "cves": cves,
            "security": bool(cves) or e["urgency"] in ("high", "emergency", "critical") or "security" in e["dist"],
        })
    fixed_before: dict[str, str] = {}
    for e in older[:MAX_OLD_ENTRIES]:
        for c in _cves(e["text"]):
            fixed_before.setdefault(c, e["version"])
    return {
        "entries": shown,
        "more_entries": max(0, len(pending) - MAX_NEW_ENTRIES),
        "cves": all_cves,
        "security": any(e["security"] for e in shown),
        "installed_found": not old or any(compare_versions(e["version"], old) == 0 for e in entries),
        "fixed_in_installed": fixed_before,   # CVE -> version (<= installed) whose entry names it
        # full text of the pending entries, for a CVE / keyword lookup in the browser
        "search_text": "\n".join(e["text"] for e in pending[:MAX_NEW_ENTRIES])[:200_000],
    }


# --------------------------------------------------------------------------- #
# cache: a package version's changelog never changes
# --------------------------------------------------------------------------- #

_lock = threading.Lock()
_cache: dict[tuple, tuple[float, dict]] = {}
CACHE_SECONDS = 12 * 3600
ERROR_CACHE_SECONDS = 300


def cached(key: tuple) -> dict | None:
    with _lock:
        hit = _cache.get(key)
    if hit and time.time() < hit[0]:
        return hit[1]
    return None


def store(key: tuple, value: dict, error: bool = False) -> None:
    with _lock:
        if len(_cache) > 3000:
            _cache.clear()
        _cache[key] = (time.time() + (ERROR_CACHE_SECONDS if error else CACHE_SECONDS), value)
