"""TLS certificate pinning for Proxmox hosts.

Most Proxmox hosts use the self-signed certificate the cluster generates, so full CA verification
("Verify SSL") is off for them. Without a pin that meant no verification at all: anyone on the path
between the dashboard and a host could read the API token, the root@pam password and tickets.

Hosts with Verify SSL off are now pinned on first use: the SHA-256 fingerprint of the certificate the
host presents is stored on the host record (when an admin tests the connection and saves, or at the
first poll), and from then on every connection to that address must present exactly that
certificate. The check runs right after the TLS handshake and before any request bytes (and so
before any token, password or cookie) are sent:

- requests / proxmoxer (polling, jobs, root@pam sign-in, console start): urllib3's assert_fingerprint,
  injected by a small wrapper around requests' HTTPAdapter. The pin is registered for the calling
  thread by prepare() right before the connection, and the wrapper fails closed: an HTTPS request
  with verification off and no pin for that thread and address is refused, never sent unverified;
- the console websocket relay: PinnedConnection checks the peer certificate before the upgrade request.

A changed certificate stops all traffic to that host until an admin accepts the new fingerprint on
Edit host (after checking it on the node: `openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -fingerprint -sha256`).
Hosts with Verify SSL on are verified against the system CAs as before and carry no pin.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import socket
import ssl
import threading

from requests.adapters import HTTPAdapter

log = logging.getLogger(__name__)

MISMATCH_MARK = "certificate changed"

_local = threading.local()   # per thread: {(host, port): fingerprint} of the host being contacted


class PinError(Exception):
    """The host presented a different certificate than the pinned one (message is user-safe)."""


def _norm_host(host: str) -> str:
    h = (host or "").strip().strip("[]").rstrip(".").lower()
    try:
        h.encode("ascii")
    except UnicodeEncodeError:
        try:
            h = h.encode("idna").decode("ascii")   # requests connects to the punycode name
        except UnicodeError:
            pass
    return h


def _key(host: str, port) -> tuple[str, int]:
    return (_norm_host(host), int(port or 0))


def normalize(fp: str) -> str:
    """'AA:BB:..' or 'aabb..' -> 64 lowercase hex characters ('' if it isn't a SHA-256 fingerprint)."""
    h = "".join(c for c in (fp or "").lower() if c in "0123456789abcdef")
    return h if len(h) == 64 else ""


def pretty(fp: str) -> str:
    h = normalize(fp)
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2)).upper() if h else ""


def of_der(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def set_pin(host: str, port, fp: str | None) -> None:
    """The pin this thread's next connections to host:port must match (replaces earlier ones)."""
    fp = normalize(fp or "")
    _local.pins = {_key(host, port): fp} if fp else {}


def pin_for(host: str, port) -> str:
    return (getattr(_local, "pins", None) or {}).get(_key(host, port), "")


def fetch(host: str, port: int, timeout: float = 10.0) -> str:
    """The SHA-256 fingerprint of the certificate host:port presents (no verification)."""
    h = (host or "").strip().strip("[]")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ipaddress.ip_address(h)
        sni = None
    except ValueError:
        sni = h
    with socket.create_connection((h, int(port)), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise PinError(f"{h}:{port} presented no certificate.")
    return of_der(der)


def mismatch_message(host_label: str, expected: str, got: str = "") -> str:
    return (f"The TLS {MISMATCH_MARK} for {host_label}: pinned SHA-256 {pretty(expected)}"
            + (f", the host now presents {pretty(got)}" if got else "")
            + ". Nothing was sent to it. If the host's certificate was replaced on purpose, accept the new one "
              "on Edit host after checking it on the node; otherwise someone may be intercepting the connection.")


# --------------------------------------------------------------------------- #
# requests / urllib3: assert the fingerprint for pinned host:port pairs
# --------------------------------------------------------------------------- #

_orig_pool_key = HTTPAdapter.build_connection_pool_key_attributes


def _pool_key_with_pin(self, request, verify, cert=None):
    host_params, pool_kwargs = _orig_pool_key(self, request, verify, cert)
    if host_params.get("scheme") == "https" and verify is False:
        host, port = host_params.get("host", ""), host_params.get("port") or 443
        fp = pin_for(host, port)
        if not fp:
            import requests

            raise requests.exceptions.SSLError(
                f"Refused an unverified TLS connection to {host}:{port}: no certificate is pinned for it.")
        pool_kwargs.pop("ssl_context", None)
        pool_kwargs["cert_reqs"] = "CERT_NONE"
        pool_kwargs["assert_fingerprint"] = fp
    return host_params, pool_kwargs


def install() -> None:
    if HTTPAdapter.build_connection_pool_key_attributes is not _pool_key_with_pin:
        HTTPAdapter.build_connection_pool_key_attributes = _pool_key_with_pin


install()


# --------------------------------------------------------------------------- #
# Host records
# --------------------------------------------------------------------------- #

def prepare(host) -> str:
    """Register the pin for a host record before connecting to it; pin on first use if it has none.
    Returns the pinned fingerprint ('' for CA-verified hosts)."""
    if getattr(host, "verify_ssl", False):
        set_pin(host.host, host.port, None)   # CA-verified: requests checks the chain and the name itself
        return ""
    fp = normalize(getattr(host, "tls_fingerprint", "") or "")
    if not fp and not getattr(host, "id", None):
        fp = saved_pin(host.host, host.port)   # a test of an address a saved host already pinned: keep that pin
    if not fp:
        fp = fetch(host.host, host.port)
        if getattr(host, "id", None):
            fp = _store_first_pin(host, fp)
        host.tls_fingerprint = fp
    set_pin(host.host, host.port, fp)
    return fp


def saved_pin(host: str, port) -> str:
    """The pin of a saved host record at this address, if any."""
    from .database import db_session
    from .models import ProxmoxHost

    want = _key(host, port)
    with db_session() as db:
        for h in db.query(ProxmoxHost).filter(ProxmoxHost.port == int(port or 0), ProxmoxHost.verify_ssl.is_(False),
                                              ProxmoxHost.tls_fingerprint != "").all():
            if _key(h.host, h.port) == want:
                return normalize(h.tls_fingerprint)
    return ""


def _store_first_pin(host, fp: str) -> str:
    """Persist a first-use pin unless another request pinned this host meanwhile (that one wins)."""
    from sqlalchemy import update

    from .database import db_session
    from .models import ProxmoxHost

    with db_session() as db:
        res = db.execute(update(ProxmoxHost).where(ProxmoxHost.id == host.id, ProxmoxHost.tls_fingerprint == "")
                         .values(tls_fingerprint=fp))
        if res.rowcount == 0:
            row = db.get(ProxmoxHost, host.id)
            return normalize(row.tls_fingerprint) if row is not None and row.tls_fingerprint else fp
    log.info("pinned TLS certificate of %s (%s:%s) on first use: %s", host.name, host.host, host.port, pretty(fp))
    try:
        from . import events

        events.event("system", "host.tls_pinned", "ok", host_id=host.id, host_name=host.name,
                    details={"address": f"{host.host}:{host.port}", "sha256": pretty(fp), "how": "first use"})
    except Exception:  # noqa: BLE001
        pass
    return fp


def explain(exc: Exception, host) -> str | None:
    """A user-facing message when a connection failed because of the pin, else None."""
    text = str(exc).lower()
    if "fingerprints did not match" not in text and MISMATCH_MARK not in text:
        return None
    got = ""
    try:
        got = fetch(host.host, host.port, timeout=5)
    except Exception:  # noqa: BLE001
        pass
    return mismatch_message(f"{host.name} ({host.host}:{host.port})", pin_for(host.host, host.port) or
                            getattr(host, "tls_fingerprint", ""), got)


# --------------------------------------------------------------------------- #
# websockets (console relay)
# --------------------------------------------------------------------------- #

def pinned_connection(expected: str):
    """A websockets ClientConnection class that refuses to send the upgrade request (with the
    root@pam cookie) unless the peer certificate matches `expected`."""
    from websockets.asyncio.client import ClientConnection

    expected = normalize(expected)

    class PinnedConnection(ClientConnection):
        async def handshake(self, *args, **kwargs):
            sslobj = self.transport.get_extra_info("ssl_object") if self.transport else None
            der = sslobj.getpeercert(binary_form=True) if sslobj is not None else None
            got = of_der(der) if der else ""
            if not expected or got != expected:
                self.transport.abort()
                raise PinError(mismatch_message("the console host", expected, got))
            return await super().handshake(*args, **kwargs)

    return PinnedConnection
