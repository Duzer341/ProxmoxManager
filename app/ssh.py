"""SSH access to Proxmox nodes (paramiko) for the things the PVE API cannot do:
apt upgrades, reboots. Host keys are pinned on first use."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import socket
from typing import Any

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy.orm import Session

from . import crypto
from .models import AppSetting, ProxmoxHost, SshHostKey

log = logging.getLogger(__name__)

APP_KEY_PRIV = "ssh_app_private_key"  # encrypted OpenSSH PEM
APP_KEY_PUB = "ssh_app_public_key"  # "ssh-ed25519 AAAA... comment"
CONNECT_TIMEOUT = 12


class SshError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Dashboard keypair
# --------------------------------------------------------------------------- #

def get_app_public_key(db: Session) -> str:
    row = db.get(AppSetting, APP_KEY_PUB)
    return row.value if row else ""


def generate_app_keypair(db: Session) -> str:
    """Create (or replace) the dashboard's own ed25519 keypair. Returns the public key line."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
    ).decode()
    pub = priv.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    pub_line = f"{pub} proxmox-manager"
    for key, value in ((APP_KEY_PRIV, crypto.encrypt(pem)), (APP_KEY_PUB, pub_line)):
        row = db.get(AppSetting, key)
        if row is None:
            db.add(AppSetting(key=key, value=value))
        else:
            row.value = value
    db.commit()
    return pub_line


def _app_private_key(db: Session) -> paramiko.PKey:
    row = db.get(AppSetting, APP_KEY_PRIV)
    if row is None:
        raise SshError("The dashboard has no SSH key yet. Generate one under Hosts → Dashboard SSH key.")
    return load_private_key(crypto.decrypt(row.value))


def load_private_key(pem: str) -> paramiko.PKey:
    pem = pem.strip() + "\n"
    errors = []
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key(io.StringIO(pem))
        except paramiko.PasswordRequiredException:
            raise SshError("The private key is passphrase-protected; use a key without a passphrase.")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{cls.__name__}: {exc}")
    raise SshError("Could not parse the private key (expected an OpenSSH or PEM ed25519/RSA/ECDSA key).")


def fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


# --------------------------------------------------------------------------- #
# Addresses
# --------------------------------------------------------------------------- #

def node_address(host: ProxmoxHost, node: str, summary: dict | None) -> str:
    """Where to SSH for a given node: explicit override > cluster-reported IP > host address."""
    if host.ssh_node_addrs:
        try:
            overrides = json.loads(host.ssh_node_addrs)
            if overrides.get(node):
                return overrides[node]
        except json.JSONDecodeError:
            pass
    nodes = (summary or {}).get("nodes") or []
    if len(nodes) <= 1:
        return host.host
    for n in nodes:
        if n.get("node") == node and n.get("ip"):
            return n["ip"]
    return host.host


# --------------------------------------------------------------------------- #
# Connection
# --------------------------------------------------------------------------- #

class PinnedHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Trust on first use; refuse if a node's key changes."""

    def __init__(self, db: Session, host: ProxmoxHost, node: str, address: str):
        self.db, self.host, self.node, self.address = db, host, node, address

    def missing_host_key(self, client, hostname, key):  # noqa: D401
        row = (
            self.db.query(SshHostKey).filter(SshHostKey.host_id == self.host.id, SshHostKey.node == self.node).first()
        )
        b64 = key.get_base64()
        if row is None:
            self.db.add(
                SshHostKey(
                    host_id=self.host.id,
                    node=self.node,
                    address=self.address,
                    key_type=key.get_name(),
                    key_b64=b64,
                    fingerprint=fingerprint(key),
                )
            )
            self.db.commit()
            log.info("Pinned SSH host key for %s/%s (%s)", self.host.name, self.node, fingerprint(key))
            return
        if row.key_type == key.get_name() and row.key_b64 == b64:
            return
        raise SshError(
            f"SSH host key for {self.node} ({self.address}) has CHANGED: stored {row.fingerprint}, "
            f"offered {fingerprint(key)}. If the node was reinstalled, edit the host and use "
            "'Forget SSH host keys'; otherwise investigate before connecting."
        )


def connect(db: Session, host: ProxmoxHost, node: str, address: str | None = None) -> paramiko.SSHClient:
    if not host.ssh_enabled:
        raise SshError("SSH is not enabled for this host (edit the host to configure it).")
    address = address or node_address(host, node, _summary(host))
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(PinnedHostKeyPolicy(db, host, node, address))
    kwargs: dict[str, Any] = dict(
        hostname=address,
        port=host.ssh_port or 22,
        username=host.ssh_user or "root",
        timeout=CONNECT_TIMEOUT,
        banner_timeout=20,
        auth_timeout=20,
        allow_agent=False,
        look_for_keys=False,
    )
    if host.ssh_auth == "password":
        kwargs["password"] = crypto.decrypt(host.ssh_secret_enc)
    elif host.ssh_auth == "key":
        kwargs["pkey"] = load_private_key(crypto.decrypt(host.ssh_secret_enc))
    else:
        kwargs["pkey"] = _app_private_key(db)
    try:
        client.connect(**kwargs)
    except SshError:
        raise
    except paramiko.AuthenticationException as exc:
        raise SshError(
            f"SSH authentication failed for {kwargs['username']}@{address}: {exc}. "
            + (
                "Check that the dashboard's public key is in /root/.ssh/authorized_keys on the node."
                if host.ssh_auth == "appkey"
                else "Check the key/password, and that PermitRootLogin allows it in sshd_config."
            )
        ) from exc
    except (socket.timeout, TimeoutError) as exc:
        raise SshError(f"SSH connection to {address}:{kwargs['port']} timed out.") from exc
    except (OSError, paramiko.SSHException) as exc:
        raise SshError(f"SSH connection to {address}:{kwargs['port']} failed: {exc}") from exc
    return client


def _summary(host: ProxmoxHost) -> dict | None:
    try:
        return json.loads(host.last_summary_json) if host.last_summary_json else None
    except json.JSONDecodeError:
        return None


def run(client: paramiko.SSHClient, cmd: str, timeout: int = 60) -> tuple[int, str]:
    """Run a command, return (exit_code, combined stdout+stderr)."""
    transport = client.get_transport()
    if transport is None or not transport.is_active():
        raise SshError("SSH connection is no longer active.")
    chan = transport.open_session(timeout=timeout)
    chan.settimeout(timeout)
    chan.set_combine_stderr(True)
    chan.exec_command(cmd)
    chunks: list[bytes] = []
    try:
        while True:
            data = chan.recv(65536)
            if not data:
                break
            chunks.append(data)
    except socket.timeout as exc:
        chan.close()
        raise SshError(f"Command timed out after {timeout}s: {cmd[:80]}") from exc
    rc = chan.recv_exit_status()
    chan.close()
    return rc, b"".join(chunks).decode("utf-8", "replace")


def probe(db: Session, address: str, port: int, username: str, auth: str, secret: str) -> dict[str, Any]:
    """Connectivity + auth check for the host form's 'Test SSH' button. Does not pin host keys."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict[str, Any] = dict(
        hostname=address, port=port, username=username or "root", timeout=CONNECT_TIMEOUT,
        banner_timeout=20, auth_timeout=20, allow_agent=False, look_for_keys=False,
    )
    if auth == "password":
        kwargs["password"] = secret
    elif auth == "key":
        kwargs["pkey"] = load_private_key(secret)
    else:
        kwargs["pkey"] = _app_private_key(db)
    try:
        client.connect(**kwargs)
    except paramiko.AuthenticationException as exc:
        raise SshError(
            f"SSH authentication failed for {kwargs['username']}@{address}: {exc}. "
            + ("Is the dashboard's public key in /root/.ssh/authorized_keys on the node?" if auth == "appkey"
               else "Check the key/password and PermitRootLogin in /etc/ssh/sshd_config.")
        ) from exc
    except (socket.timeout, TimeoutError) as exc:
        raise SshError(f"SSH connection to {address}:{port} timed out.") from exc
    except (OSError, paramiko.SSHException) as exc:
        raise SshError(f"SSH connection to {address}:{port} failed: {exc}") from exc
    try:
        rc, out = run(client, "hostname; id -u; pveversion 2>/dev/null || echo no-pveversion; uname -r", timeout=20)
    finally:
        client.close()
    lines = [l.strip() for l in out.splitlines()]
    key = kwargs.get("pkey")
    return {
        "ok": rc == 0,
        "address": address,
        "hostname": lines[0] if lines else "",
        "is_root": (lines[1] if len(lines) > 1 else "") == "0",
        "pveversion": lines[2] if len(lines) > 2 else "",
        "kernel": lines[3] if len(lines) > 3 else "",
        "key_fingerprint": fingerprint(key) if key is not None else "",
    }


def forget_host_keys(db: Session, host: ProxmoxHost) -> int:
    n = db.query(SshHostKey).filter(SshHostKey.host_id == host.id).delete()
    db.commit()
    return n
