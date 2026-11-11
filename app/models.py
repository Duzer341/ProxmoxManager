"""Database models."""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="viewer")  # admin | technician | viewer
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # local = username/password (optionally with TOTP); entra = Microsoft Entra ID sign-in.
    auth_source: Mapped[str] = mapped_column(String(16), nullable=False, default="local")
    # Entra: immutable object id (oid claim) and tenant id; the account is matched on these.
    entra_oid: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    entra_tid: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    display_name: Mapped[str] = mapped_column(String(128), nullable=False, default="")

    # TOTP (authenticator app). Secrets are Fernet-encrypted; recovery codes are SHA-256 hashes.
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mfa_secret_enc: Mapped[str] = mapped_column(Text, nullable=False, default="")
    mfa_pending_secret_enc: Mapped[str] = mapped_column(Text, nullable=False, default="")
    mfa_last_step: Mapped[int] = mapped_column(Integer, nullable=False, default=0)  # replay protection
    mfa_recovery_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    mfa_enabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # random key also stored in the session cookie. Changing it signs the user out of every
    # browser (password / authenticator reset, role change, disable). A deleted user's cookie can't
    # authenticate as a new user who later gets the same id.
    session_key: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    # one-time code an admin gives a privileged user for the first authenticator setup
    enroll_code_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    enroll_code_expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # the password was set by an administrator (new account or reset); the user sets
    # their own at the next sign-in, after the authenticator step, before the session starts.
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # colour theme, stored on the account so it follows the user to any browser.
    theme: Mapped[str] = mapped_column(String(8), nullable=False, default="dark")  # dark | light | system

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def rotate_session_key(self) -> None:
        import secrets

        self.session_key = secrets.token_hex(16)

    @property
    def is_technician(self) -> bool:
        return self.role == "technician"

    def can(self, cap: str) -> bool:
        """Role permission check (app/permissions.py is the single source of truth)."""
        from .permissions import role_can

        return bool(self.is_active) and role_can(self.role, cap)

    @property
    def caps(self) -> list[str]:
        from .permissions import caps_for

        return caps_for(self.role) if self.is_active else []

    @property
    def is_sso(self) -> bool:
        return self.auth_source == "entra"


class ProxmoxHost(Base):
    """One Proxmox VE endpoint. If it is a cluster member, the API returns the whole cluster."""

    __tablename__ = "proxmox_hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    client: Mapped[str] = mapped_column(String(128), nullable=False, default="")  # grouping label
    host: Mapped[str] = mapped_column(String(255), nullable=False)  # IP or DNS name
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=8006)
    # Optional override for the clickable web UI link (e.g. a VPN-side address).
    web_url: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    verify_ssl: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # SHA-256 of the pinned certificate when verify_ssl is off ("" = pin on first use)
    tls_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    auth_type: Mapped[str] = mapped_column(String(16), nullable=False, default="token")  # token | password
    # For token auth: user = "monitor@pve", token_name = "dashboard", secret = token value
    # For password auth: user = "root@pam", secret = password
    pve_user: Mapped[str] = mapped_column(String(128), nullable=False)
    token_name: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    secret_enc: Mapped[str] = mapped_column(Text, nullable=False)  # Fernet-encrypted

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # SSH access (used for apt upgrades, reboots - things the PVE API cannot do).
    ssh_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ssh_user: Mapped[str] = mapped_column(String(64), nullable=False, default="root")
    ssh_port: Mapped[int] = mapped_column(Integer, nullable=False, default=22)
    # appkey = the dashboard's own generated keypair; key = pasted private key; password
    ssh_auth: Mapped[str] = mapped_column(String(16), nullable=False, default="appkey")
    ssh_secret_enc: Mapped[str] = mapped_column(Text, nullable=False, default="")  # key PEM or password
    # SSH host key fingerprint (SHA256:...) the admin confirmed with Test SSH; with SSH password auth a
    # node's first key must match it before the password is sent
    ssh_host_key: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    # nodes with the update agent, JSON {"node": {"version": 1, "seen_at": iso}}
    agent_json: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Optional per-node SSH address overrides, JSON {"node": "ip-or-dns"}; otherwise the
    # cluster-reported node IP is used, or the host address for single nodes.
    ssh_node_addrs: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # optional friendly name per cluster node, JSON {"node": "name"} (host page, console titles)
    node_names: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # free-form labels, JSON list ["site-erie", "backup-target"] (dashboard chips + filter)
    tags: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Optional root@pam password used only to sign the browser in to the PVE web UI
    # (Upgrade shell). Fernet-encrypted; empty = ask each time.
    console_secret_enc: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Last poll results (summary JSON produced by the collector).
    last_poll_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_ok_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    last_summary_json: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # last network read per node, JSON {"node": {"at": iso, "net": {...}}}, shown (marked as
    # last known) while the host or node can't be reached
    network_json: Mapped[str] = mapped_column(Text, nullable=False, default="")

    samples = relationship("StatSample", back_populates="host", cascade="all, delete-orphan")
    smart_results = relationship("SmartResult", back_populates="host", cascade="all, delete-orphan")
    jobs = relationship("Job", back_populates="host", cascade="all, delete-orphan")
    ssh_keys = relationship("SshHostKey", back_populates="host", cascade="all, delete-orphan")

    @property
    def ui_url(self) -> str:
        if self.web_url:
            return self.web_url
        return f"https://{self.host}:{self.port}/"


class StatSample(Base):
    """One aggregated sample per host per poll; used for rolling averages."""

    __tablename__ = "stat_samples"
    __table_args__ = (Index("ix_stat_samples_host_ts", "host_id", "ts"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("proxmox_hosts.id", ondelete="CASCADE"), nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    cpu_pct: Mapped[float] = mapped_column(Float, nullable=False)
    mem_pct: Mapped[float] = mapped_column(Float, nullable=False)
    disk_pct: Mapped[float] = mapped_column(Float, nullable=False)

    host = relationship("ProxmoxHost", back_populates="samples")


class SmartResult(Base):
    """Most recent SMART read for a physical disk on a node."""

    __tablename__ = "smart_results"
    __table_args__ = (Index("ix_smart_host_node_disk", "host_id", "node", "devpath", unique=True),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("proxmox_hosts.id", ondelete="CASCADE"), nullable=False)
    node: Mapped[str] = mapped_column(String(128), nullable=False)
    devpath: Mapped[str] = mapped_column(String(128), nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    health: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    result_json: Mapped[str] = mapped_column(Text, nullable=False, default="")
    requested_by: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    host = relationship("ProxmoxHost", back_populates="smart_results")


class SshHostKey(Base):
    """Pinned SSH host key per node (trust on first use)."""

    __tablename__ = "ssh_host_keys"
    __table_args__ = (Index("ix_ssh_host_keys_host_node", "host_id", "node", unique=True),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("proxmox_hosts.id", ondelete="CASCADE"), nullable=False)
    node: Mapped[str] = mapped_column(String(128), nullable=False)
    address: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    key_type: Mapped[str] = mapped_column(String(64), nullable=False)
    key_b64: Mapped[str] = mapped_column(Text, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    host = relationship("ProxmoxHost", back_populates="ssh_keys")


class Job(Base):
    """A long-running action against one node (apt upgrade, reboot, update check)."""

    __tablename__ = "jobs"
    __table_args__ = (Index("ix_jobs_host_created", "host_id", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("proxmox_hosts.id", ondelete="CASCADE"), nullable=False)
    node: Mapped[str] = mapped_column(String(128), nullable=False)
    # Set for guest jobs (power, snapshot, backup); NULL for node jobs.
    vmid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)  # check_updates | upgrade | reboot | guest_* ...
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")  # queued|running|done|failed
    requested_by: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    options_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    output: Mapped[str] = mapped_column(Text, nullable=False, default="")
    result_json: Mapped[str] = mapped_column(Text, nullable=False, default="")  # structured outcome
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    host = relationship("ProxmoxHost", back_populates="jobs")


class AppSetting(Base):
    """Key/value settings (e.g. the dashboard's own SSH keypair, encrypted)."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class RevokedSession(Base):
    """A browser sign-in that was signed out. Session cookies are signed, not stored, so
    signing out records the sign-in's random id here; the cookie is refused from then on even if
    someone kept a copy. Rows are pruned after PM_SESSION_MAX_AGE."""

    __tablename__ = "revoked_sessions"

    sid: Mapped[str] = mapped_column(String(64), primary_key=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class ConsoleLog(Base):
    """One console session through the relay: who, what, when, how much."""

    __tablename__ = "console_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    host_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    host_name: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    node: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    vmid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)  # vm | ct | shell | upgrade
    label: Mapped[str] = mapped_column(String(160), nullable=False, default="")
    client_ip: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    connected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    end_reason: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    bytes_to_host: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    bytes_from_host: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # how the console re-auth was done (totp / entra)
    stepup_method: Mapped[str] = mapped_column(String(16), nullable=False, default="")


TAG_MAX = 20          # tags per host
TAG_MAX_LEN = 40      # characters per tag


def tags_of(host) -> list[str]:
    """A host's tags ([] when none or unreadable)."""
    import json

    try:
        d = json.loads(getattr(host, "tags", "") or "[]")
    except ValueError:
        return []
    return [str(t) for t in d if str(t).strip()] if isinstance(d, list) else []


def clean_tags(values) -> list[str]:
    """Trimmed, inner whitespace collapsed, case-insensitive duplicates dropped (first spelling kept),
    in the order given. Raises ValueError for too many / too long / control characters."""
    out: list[str] = []
    seen: set[str] = set()
    for v in values or []:
        t = " ".join(str(v).split())
        if not t:
            continue
        if len(t) > TAG_MAX_LEN:
            raise ValueError(f"Tag '{t[:20]}…' is longer than {TAG_MAX_LEN} characters.")
        if any(ord(c) < 32 or c in "<>," for c in t):
            raise ValueError(f"Tag '{t}' has a character tags can't contain (comma, < or >).")
        if t.lower() in seen:
            continue
        seen.add(t.lower())
        out.append(t)
    if len(out) > TAG_MAX:
        raise ValueError(f"A host can have at most {TAG_MAX} tags.")
    return out


def node_names_of(host) -> dict[str, str]:
    """A host's per-node friendly names ({} when none or unreadable)."""
    import json

    try:
        d = json.loads(getattr(host, "node_names", "") or "{}")
    except ValueError:
        return {}
    return {str(k): str(v) for k, v in d.items() if v} if isinstance(d, dict) else {}
