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
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="viewer")  # admin | viewer
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


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
    # Optional per-node SSH address overrides, JSON {"node": "ip-or-dns"}; otherwise the
    # cluster-reported node IP is used, or the host address for single nodes.
    ssh_node_addrs: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Optional root@pam password used only to sign the browser in to the PVE web UI
    # (Upgrade shell). Fernet-encrypted; empty = ask each time.
    console_secret_enc: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Last poll results (summary JSON produced by the collector).
    last_poll_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_ok_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    last_summary_json: Mapped[str] = mapped_column(Text, nullable=False, default="")

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
