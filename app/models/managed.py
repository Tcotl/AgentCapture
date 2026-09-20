"""Managed-host C2 models (ported from PentestManusWeb managed_hosts stack).

Five tables drive the managed-console face of the C2 deck:
listeners (config), hosts (implant inventory), sessions (routing unit,
one per register), tasks (lease queue) and evidence (op results).

Single-scope deployment: the source's ManagedScope container is collapsed
into an implicit default scope; approvals live inline on the task row.
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ManagedListener(Base):
    __tablename__ = "managed_listeners"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), index=True)
    # http/https/tcp/udp/dns/icmp × bind/reverse (+ http_poll/https_poll/dns_poll server-side)
    transport: Mapped[str] = mapped_column(String(32), index=True)
    bind_address: Mapped[str] = mapped_column(String(255), default="0.0.0.0")
    bind_port: Mapped[int] = mapped_column(Integer, default=8443)
    registration_token: Mapped[str] = mapped_column(String(128), index=True)
    tls_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20), default="active")  # active/disabled/paused
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)  # payloadType, approvalPolicy
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class ManagedHost(Base):
    __tablename__ = "managed_hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    listener_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    # upsert key together with listener_id
    host_uid: Mapped[str] = mapped_column(String(128), index=True)
    display_name: Mapped[str] = mapped_column(String(160), default="")
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    platform: Mapped[str] = mapped_column(String(32), default="unknown")
    architecture: Mapped[str] = mapped_column(String(64), default="unknown")
    os_version: Mapped[str | None] = mapped_column(String(160), nullable=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    internal_ips: Mapped[list] = mapped_column(JSON, default=list)
    external_ips: Mapped[list] = mapped_column(JSON, default=list)
    capabilities: Mapped[dict] = mapped_column(JSON, default=dict)
    integrity_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(
        String(20), default="online", index=True
    )  # online/stale/offline
    labels: Mapped[list] = mapped_column(JSON, default=list)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)  # note, beaconIntervalSeconds
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class ManagedSession(Base):
    __tablename__ = "managed_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(Integer, index=True)
    listener_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    session_key: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    transport: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(
        String(20), default="active", index=True
    )  # active/stale/closed
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    active_task_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class ManagedTask(Base):
    __tablename__ = "managed_tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    session_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    listener_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    task_type: Mapped[str] = mapped_column(String(64), index=True, default="command_run")
    title: Mapped[str] = mapped_column(String(200), default="")
    command_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    arguments_json: Mapped[dict] = mapped_column(JSON, default=dict)
    result_json: Mapped[dict] = mapped_column(JSON, default=dict)  # normalized op result payloads
    risk_level: Mapped[str] = mapped_column(String(20), default="low")
    status: Mapped[str] = mapped_column(String(24), default="queued", index=True)
    # queued -> leased -> running -> completed/failed/cancelled
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    approval_status: Mapped[str] = mapped_column(String(24), default="not_required", index=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    review_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    lease_token: Mapped[str | None] = mapped_column(String(128), nullable=True)
    leased_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    task_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    result_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class ManagedEvidence(Base):
    __tablename__ = "managed_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    session_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    task_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    evidence_type: Mapped[str] = mapped_column(
        String(24), default="summary"
    )  # stdout/file/screenshot/json/summary
    title: Mapped[str | None] = mapped_column(String(200), nullable=True)
    content_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload_json: Mapped[dict] = mapped_column(JSON, default=dict)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
