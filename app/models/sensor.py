"""Sensor-network roster: employee-agent canary sensors (PoC for the
distributed honeypot-marker sensing network).

A sensor is a read-only probe installed inside an employee's AI agent
(Claude Code hooks flagship, MCP tool fallback). It scans content flowing
through the agent's context for honeypot watermark features and reports
hits — the second-hop capture channel for bait data carried out of the
honeypot. Sensors never execute anything; the channel carries no task
capability by design (NodeTask stays a separate system)."""

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Sensor(Base):
    __tablename__ = "sensors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    sensor_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    token: Mapped[str] = mapped_column(String(64), index=True)
    employee: Mapped[str] = mapped_column(String(120), default="")
    device: Mapped[str] = mapped_column(String(120), default="")
    agent_product: Mapped[str] = mapped_column(String(64), default="")
    agent_version: Mapped[str] = mapped_column(String(64), default="")
    mode: Mapped[str] = mapped_column(String(16), default="hooks")  # hooks | mcp
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SensorHit(Base):
    __tablename__ = "sensor_hits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    sensor_id: Mapped[str] = mapped_column(String(64), index=True)
    hit_token: Mapped[str] = mapped_column(String(255))  # the suspected marker string
    feature: Mapped[str] = mapped_column(String(48))  # which pattern matched
    source_kind: Mapped[str] = mapped_column(String(32), default="")  # file | url | tool
    source_ref: Mapped[str] = mapped_column(String(512), default="")  # path / url / tool name
    agent_product: Mapped[str] = mapped_column(String(64), default="")
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    attributed_session: Mapped[str] = mapped_column(String(64), default="", index=True)
    attributed_event_id: Mapped[int] = mapped_column(Integer, nullable=True)
