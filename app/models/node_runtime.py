from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class NodeHeartbeat(Base):
    __tablename__ = "node_heartbeats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    node_id: Mapped[int | None] = mapped_column(ForeignKey("nodes.id"), nullable=True, index=True)
    node_name: Mapped[str] = mapped_column(String(120), index=True)
    status: Mapped[str] = mapped_column(String(32), default="online", index=True)
    source_ip: Mapped[str] = mapped_column(String(128), default="unknown")
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metrics_json: Mapped[dict] = mapped_column(JSON, default=dict)
    services_json: Mapped[list] = mapped_column(JSON, default=list)
    payload_json: Mapped[dict] = mapped_column(JSON, default=dict)


class NodeTask(Base):
    __tablename__ = "node_tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )
    node_id: Mapped[int | None] = mapped_column(ForeignKey("nodes.id"), nullable=True, index=True)
    node_name: Mapped[str] = mapped_column(String(120), index=True)
    task_type: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    priority: Mapped[int] = mapped_column(Integer, default=50)
    task_payload_json: Mapped[dict] = mapped_column(JSON, default=dict)
    result_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(100), default="system")
    dispatch_count: Mapped[int] = mapped_column(Integer, default=0)
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
