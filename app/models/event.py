from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Event(Base):
    __tablename__ = "events"
    # Composite indexes for the per-request hot queries: velocity counters
    # filter on (session_id|source_ip, created_at) and most admin/console
    # views filter on (event_type, created_at). Single-column indexes alone
    # degrade into full scans once the table grows.
    __table_args__ = (
        Index("ix_events_session_created", "session_id", "created_at"),
        Index("ix_events_ip_created", "source_ip", "created_at"),
        Index("ix_events_type_created", "event_type", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    site_id: Mapped[str] = mapped_column(String(64), index=True)
    session_id: Mapped[str] = mapped_column(String(64), index=True)
    source_ip: Mapped[str] = mapped_column(String(128), index=True)
    method: Mapped[str] = mapped_column(String(16), default="GET")
    path: Mapped[str] = mapped_column(String(512), index=True)
    status_code: Mapped[int] = mapped_column(Integer, default=200)
    event_type: Mapped[str] = mapped_column(String(32), default="http_request")
    user_agent: Mapped[str] = mapped_column(Text, default="")
    headers_json: Mapped[dict] = mapped_column(JSON, default=dict)
    payload_json: Mapped[dict] = mapped_column(JSON, default=dict)
    signals_json: Mapped[list] = mapped_column(JSON, default=list)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    decision: Mapped[str] = mapped_column(String(32), default="allow")
    token_echo: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Deployment context: which cloned honeypot template (if any) was hit.
    # These are populated by the per-port background proxy so a single
    # ``events`` table can be cross-referenced back to the template that
    # captured the interaction.
    template_id: Mapped[int | None] = mapped_column(
        ForeignKey("service_templates.id"), nullable=True, index=True
    )
    node_id: Mapped[int | None] = mapped_column(
        ForeignKey("nodes.id"), nullable=True, index=True
    )
    deploy_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    deploy_route: Mapped[str | None] = mapped_column(String(255), nullable=True)
