from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Node(Base):
    __tablename__ = "nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    node_type: Mapped[str] = mapped_column(String(32), default="embedded")
    listen_address: Mapped[str] = mapped_column(String(255), default="127.0.0.1")
    callback_address: Mapped[str] = mapped_column(String(255), default="127.0.0.1")
    status: Mapped[str] = mapped_column(String(32), default="online", index=True)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    template_id: Mapped[int | None] = mapped_column(ForeignKey("service_templates.id"), nullable=True)
    deployed_services_json: Mapped[list] = mapped_column(JSON, default=list)
    tags_json: Mapped[list] = mapped_column(JSON, default=list)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
