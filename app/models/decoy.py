from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class DecoyTemplate(Base):
    __tablename__ = "decoy_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    file_name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    content_template: Mapped[str] = mapped_column(Text)
    username_dictionary: Mapped[str] = mapped_column(Text, default="root")
    password_length: Mapped[int] = mapped_column(Integer, default=16)
    target_service_key: Mapped[str] = mapped_column(String(64), default="ssh")
    decoy_type: Mapped[str] = mapped_column(String(32), default="credential", index=True)
    route_path: Mapped[str] = mapped_column(String(255), default="")
    exposure_channel: Mapped[str] = mapped_column(String(80), default="manual")
    bind_route_template_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bind_credential_template_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class DecoyDeployment(Base):
    __tablename__ = "decoy_deployments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    template_id: Mapped[int | None] = mapped_column(ForeignKey("decoy_templates.id"), nullable=True)
    node_id: Mapped[int | None] = mapped_column(ForeignKey("nodes.id"), nullable=True)
    unique_token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    fetch_path: Mapped[str] = mapped_column(String(255), unique=True)
    deployed_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="generated", index=True)
    generated_username: Mapped[str] = mapped_column(String(120), default="root")
    generated_password: Mapped[str] = mapped_column(String(255), default="")
    target_endpoint: Mapped[str] = mapped_column(String(255), default="")
    last_fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_triggered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
