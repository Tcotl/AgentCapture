from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class C2Listener(Base):
    __tablename__ = "c2_listeners"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    protocol: Mapped[str] = mapped_column(String(16), index=True)  # tcp/http/https/udp/icmp/dns
    bind_address: Mapped[str] = mapped_column(String(255), default="0.0.0.0")
    bind_port: Mapped[int] = mapped_column(Integer, default=80)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Agent-side registration token (ported from PentestManusWeb c2_control):
    # implants present it in the heartbeat body / X-Client-Token header so the
    # operator can bind and revoke beacons per listener.
    registration_token: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ssl_cert_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ssl_key_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    config_json: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="stopped")  # running/stopped/error
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
