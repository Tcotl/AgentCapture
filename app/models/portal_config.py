from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class PortalConfig(Base):
    """Runtime configuration for the functional-camouflage counter channel.

    Single-row table (id=1) seeded on first read. The middleware and the
    portal endpoints consult it on every request, so reads go through a
    short-TTL cache in ``app.services.portal_config``.
    """

    __tablename__ = "portal_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    footer_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    footer_title: Mapped[str] = mapped_column(String(120), default="Developer API")
    heartbeat_interval: Mapped[int] = mapped_column(Integer, default=30)
    register_max_per_ip_hour: Mapped[int] = mapped_column(Integer, default=20)
    updated_by: Mapped[str] = mapped_column(String(64), default="system")
    notes: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
