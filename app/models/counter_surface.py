from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class CounterSurface(Base):
    """Per-surface enable/disable switch for counter-offense bait faces.

    One row per surface key (agent_files / mcp / dataset / metadata /
    intranet / behavior). Reads go through the TTL cache in
    ``app.services.surface_config`` because the middleware consults it.
    """

    __tablename__ = "counter_surfaces"

    surface_key: Mapped[str] = mapped_column(String(48), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_by: Mapped[str] = mapped_column(String(64), default="system")
    notes: Mapped[str] = mapped_column(Text, default="")
    config_json: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
