from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class AgentDeviceProfile(Base):
    """Per-section attacker device intelligence collected via recruited agents.

    One row per (agent_id, section); `data` holds {"fields": {...}, "raw": str}
    parsed from the completing task's output.
    """

    __tablename__ = "c2_device_profiles"
    __table_args__ = (
        UniqueConstraint("agent_id", "section", name="uq_deviceprofile_agent_section"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    section: Mapped[str] = mapped_column(String(32), index=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    task_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
