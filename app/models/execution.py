from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class ExecutionHistory(Base):
    __tablename__ = "execution_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    actor_username: Mapped[str] = mapped_column(String(100), default="system")
    action: Mapped[str] = mapped_column(String(120), index=True)
    module: Mapped[str] = mapped_column(String(120), index=True)
    target_type: Mapped[str] = mapped_column(String(64), default="")
    target_ref: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(32), default="success")
    detail_json: Mapped[dict] = mapped_column(JSON, default=dict)
