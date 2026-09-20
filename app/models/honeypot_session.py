from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class HoneypotSession(Base):
    """Interactive honeypot session with a full replayable transcript.

    Populated by the paramiko SSH honeypot (auth attempts, every command and
    its output). The transcript is written incrementally so a session can be
    replayed live from the admin UI while the attacker is still connected.
    """

    __tablename__ = "honeypot_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    service: Mapped[str] = mapped_column(String(32), default="ssh", index=True)
    source_ip: Mapped[str] = mapped_column(String(128), index=True)
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(64), default="")
    password: Mapped[str] = mapped_column(String(256), default="")
    auth_attempts: Mapped[int] = mapped_column(Integer, default=0)
    command_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active|closed
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    transcript_json: Mapped[list] = mapped_column(JSON, default=list)
