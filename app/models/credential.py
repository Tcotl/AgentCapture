from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class CredentialObservation(Base):
    __tablename__ = "credential_observations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    source_ip: Mapped[str] = mapped_column(String(128), index=True)
    node_name: Mapped[str] = mapped_column(String(120), default="embedded-node")
    service_name: Mapped[str] = mapped_column(String(120), default="web-login")
    username: Mapped[str] = mapped_column(String(255), index=True)
    password: Mapped[str] = mapped_column(String(255), default="")
    path: Mapped[str] = mapped_column(String(255), default="")
    session_id: Mapped[str] = mapped_column(String(64), default="")
    source_label: Mapped[str] = mapped_column(String(120), default="")
    matched_keywords_json: Mapped[list] = mapped_column(JSON, default=list)
