from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class DockerHoneypot(Base):
    """A user-supplied Docker image deployed as a web honeypot.

    AgentCapture manages the container lifecycle through the Docker Engine
    API and fronts it with the deception proxy, which injects decoy API
    routes and bait signals into the traffic.
    """

    __tablename__ = "docker_honeypots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    image: Mapped[str] = mapped_column(String(255))
    container_id: Mapped[str] = mapped_column(String(80), default="")
    container_port: Mapped[int] = mapped_column(Integer, default=80)
    proxy_port: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), default="stopped", index=True)  # running/stopped/error
    error: Mapped[str] = mapped_column(String(500), default="")
    canary: Mapped[str] = mapped_column(String(64), default="")
    baits_json: Mapped[list] = mapped_column(JSON, default=list)  # [{path, body}]
    js_inject: Mapped[bool] = mapped_column(Boolean, default=True)
    upstream_ip: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc)
    )
