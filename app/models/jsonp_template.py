from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class JsonpTemplate(Base):
    __tablename__ = "jsonp_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    method_key: Mapped[str] = mapped_column(String(96), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120))
    request_method: Mapped[str] = mapped_column(String(16), default="GET")
    endpoint_path: Mapped[str] = mapped_column(String(160), default="/recon/jsonp")
    callback_param: Mapped[str] = mapped_column(String(64), default="callback")
    description: Mapped[str] = mapped_column(Text, default="")
    params_json: Mapped[list] = mapped_column(JSON, default=list)
    response_template: Mapped[str] = mapped_column(Text, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
