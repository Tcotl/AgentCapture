from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class PromptInjectionTemplate(Base):
    __tablename__ = "prompt_injection_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    template_key: Mapped[str] = mapped_column(String(96), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default="")
    target_scope: Mapped[str] = mapped_column(String(48), default="html_response", index=True)
    trigger_type: Mapped[str] = mapped_column(String(48), default="always", index=True)
    priority: Mapped[int] = mapped_column(Integer, default=50)
    content_template: Mapped[str] = mapped_column(Text)
    variables_json: Mapped[list] = mapped_column(JSON, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
