from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class InternetSystem(Base):
    __tablename__ = "internet_systems"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    name: Mapped[str] = mapped_column(String(160))
    domain: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    upstream_url: Mapped[str] = mapped_column(String(512))
    owner: Mapped[str] = mapped_column(String(120), default="")
    deploy_mode: Mapped[str] = mapped_column(String(80), default="反向代理无损接入")
    status: Mapped[str] = mapped_column(String(60), default="监测模式")
    tls_mode: Mapped[str] = mapped_column(String(80), default="沿用原证书")
    failover_mode: Mapped[str] = mapped_column(String(80), default="异常自动旁路")
    inject_policy: Mapped[str] = mapped_column(String(120), default="仅公开页面注入")
    decoy_policy: Mapped[str] = mapped_column(String(120), default="蜜饵路径 + 假接口")
    jsonp_template_key: Mapped[str] = mapped_column(String(120), default="")
    risk_policy: Mapped[str] = mapped_column(String(80), default="observe")
    notes: Mapped[str] = mapped_column(Text, default="")
    tags_json: Mapped[list] = mapped_column(JSON, default=list)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
