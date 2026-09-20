from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class IsolationEntry(Base):
    """Persistent isolation decision (isolate / confirmed canary echo).

    The risk engine's ``isolate`` decision used to be a per-request page swap
    with no state, so an attacker could simply rotate cookies. Entries here
    are checked by the capture middleware before scoring and short-circuit
    the request for the whole TTL window.
    """

    __tablename__ = "isolation_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)  # "ip" | "session"
    value: Mapped[str] = mapped_column(String(128), index=True)
    reason: Mapped[str] = mapped_column(String(64), default="risk_isolate")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_by: Mapped[str] = mapped_column(String(64), default="risk_engine")
