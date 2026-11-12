"""Persistent isolation state backing the middleware's isolate decision.

Entries are stored in ``isolation_entries`` (see models/isolation.py) so an
isolate/canary-echo verdict survives cookie rotation and page reloads for the
whole TTL window. Expired rows are purged opportunistically (time-gated, at
most once per purge interval) instead of on a background scheduler.
"""

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.isolation import IsolationEntry

logger = logging.getLogger("isolation")

_PURGE_INTERVAL_SECONDS = 300
_purge_lock = threading.Lock()
_last_purge = 0.0


def isolate_target(
    db: Session,
    *,
    kind: str,
    value: str,
    reason: str = "risk_isolate",
    ttl_minutes: int | None = None,
    created_by: str = "risk_engine",
) -> IsolationEntry:
    """Create or extend an active isolation entry for an IP or a session."""
    if not value or kind not in ("ip", "session"):
        raise ValueError(f"invalid isolation target: kind={kind!r} value={value!r}")
    settings = get_settings()
    ttl = settings.isolation_ttl_minutes if ttl_minutes is None else ttl_minutes
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=ttl)
    entry = db.scalar(
        select(IsolationEntry).where(
            IsolationEntry.kind == kind,
            IsolationEntry.value == value,
            IsolationEntry.expires_at > now,
        )
    )
    if entry:
        entry.expires_at = max(entry.expires_at, expires)
        entry.reason = reason
    else:
        entry = IsolationEntry(
            kind=kind, value=value, reason=reason, expires_at=expires, created_by=created_by
        )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def get_active_isolation(
    db: Session, *, source_ip: str, session_id: str
) -> IsolationEntry | None:
    """Return the active isolation entry covering this IP or session, if any."""
    now = datetime.now(timezone.utc)
    conds = []
    if session_id:
        conds.append((IsolationEntry.kind == "session") & (IsolationEntry.value == session_id))
    if source_ip and source_ip != "unknown":
        conds.append((IsolationEntry.kind == "ip") & (IsolationEntry.value == source_ip))
    if not conds:
        return None
    entry = db.scalar(
        select(IsolationEntry)
        .where(or_(*conds), IsolationEntry.expires_at > now)
        .order_by(IsolationEntry.expires_at.desc())
    )
    _maybe_purge(db, now)
    return entry


def list_active_isolations(db: Session, limit: int = 100) -> list[IsolationEntry]:
    now = datetime.now(timezone.utc)
    stmt = (
        select(IsolationEntry)
        .where(IsolationEntry.expires_at > now)
        .order_by(IsolationEntry.expires_at.desc())
        .limit(limit)
    )
    return list(db.scalars(stmt).all())


def revoke_isolation(db: Session, entry_id: int) -> bool:
    entry = db.get(IsolationEntry, entry_id)
    if not entry:
        return False
    db.delete(entry)
    db.commit()
    return True


def purge_expired(db: Session) -> int:
    now = datetime.now(timezone.utc)
    result = db.execute(delete(IsolationEntry).where(IsolationEntry.expires_at <= now))
    db.commit()
    return int(result.rowcount or 0)


def _maybe_purge(db: Session, now: datetime) -> None:
    """Purge expired rows at most once per interval (cheap, opportunistic)."""
    global _last_purge
    current = time.monotonic()
    if current - _last_purge < _PURGE_INTERVAL_SECONDS:
        return
    with _purge_lock:
        if time.monotonic() - _last_purge < _PURGE_INTERVAL_SECONDS:
            return
        _last_purge = time.monotonic()
    try:
        purge_expired(db)
    except Exception as exc:  # never let housekeeping break a request
        logger.debug("isolation purge failed: %s", exc)
