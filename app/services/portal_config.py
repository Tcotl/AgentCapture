"""Runtime configuration service for the functional-camouflage (portal) channel.

The injection middleware reads this on every public request and the portal
endpoints gate on it, so reads are served from a 5-second TTL cache that a
save invalidates immediately — flipping the master switch takes effect on
live traffic without a restart.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.portal_config import PortalConfig

CACHE_TTL_SECONDS = 5.0


@dataclass(frozen=True)
class PortalRuntimeConfig:
    enabled: bool
    footer_enabled: bool
    footer_title: str
    heartbeat_interval: int
    register_max_per_ip_hour: int


_DEFAULTS = PortalRuntimeConfig(
    enabled=True,
    footer_enabled=True,
    footer_title="Developer API",
    heartbeat_interval=30,
    register_max_per_ip_hour=20,
)

_cache: PortalRuntimeConfig | None = None
_cache_at: float = 0.0
_lock = threading.Lock()


def invalidate_cache() -> None:
    global _cache, _cache_at
    with _lock:
        _cache = None
        _cache_at = 0.0


def ensure_row(db: Session) -> PortalConfig:
    row = db.get(PortalConfig, 1)
    if row is None:
        row = PortalConfig(
            id=1,
            enabled=_DEFAULTS.enabled,
            footer_enabled=_DEFAULTS.footer_enabled,
            footer_title=_DEFAULTS.footer_title,
            heartbeat_interval=_DEFAULTS.heartbeat_interval,
            register_max_per_ip_hour=_DEFAULTS.register_max_per_ip_hour,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def get_runtime_config(db: Session) -> PortalRuntimeConfig:
    """Cached read for hot paths (middleware / portal endpoints)."""
    global _cache, _cache_at
    now = time.monotonic()
    if _cache is not None and now - _cache_at < CACHE_TTL_SECONDS:
        return _cache
    row = ensure_row(db)
    cfg = PortalRuntimeConfig(
        enabled=bool(row.enabled),
        footer_enabled=bool(row.footer_enabled),
        footer_title=(row.footer_title or _DEFAULTS.footer_title)[:120],
        heartbeat_interval=max(1, int(row.heartbeat_interval or 30)),
        register_max_per_ip_hour=max(0, int(row.register_max_per_ip_hour or 0)),
    )
    with _lock:
        _cache = cfg
        _cache_at = now
    return cfg


def get_config_row(db: Session) -> PortalConfig:
    return ensure_row(db)


def save_config(
    db: Session,
    *,
    actor: str,
    enabled: bool,
    footer_enabled: bool,
    footer_title: str,
    heartbeat_interval: int,
    register_max_per_ip_hour: int,
    notes: str = "",
) -> PortalConfig:
    row = ensure_row(db)
    row.enabled = bool(enabled)
    row.footer_enabled = bool(footer_enabled)
    row.footer_title = (footer_title or _DEFAULTS.footer_title).strip()[:120] or _DEFAULTS.footer_title
    row.heartbeat_interval = min(3600, max(1, int(heartbeat_interval)))
    row.register_max_per_ip_hour = min(10000, max(0, int(register_max_per_ip_hour)))
    row.notes = (notes or "")[:2000]
    row.updated_by = actor[:64]
    from datetime import datetime, timezone

    row.updated_at = datetime.now(timezone.utc)
    db.add(row)
    db.commit()
    db.refresh(row)
    invalidate_cache()
    return row


def portal_register_count_recent(db: Session, source_ip: str, hours: float = 1.0) -> int:
    """Registrations from one IP inside the sliding window (for the cap)."""
    from datetime import datetime, timedelta, timezone

    from app.models.event import Event

    threshold = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = db.execute(
        select(Event.id).where(
            Event.event_type == "portal_client_registered",
            Event.source_ip == source_ip,
            Event.created_at >= threshold,
        )
    ).all()
    return len(rows)
