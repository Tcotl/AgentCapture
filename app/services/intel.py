import ipaddress
import threading
import time

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.models.intel import ThreatIntelEntry

# Whitelist entries sit on the hottest path of the whole platform (checked for
# every captured request). Loading and parsing them per request is wasteful —
# the table changes rarely, so cache the parsed networks for a short TTL.
_WHITELIST_TTL_SECONDS = 60.0
_cache_lock = threading.Lock()
_cache: dict = {"ts": 0.0, "entries": []}


def invalidate_whitelist_cache() -> None:
    """Drop the cached whitelist (call after any intel CRUD from the admin)."""
    with _cache_lock:
        _cache["ts"] = 0.0
        _cache["entries"] = []


def _load_whitelist(db: Session) -> list:
    stmt = select(ThreatIntelEntry).where(
        ThreatIntelEntry.entry_type == "whitelist",
        ThreatIntelEntry.is_active.is_(True),
    )
    parsed: list = []
    for entry in db.scalars(stmt).all():
        value = entry.value.strip()
        try:
            if "/" in value:
                parsed.append(ipaddress.ip_network(value, strict=False))
            else:
                parsed.append(ipaddress.ip_address(value))
        except ValueError:
            continue
    return parsed


def _cached_whitelist(db: Session) -> list:
    now = time.monotonic()
    with _cache_lock:
        if _cache["entries"] and (now - _cache["ts"]) < _WHITELIST_TTL_SECONDS:
            return _cache["entries"]
    entries = _load_whitelist(db)
    with _cache_lock:
        _cache["ts"] = now
        _cache["entries"] = entries
    return entries


def is_ip_whitelisted(db: Session, ip_text: str) -> bool:
    if not ip_text or ip_text == "unknown":
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        return False

    for entry in _cached_whitelist(db):
        try:
            if isinstance(entry, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                if ip_obj in entry:
                    return True
            elif ip_obj == entry:
                return True
        except (TypeError, ValueError):
            continue
    return False


def list_intel_entries(db: Session) -> list[ThreatIntelEntry]:
    stmt = select(ThreatIntelEntry).order_by(desc(ThreatIntelEntry.created_at))
    return list(db.scalars(stmt).all())


def intel_stats(db: Session) -> dict[str, int]:
    total = int(db.scalar(select(func.count()).select_from(ThreatIntelEntry)) or 0)
    whitelist = int(
        db.scalar(
            select(func.count()).select_from(ThreatIntelEntry).where(
                ThreatIntelEntry.entry_type == "whitelist"
            )
        )
        or 0
    )
    return {"total": total, "whitelist": whitelist}
