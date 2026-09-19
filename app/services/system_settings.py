"""Runtime platform settings backed by the system_settings table.

Currently manages the console security access path: the URL prefix the
admin console is served under (default ``agentcapture``). Requests to
``/admin`` are answered with 404 whenever the configured path differs, so
the console is not discoverable at the well-known location. Edited from
系统设置 (System Settings) with a short TTL cache because the middleware
consults it on every request.
"""
from __future__ import annotations

import re
import threading
import time

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.system_setting import SystemSetting

ADMIN_ACCESS_PATH_KEY = "admin_access_path"
DEFAULT_ADMIN_ACCESS_PATH = "agentcapture"

# First path segments that already belong to other console/protocol routes —
# a custom access path must not shadow or collide with them.
RESERVED_ADMIN_PATHS = frozenset({
    "admin", "api", "static", "healthz", "console", "c2", "collect",
    "recon", "payload", "portal", "mcp", "intranet", "latest",
    "_agent", "_trap", "_bait", "_clone", "_preview", "favicon.ico",
})

_PATH_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,48}$")

_CACHE: str | None = None
_CACHE_AT: float = 0.0
_LOCK = threading.Lock()
_TTL_SECONDS = 5.0


def validate_admin_path(value: str) -> str | None:
    """Return an error message for invalid paths, or None when acceptable."""
    v = (value or "").strip().strip("/").lower()
    if not v:
        return "访问路径不能为空"
    if not _PATH_RE.fullmatch(v):
        return "仅允许小写字母、数字与连字符，长度 3-49，且以字母或数字开头"
    if v in RESERVED_ADMIN_PATHS:
        return f"「{v}」为系统保留路径，不能使用"
    return None


def _resolve_raw(db: Session) -> str:
    row = db.get(SystemSetting, ADMIN_ACCESS_PATH_KEY)
    if row and (row.value or "").strip():
        return row.value.strip().strip("/").lower()
    return get_settings().admin_access_path.strip().strip("/").lower()


def get_admin_access_path() -> str:
    """Current console path prefix (TTL-cached; middleware calls per request)."""
    global _CACHE, _CACHE_AT
    now = time.monotonic()
    if _CACHE is not None and now - _CACHE_AT < _TTL_SECONDS:
        return _CACHE
    from app.core.db import SessionLocal

    try:
        with SessionLocal() as db:
            value = _resolve_raw(db)
    except Exception:  # noqa: BLE001 — fail-open to the settings default when DB is unavailable
        value = get_settings().admin_access_path.strip().strip("/").lower()
    with _LOCK:
        _CACHE = value
        _CACHE_AT = now
    return value


def set_admin_access_path(db: Session, value: str, actor: str) -> None:
    from datetime import UTC, datetime

    v = (value or "").strip().strip("/").lower()
    row = db.get(SystemSetting, ADMIN_ACCESS_PATH_KEY)
    if row is None:
        row = SystemSetting(key=ADMIN_ACCESS_PATH_KEY)
        db.add(row)
    row.value = v
    row.updated_by = (actor or "")[:64]
    row.updated_at = datetime.now(UTC)
    db.commit()
    invalidate_admin_path_cache()


def invalidate_admin_path_cache() -> None:
    global _CACHE
    with _LOCK:
        _CACHE = None


def seed_admin_access_path(db: Session) -> None:
    """Insert the shipped default on first boot; never override a custom value."""
    if db.get(SystemSetting, ADMIN_ACCESS_PATH_KEY) is None:
        db.add(SystemSetting(
            key=ADMIN_ACCESS_PATH_KEY,
            value=DEFAULT_ADMIN_ACCESS_PATH,
            updated_by="seed",
        ))
        db.commit()
