"""Runtime platform settings backed by the system_settings table.

Manages, with a short TTL cache (consulted per request):

- Console security access path (``admin_access_path``): the URL prefix the
  admin console is served under (default ``agentcapture``). Requests to
  ``/admin`` are answered with 404 whenever the configured path differs.
  Edited from 系统设置 (System Settings).
- Embedded honeypot master switch (``embedded_honeypot_enabled``): gates the
  console-plane bait callback channels (/collect, /recon, /_agent,
  /payload). Off by default — the embedded layer is opt-in, while the 48777
  web honeypot is the out-of-the-box deception surface.
"""
from __future__ import annotations

import re
import threading
import time
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.system_setting import SystemSetting

ADMIN_ACCESS_PATH_KEY = "admin_access_path"
DEFAULT_ADMIN_ACCESS_PATH = "agentcapture"
EMBEDDED_HONEYPOT_KEY = "embedded_honeypot_enabled"
# Deployment defaults per honeypot type: the 48777 web honeypot is on out of
# the box; the embedded layer (bait snippets inside the operator's own sites)
# and the protocol honeypots stay OFF until the user enables them.
DEFAULT_EMBEDDED_ENABLED = False

# First path segments that already belong to other console/protocol routes —
# a custom access path must not shadow or collide with them.
RESERVED_ADMIN_PATHS = frozenset({
    "admin", "api", "static", "healthz", "console", "c2", "collect",
    "recon", "payload", "portal", "mcp", "intranet", "latest",
    "_agent", "_trap", "_bait", "_clone", "_preview", "favicon.ico",
})

_PATH_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,48}$")

_LOCK = threading.Lock()
_TTL_SECONDS = 5.0
_CACHE: dict[str, tuple[str, float]] = {}


def _cached(key: str):
    """Return the cached (value, at) tuple for key, or (None, 0.0)."""
    with _LOCK:
        entry = _CACHE.get(key)
    if entry is None or time.monotonic() - entry[1] >= _TTL_SECONDS:
        return None, 0.0
    return entry


def _store(key: str, value: str) -> None:
    with _LOCK:
        _CACHE[key] = (value, time.monotonic())


def _drop(key: str) -> None:
    with _LOCK:
        _CACHE.pop(key, None)


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


def get_admin_access_path() -> str:
    """Current console path prefix (TTL-cached; middleware calls per request)."""
    cached, _ = _cached(ADMIN_ACCESS_PATH_KEY)
    if cached is not None:
        return cached
    from app.core.db import SessionLocal

    try:
        with SessionLocal() as db:
            value = _resolve_raw(db)
    except Exception:  # noqa: BLE001 — fail-open to the settings default when DB is unavailable
        value = get_settings().admin_access_path.strip().strip("/").lower()
    _store(ADMIN_ACCESS_PATH_KEY, value)
    return value


def _resolve_raw(db: Session) -> str:
    row = db.get(SystemSetting, ADMIN_ACCESS_PATH_KEY)
    if row and (row.value or "").strip():
        return row.value.strip().strip("/").lower()
    return get_settings().admin_access_path.strip().strip("/").lower()


def set_admin_access_path(db: Session, value: str, actor: str) -> None:
    v = (value or "").strip().strip("/").lower()
    row = db.get(SystemSetting, ADMIN_ACCESS_PATH_KEY)
    if row is None:
        row = SystemSetting(key=ADMIN_ACCESS_PATH_KEY)
        db.add(row)
    row.value = v
    row.updated_by = (actor or "")[:64]
    row.updated_at = datetime.now(UTC)
    db.commit()
    _drop(ADMIN_ACCESS_PATH_KEY)


def invalidate_admin_path_cache() -> None:
    _drop(ADMIN_ACCESS_PATH_KEY)
    _drop(EMBEDDED_HONEYPOT_KEY)


def seed_admin_access_path(db: Session) -> None:
    """Insert the shipped default on first boot; never override a custom value."""
    if db.get(SystemSetting, ADMIN_ACCESS_PATH_KEY) is None:
        db.add(SystemSetting(
            key=ADMIN_ACCESS_PATH_KEY,
            value=DEFAULT_ADMIN_ACCESS_PATH,
            updated_by="seed",
        ))
        db.commit()


def get_embedded_honeypot_enabled() -> bool:
    """Embedded honeypot master switch (TTL-cached). Gates the console-plane
    bait callback channels (/collect, /recon, /_agent, /payload); the web
    honeypot plane's own instances of those routes are unaffected."""
    cached, _ = _cached(EMBEDDED_HONEYPOT_KEY)
    if cached is not None:
        return cached == "1"
    value = DEFAULT_EMBEDDED_ENABLED
    from app.core.db import SessionLocal

    try:
        with SessionLocal() as db:
            row = db.get(SystemSetting, EMBEDDED_HONEYPOT_KEY)
            if row is not None:
                value = (row.value or "").strip() == "1"
    except Exception:  # noqa: BLE001 — fail closed to the shipped default
        value = DEFAULT_EMBEDDED_ENABLED
    _store(EMBEDDED_HONEYPOT_KEY, "1" if value else "0")
    return value


def set_embedded_honeypot_enabled(db: Session, enabled: bool, actor: str) -> None:
    row = db.get(SystemSetting, EMBEDDED_HONEYPOT_KEY)
    if row is None:
        row = SystemSetting(key=EMBEDDED_HONEYPOT_KEY)
        db.add(row)
    row.value = "1" if enabled else "0"
    row.updated_by = (actor or "")[:64]
    row.updated_at = datetime.now(UTC)
    db.commit()
    _drop(EMBEDDED_HONEYPOT_KEY)


def seed_embedded_honeypot(db: Session) -> None:
    """Insert the shipped default (off) on first boot; never override a
    value the operator has set."""
    if db.get(SystemSetting, EMBEDDED_HONEYPOT_KEY) is None:
        db.add(SystemSetting(
            key=EMBEDDED_HONEYPOT_KEY,
            value="1" if DEFAULT_EMBEDDED_ENABLED else "0",
            updated_by="seed",
        ))
        db.commit()


def embedded_disabled_response(request):
    """404 when the embedded honeypot is disabled and the request hit the
    console plane (web honeypot plane instances stay available)."""
    from starlette.requests import Request
    from starlette.responses import Response

    request: Request
    from app.services.honeypot_web import WEB_HONEYPOT_APP_TITLE

    app_title = getattr(request.app, "title", "") if request.app is not None else ""
    if app_title == WEB_HONEYPOT_APP_TITLE:
        return None
    if get_embedded_honeypot_enabled():
        return None
    return Response("Not Found", status_code=404, media_type="text/plain")
