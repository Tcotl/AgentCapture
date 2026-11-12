"""Data retention: the events table grows by one row per request and
node_heartbeats by one row per heartbeat. Without a cleanup pass the SQLite
file (and every dashboard COUNT over it) grows without bound.

A daemon thread runs :func:`run_retention` hourly; the same function is
invoked once at startup. All windows are configured in days via settings
(0 disables the respective cleanup).
"""

import logging
import threading
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete

from app.core.config import get_settings

logger = logging.getLogger("retention")

_INTERVAL_SECONDS = 3600
_thread_started = False


def run_retention(db) -> dict[str, int]:
    """Delete rows past their retention window. Returns deleted-row counts."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    deleted: dict[str, int] = {}

    if settings.event_retention_days > 0:
        from app.models.event import Event

        cutoff = now - timedelta(days=settings.event_retention_days)
        result = db.execute(delete(Event).where(Event.created_at < cutoff))
        deleted["events"] = int(result.rowcount or 0)

    if settings.heartbeat_retention_days > 0:
        from app.models.node_runtime import NodeHeartbeat

        cutoff = now - timedelta(days=settings.heartbeat_retention_days)
        result = db.execute(delete(NodeHeartbeat).where(NodeHeartbeat.created_at < cutoff))
        deleted["node_heartbeats"] = int(result.rowcount or 0)

    if settings.login_log_retention_days > 0:
        from app.models.login_log import LoginLog

        cutoff = now - timedelta(days=settings.login_log_retention_days)
        result = db.execute(delete(LoginLog).where(LoginLog.created_at < cutoff))
        deleted["login_logs"] = int(result.rowcount or 0)

    if settings.honeypot_session_retention_days > 0:
        from app.models.honeypot_session import HoneypotSession

        cutoff = now - timedelta(days=settings.honeypot_session_retention_days)
        result = db.execute(delete(HoneypotSession).where(HoneypotSession.started_at < cutoff))
        deleted["honeypot_sessions"] = int(result.rowcount or 0)

    if any(deleted.values()):
        db.commit()
        logger.info("Retention removed: %s", {k: v for k, v in deleted.items() if v})
    return deleted


def _loop() -> None:
    import time

    from app.core.db import SessionLocal

    while True:
        time.sleep(_INTERVAL_SECONDS)
        try:
            with SessionLocal() as db:
                run_retention(db)
        except Exception as exc:
            logger.warning("Retention pass failed: %s", exc)


def start_retention_scheduler() -> None:
    global _thread_started
    if _thread_started:
        return
    _thread_started = True
    threading.Thread(target=_loop, daemon=True, name="retention-scheduler").start()
