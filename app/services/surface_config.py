"""Runtime switches for the counter-offense bait surfaces.

Mirrors the portal-config pattern: 5-second TTL cache, save invalidates.
Disabled semantics per surface: the bait endpoint answers 404 (the surface
"does not exist") — mirroring the portal master switch.
"""
from __future__ import annotations

import threading
import time
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.counter_surface import CounterSurface

CACHE_TTL_SECONDS = 5.0

# surface registry: key -> display metadata (order defines page order)
SURFACES: list[dict[str, str]] = [
    {"key": "agent_files", "name": "Agent 指令文件蜜饵",
     "description": "AGENTS.md / CLAUDE.md / .cursorrules 返回项目级 Agent 指南（含 Portal/数据集/MCP 引流与会话水印）",
     "paths": "/AGENTS.md · /CLAUDE.md · /.cursorrules",
     "event_types": "agent_file_bait_read"},
    {"key": "mcp", "name": "MCP 蜜罐",
     "description": "JSON-RPC 工具服务：initialize / tools/list / tools/call，四个毒化工具，调用即指纹归因",
     "paths": "/mcp",
     "event_types": "mcp_discover,mcp_initialize,mcp_tools_list,mcp_tool_call"},
    {"key": "dataset", "name": "消耗战数据集",
     "description": "无限分页（999,999 页）水印假客户数据，逐行可溯源至 (会话,页,行)",
     "paths": "/portal/api/dataset",
     "event_types": "poison_dataset_fetch"},
    {"key": "metadata", "name": "云元数据蜜罐（SSRF）",
     "description": "伪装云元数据服务，返回蜜标云凭证；SSRF 利用即 risk 95 告警 + 凭证观测",
     "paths": "/latest/meta-data/* · /computeMetadata/v1/*",
     "event_types": "metadata_probe,metadata_credentials_read"},
    {"key": "intranet", "name": "内网横向 Wiki",
     "description": "SSH 假文件系统内网主机的落点：返回会话水印版内网 wiki（横向探测即 risk 75）",
     "paths": "/intranet/* · SSH shell 内网 curl",
     "event_types": "intranet_probe"},
    {"key": "behavior", "name": "行为序列指纹",
     "description": "对会话请求历史做自动化特征分析（无静态资源/高路径多样性/匀速间隔），命中即附加信号",
     "paths": "中间件（全请求）",
     "event_types": ""},
]

_CACHE: dict[str, bool] | None = None
_CACHE_AT: float = 0.0
_LOCK = threading.Lock()


def invalidate_cache() -> None:
    global _CACHE, _CACHE_AT
    with _LOCK:
        _CACHE = None
        _CACHE_AT = 0.0


def ensure_rows(db: Session) -> None:
    existing = {
        row.surface_key: row
        for row in db.scalars(select(CounterSurface)).all()
    }
    changed = False
    for meta in SURFACES:
        if meta["key"] not in existing:
            db.add(CounterSurface(surface_key=meta["key"], enabled=True))
            changed = True
    if changed:
        db.commit()


def get_enabled_map(db: Session) -> dict[str, bool]:
    """Cached read for hot paths. Unknown keys default to enabled."""
    global _CACHE, _CACHE_AT
    now = time.monotonic()
    if _CACHE is not None and now - _CACHE_AT < CACHE_TTL_SECONDS:
        return _CACHE
    ensure_rows(db)
    enabled = {
        meta["key"]: bool(
            db.scalar(
                select(CounterSurface.enabled).where(
                    CounterSurface.surface_key == meta["key"])
            )
        )
        for meta in SURFACES
    }
    with _LOCK:
        _CACHE = enabled
        _CACHE_AT = now
    return enabled


def is_enabled(db: Session, key: str) -> bool:
    return get_enabled_map(db).get(key, True)


def set_surface(db: Session, *, key: str, enabled: bool, actor: str,
                notes: str = "") -> None:
    ensure_rows(db)
    row = db.get(CounterSurface, key)
    if row is None:
        row = CounterSurface(surface_key=key, enabled=enabled)
    row.enabled = bool(enabled)
    row.updated_by = actor[:64]
    if notes:
        row.notes = notes[:2000]
    from datetime import datetime, timezone

    row.updated_at = datetime.now(timezone.utc)
    db.add(row)
    db.commit()
    invalidate_cache()


def surface_meta() -> list[dict[str, str]]:
    return SURFACES


def surface_stats(db: Session, hours: float = 24.0) -> dict[str, dict[str, Any]]:
    """Per-surface 24h hit counts + last-hit time for the management page."""
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import func

    from app.models.event import Event

    threshold = datetime.now(timezone.utc) - timedelta(hours=hours)
    out: dict[str, dict[str, Any]] = {}
    for meta in SURFACES:
        types = [t for t in meta["event_types"].split(",") if t]
        hits = 0
        last = None
        if not types:
            out[meta["key"]] = {"hits_24h": 0, "last_hit": None}
            continue
        if types:
            hits = int(db.scalar(
                select(func.count()).select_from(Event).where(
                    Event.event_type.in_(types), Event.created_at >= threshold)
            ) or 0)
            last = db.scalar(
                select(Event.created_at).where(
                    Event.event_type.in_(types), Event.created_at >= threshold)
                .order_by(Event.created_at.desc()).limit(1)
            )
        out[meta["key"]] = {"hits_24h": hits, "last_hit": last}
    return out
