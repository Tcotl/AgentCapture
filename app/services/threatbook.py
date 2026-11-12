"""微步在线 (ThreatBook) threat-intel integration.

The operator supplies an API key (威胁情报 page); IP reputation lookups go to
``https://api.threatbook.cn/v3/scene/ip_reputation``. Key state lives in the
system_settings table (same store as the console access path) so it survives
restarts without touching the env. Lookups are TTL-cached per IP — reputation
data changes slowly, and attacker IPs repeat heavily within a session.

Network calls are best-effort: any failure (no key, timeout, quota, bad key)
degrades to an ``error`` result instead of raising — intel enrichment must
never take down the request path or the intel page.
"""
from __future__ import annotations

import threading
import time
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.models.system_setting import SystemSetting

THREATBOOK_KEY_SETTING = "threatbook_api_key"
THREATBOOK_ENABLED_SETTING = "threatbook_enabled"
THREATBOOK_API_URL = "https://api.threatbook.cn/v3/scene/ip_reputation"
LOOKUP_TIMEOUT_SECONDS = 8.0
_CACHE_TTL_SECONDS = 600.0
_CACHE_MAX = 2048

_lock = threading.Lock()
_cache: dict[str, tuple[float, dict]] = {}

_SETTINGS_CACHE: dict[str, tuple[str, float]] = {}
_SETTINGS_TTL = 5.0


def _get_setting_cached(key: str) -> str:
    cached = _SETTINGS_CACHE.get(key)
    if cached and time.monotonic() - cached[1] < _SETTINGS_TTL:
        return cached[0]
    value = ""
    from app.core.db import SessionLocal

    try:
        with SessionLocal() as db:
            row = db.get(SystemSetting, key)
            if row is not None:
                value = (row.value or "").strip()
    except Exception:  # noqa: BLE001 — intel must degrade, not raise
        value = ""
    with _lock:
        _SETTINGS_CACHE[key] = (value, time.monotonic())
    return value


def invalidate_config_cache() -> None:
    with _lock:
        _SETTINGS_CACHE.clear()
        _cache.clear()


def get_api_key() -> str:
    return _get_setting_cached(THREATBOOK_KEY_SETTING)


def is_enabled() -> bool:
    return bool(get_api_key()) and _get_setting_cached(THREATBOOK_ENABLED_SETTING) == "1"


def save_config(db: Session, *, api_key: str, enabled: bool, actor: str) -> None:
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    for key, value in (
        (THREATBOOK_KEY_SETTING, (api_key or "").strip()),
        (THREATBOOK_ENABLED_SETTING, "1" if enabled else "0"),
    ):
        row = db.get(SystemSetting, key)
        if row is None:
            row = SystemSetting(key=key)
            db.add(row)
        row.value = value
        row.updated_by = (actor or "")[:64]
        row.updated_at = now
    db.commit()
    invalidate_config_cache()


def _cached_result(ip: str):
    entry = _cache.get(ip)
    if entry and time.monotonic() - entry[0] < _CACHE_TTL_SECONDS:
        return entry[1]
    return None


def _store_result(ip: str, result: dict) -> None:
    with _lock:
        if len(_cache) >= _CACHE_MAX:
            _cache.pop(next(iter(_cache)))
        _cache[ip] = (time.monotonic(), result)


def lookup_ip(ip: str, *, lang: str = "zh", refresh: bool = False) -> dict[str, Any]:
    """Query ThreatBook IP reputation for one IP.

    Returns a normalized dict: {ip, ok, malicious, severity, confidence,
    judgments, location, carrier, scene, permalink, update_time, error}.
    ``ok=False`` carries the reason in ``error`` (disabled / no key /
    upstream failure). Results are cached for 10 minutes unless refresh.
    """
    ip = (ip or "").strip()
    if not ip:
        return {"ip": ip, "ok": False, "error": "未提供 IP"}
    if not refresh:
        cached = _cached_result(ip)
        if cached is not None:
            return cached
    if not is_enabled():
        result = {"ip": ip, "ok": False, "error": "微步在线接入未启用或未填写 Key"}
        _store_result(ip, result)
        return result

    try:
        resp = httpx.get(
            THREATBOOK_API_URL,
            params={"apikey": get_api_key(), "resource": ip, "lang": lang},
            timeout=LOOKUP_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        body = resp.json()
    except Exception as exc:  # noqa: BLE001 — degrade to an error result
        result = {"ip": ip, "ok": False, "error": f"查询失败：{type(exc).__name__}"}
        _store_result(ip, result)
        return result

    if body.get("response_code") != 0:
        result = {
            "ip": ip,
            "ok": False,
            "error": f"微步返回错误：{body.get('verbose_msg') or body.get('response_code')}",
        }
        # don't cache key/quota errors long — the operator may fix the key
        return result

    info = (body.get("ipsmap") or {}).get(ip) or {}
    basic = info.get("basic") or {}
    location = basic.get("location") or {}
    result = {
        "ip": ip,
        "ok": True,
        "malicious": bool(info.get("is_malicious")),
        "severity": info.get("severity") or "info",
        "confidence": info.get("confidence_level") or "",
        "judgments": list(info.get("judgments") or []),
        "location": " ".join(
            str(location.get(part) or "") for part in ("country", "province", "city")
        ).strip(),
        "carrier": basic.get("carrier") or "",
        "scene": info.get("scene") or "",
        "asn": (info.get("asn") or {}).get("info") or "",
        "permalink": info.get("permalink") or "",
        "update_time": info.get("update_time") or "",
        "error": "",
    }
    _store_result(ip, result)
    return result
