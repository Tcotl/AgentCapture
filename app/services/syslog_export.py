"""Unified syslog export interface (统一数据日志外发).

Forwards every captured platform event to a standard syslog collector
(RFC 5424 or RFC 3164, UDP or TCP) so AI SOC platforms can ingest the
deception plane's telemetry through their existing syslog pipeline.

Design:
- configuration lives in system_settings (managed from 告警配置 page)
- export is fire-and-forget: a background worker drains a bounded queue;
  the capture path never blocks on syslog I/O
- message body is a single-line JSON document (the unified data interface)
  plus a human summary; RFC 5424 by default, RFC 3164 optional
- counters track sent / dropped / errors for the config page
"""
from __future__ import annotations

import json
import queue
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any

from app.models.system_setting import SystemSetting

SETTINGS_KEYS = ("syslog_enabled", "syslog_host", "syslog_port",
                 "syslog_proto", "syslog_format", "syslog_facility",
                 "syslog_min_risk")
DEFAULTS = {"syslog_enabled": "0", "syslog_host": "", "syslog_port": "514",
            "syslog_proto": "udp", "syslog_format": "rfc5424",
            "syslog_facility": "16", "syslog_min_risk": "0"}

_lock = threading.Lock()
_cfg_cache: dict[str, str] | None = None
_cfg_ts = 0.0
_CFG_TTL = 5.0
_worker_started = False
_queue: "queue.Queue[bytes | None]" = queue.Queue(maxsize=4096)
_counters = {"sent": 0, "dropped": 0, "errors": 0}
_tcp_conn: socket.socket | None = None
_tcp_peer = ""


def _load_cfg() -> dict[str, str]:
    global _cfg_cache, _cfg_ts
    now = time.monotonic()
    with _lock:
        if _cfg_cache is not None and now - _cfg_ts < _CFG_TTL:
            return _cfg_cache
    from app.core.db import SessionLocal

    cfg = dict(DEFAULTS)
    try:
        with SessionLocal() as db:
            rows = db.query(SystemSetting).filter(
                SystemSetting.key.in_(SETTINGS_KEYS)).all()
            for row in rows:
                if (row.value or "").strip():
                    cfg[row.key] = row.value.strip()
    except Exception:  # noqa: BLE001 — degrade to defaults
        pass
    with _lock:
        _cfg_cache = cfg
        _cfg_ts = now
    return cfg


def invalidate_config_cache() -> None:
    global _cfg_cache
    with _lock:
        _cfg_cache = None


def save_config(db, *, enabled: bool, host: str, port: int, proto: str,
                fmt: str, facility: int, min_risk: int, actor: str) -> None:
    from datetime import UTC, datetime

    values = {"syslog_enabled": "1" if enabled else "0",
              "syslog_host": (host or "").strip(),
              "syslog_port": str(port or 514),
              "syslog_proto": proto if proto in ("udp", "tcp") else "udp",
              "syslog_format": fmt if fmt in ("rfc5424", "rfc3164") else "rfc5424",
              "syslog_facility": str(facility if 0 <= facility <= 23 else 16),
              "syslog_min_risk": str(min_risk if 0 <= min_risk <= 100 else 0)}
    for key, value in values.items():
        row = db.get(SystemSetting, key)
        if row is None:
            row = SystemSetting(key=key)
            db.add(row)
        row.value = value
        row.updated_by = (actor or "")[:64]
        row.updated_at = datetime.now(UTC)
    db.commit()
    invalidate_config_cache()


def get_config() -> dict[str, Any]:
    cfg = _load_cfg()
    return {"enabled": cfg.get("syslog_enabled") == "1",
            "host": cfg.get("syslog_host", ""),
            "port": int(cfg.get("syslog_port", "514") or 514),
            "proto": cfg.get("syslog_proto", "udp"),
            "format": cfg.get("syslog_format", "rfc5424"),
            "facility": int(cfg.get("syslog_facility", "16") or 16),
            "min_risk": int(cfg.get("syslog_min_risk", "0") or 0)}


def counters() -> dict[str, int]:
    with _lock:
        return dict(_counters)


def _severity(risk: int, decision: str) -> int:
    if decision == "block" or risk >= 90:
        return 2   # critical
    if decision == "isolate" or risk >= 70:
        return 3   # error
    if decision == "challenge" or risk >= 45:
        return 5   # notice
    return 6       # info


def _rfc5424_timestamp(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _rfc3164_timestamp(ts: datetime) -> str:
    return ts.strftime("%b %d %H:%M:%S").replace("  0", "  0")


def _coerce_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)


def format_message(event: dict[str, Any], *, fmt: str, facility: int,
                   hostname: str) -> tuple[int, str]:
    """Return (pri, full syslog line) for one normalized event."""
    ts = _coerce_ts(event.get("ts"))
    severity = _severity(int(event.get("risk_score", 0) or 0),
                         str(event.get("decision", "")))
    pri = facility * 8 + severity
    msg = json.dumps(event, ensure_ascii=False, default=str)
    app_name = "agentcapture"
    if fmt == "rfc3164":
        stamp = ts.astimezone(timezone.utc).strftime("%b %d %H:%M:%S")
        return pri, f"<{pri}>{stamp} {hostname} {app_name}: {msg}"
    stamp = _rfc5424_timestamp(ts)
    return pri, (f"<{pri}>1 {stamp} {hostname} {app_name} - "
                 f"{event.get('event_type', 'event')} - {msg}")


def _send_line(line: bytes, proto: str, host: str, port: int) -> None:
    global _tcp_conn, _tcp_peer
    if proto == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(line, (host, port))
        return
    peer = f"{host}:{port}"
    if _tcp_conn is None or _tcp_peer != peer:
        try:
            if _tcp_conn:
                _tcp_conn.close()
        except OSError:
            pass
        _tcp_conn = socket.create_connection((host, port), timeout=5)
        _tcp_peer = peer
    try:
        _tcp_conn.sendall(line + b"\n")
    except OSError:
        try:
            _tcp_conn.close()
        except OSError:
            pass
        _tcp_conn = None
        _tcp_conn = socket.create_connection((host, port), timeout=5)
        _tcp_conn.sendall(line + b"\n")


def _worker() -> None:
    while True:
        try:
            item = _queue.get(timeout=1.0)
        except queue.Empty:
            continue
        if item is None:
            continue
        line, proto, host, port = item
        try:
            _send_line(line, proto, host, port)
            with _lock:
                _counters["sent"] += 1
        except Exception:  # noqa: BLE001 — errors counted, never fatal
            with _lock:
                _counters["errors"] += 1
            _tcp_conn = None


def _ensure_worker() -> None:
    global _worker_started
    if _worker_started:
        return
    with _lock:
        if _worker_started:
            return
        threading.Thread(target=_worker, daemon=True,
                         name="syslog-export").start()
        _worker_started = True


def enqueue_event(event: Any) -> None:
    """Queue one ORM Event for syslog export (no-op when disabled)."""
    cfg = get_config()
    if not cfg["enabled"] or not cfg["host"]:
        return
    if int(event.risk_score or 0) < cfg["min_risk"]:
        return
    payload = {
        "ts": (event.created_at or datetime.now(timezone.utc)).isoformat(),
        "site_id": event.site_id,
        "event_type": event.event_type,
        "decision": event.decision,
        "risk_score": event.risk_score,
        "signals": list(event.signals_json or []),
        "source_ip": event.source_ip,
        "session_id": event.session_id,
        "method": event.method,
        "path": event.path,
        "status_code": event.status_code,
        "user_agent": (event.user_agent or "")[:200],
        "payload": event.payload_json or {},
        "summary": f"{event.decision} {event.event_type} {event.source_ip} {event.path}",
    }
    _enqueue_line(payload, cfg)


def send_event_dict(event: dict[str, Any]) -> dict[str, Any]:
    """Send one already-normalized dict (used by the test button)."""
    cfg = get_config()
    if not cfg["enabled"] or not cfg["host"]:
        return {"ok": False, "error": "微步/数源未启用：请先填写 syslog 服务器并启用"}
    try:
        pri, line = format_message(event, fmt=cfg["format"],
                                   facility=cfg["facility"],
                                   hostname=socket.gethostname())
        _send_line(line.encode("utf-8"), cfg["proto"], cfg["host"], cfg["port"])
        with _lock:
            _counters["sent"] += 1
        return {"ok": True}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


def _enqueue_line(payload: dict, cfg: dict) -> None:
    _ensure_worker()
    pri, line = format_message(payload, fmt=cfg["format"],
                               facility=cfg["facility"],
                               hostname=socket.gethostname())
    if int(payload.get("risk_score", 0)) < cfg["min_risk"]:
        return
    try:
        _queue.put_nowait((line.encode("utf-8"), cfg["proto"], cfg["host"], cfg["port"]))
    except queue.Full:
        with _lock:
            _counters["dropped"] += 1


def send_test_message(host: str, port: int, proto: str, fmt: str,
                      facility: int) -> dict[str, Any]:
    ts = datetime.now(timezone.utc)
    event = {"ts": ts.isoformat(), "site_id": "agentcapture",
             "event_type": "syslog_test", "decision": "observe",
             "risk_score": 10, "signals": ["test"],
             "source_ip": "127.0.0.1", "session_id": "test",
             "method": "GET", "path": "/syslog/test", "status_code": 200,
             "user_agent": "", "payload": {}, "summary": "syslog test message"}
    try:
        pri, line = format_message(event, fmt=fmt, facility=facility,
                                   hostname=socket.gethostname())
        _send_line(line.encode("utf-8"), proto, host, port)
        return {"ok": True}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}
