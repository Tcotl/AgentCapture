import json
from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from app.core.config import get_settings
from app.core.db import SessionLocal
from app.services.events import (
    RISK_TIER_LABELS,
    aggregate_window,
    format_dt,
    list_events_since,
    list_recent_events,
    risk_tier,
    translate_decision,
    translate_signal,
)

settings = get_settings()

router = APIRouter(prefix="/console", tags=["console"])


def serialize_event(event) -> dict:
    """One console row: raw machine fields first (backward compatible),
    then human-readable labels for display."""
    signals = list(event.signals_json or [])
    tier = risk_tier(event.risk_score)
    return {
        "id": event.id,
        "created_at": event.created_at.isoformat(),
        "site_id": event.site_id,
        "session_id": event.session_id,
        "source_ip": event.source_ip,
        "method": event.method,
        "path": event.path,
        "status_code": event.status_code,
        "event_type": event.event_type,
        "decision": event.decision,
        "risk_score": event.risk_score,
        "signals": signals,
        "payload": event.payload_json,
        # human-readable additions
        "time": format_dt(event.created_at),
        "target": f"{event.method} {event.path}",
        "decision_label": translate_decision(event.decision),
        "risk_tier": tier,
        "risk_tier_label": RISK_TIER_LABELS[tier],
        "signal_labels": [translate_signal(signal) for signal in signals],
    }


def serialize_event_compact(event) -> dict:
    """Slim row for high-volume feeds: drops the JSON blobs and the
    display-only labels — payload size drops by an order of magnitude."""
    return {
        "id": event.id,
        "created_at": event.created_at.isoformat(),
        "source_ip": event.source_ip,
        "method": event.method,
        "path": event.path,
        "status_code": event.status_code,
        "event_type": event.event_type,
        "decision": event.decision,
        "risk_score": event.risk_score,
        "time": format_dt(event.created_at),
        "risk_tier": risk_tier(event.risk_score),
    }


def _filter_events(events: list, *, decision: str, event_type: str, source_ip: str) -> list:
    return [
        event
        for event in events
        if (not decision or event.decision == decision)
        and (not event_type or event.event_type == event_type)
        and (not source_ip or event.source_ip == source_ip)
    ]


@router.get("/events")
def recent_events(
    request: Request,
    limit: int = 50,
    decision: str = "",
    event_type: str = "",
    source_ip: str = "",
    since_id: int | None = None,
    min_risk: int = 0,
    aggregate: int = 0,
    window: int = 60,
    compact: int = 0,
):
    # The event stream documents every detection signal we use. Gate it
    # behind an admin session unless the deployment explicitly opts out.
    if not settings.console_public and not request.session.get("user_id"):
        return JSONResponse(
            {
                "status": "unauthorized",
                "reason": "admin session required (set CONSOLE_PUBLIC=true to expose the console)",
            },
            status_code=401,
        )
    limit = min(max(limit, 1), 500)
    page_cap = min(max(limit, 1), 200)

    with SessionLocal() as db:
        pre_serialized = False
        if aggregate:
            # Aggregate feed view: window rollup for wallboards + a small
            # tail of raw high-risk rows so the operator still sees shapes.
            rollup = aggregate_window(db, window_seconds=window, since_id=since_id or 0)
            rows, _total_new, horizon = list_events_since(
                db,
                since_id=since_id or 0,
                decision=decision,
                event_type=event_type,
                source_ip=source_ip,
                min_risk=min_risk or 30,
            )
            rows = rows[-20:]  # 最近 20 条高危原始行作为聚合视图的形状样本
            payload = {
                "mode": "aggregate",
                "window_seconds": rollup["window_seconds"],
                "total": rollup["total"],
                "sources": rollup["sources"],
                "top_paths": rollup["top_paths"],
                "generated_at": format_dt(datetime.now(timezone.utc)),
                "last_id": horizon,
                "items": [serialize_event_compact(event) for event in rows],
            }
            pre_serialized = True
        elif since_id is not None:
            # Cursor mode: only rows newer than since_id (0 = from the very
            # beginning). When more new events arrived than fit the page, the
            # highest-risk rows win and the remainder is reported via omitted
            # — the feed always reflects the true arrival count instead of
            # lagging behind.
            rows, total_new, horizon = list_events_since(
                db,
                since_id=since_id,
                decision=decision,
                event_type=event_type,
                source_ip=source_ip,
                min_risk=min_risk,
            )
            truncated = total_new > page_cap
            omitted = max(total_new - page_cap, 0)
            if truncated:
                rows = sorted(rows, key=lambda e: (e.risk_score, e.id), reverse=True)
            items = [event for event in rows][:page_cap]
            payload = {
                "total": len(items),
                "total_new": total_new,
                "truncated": truncated,
                "omitted": omitted,
                "last_id": horizon,
                "since_id": since_id,
                "limit": limit,
                "filters": {
                    key: value
                    for key, value in {
                        "decision": decision,
                        "event_type": event_type,
                        "source_ip": source_ip,
                        "min_risk": min_risk,
                    }.items()
                    if value
                },
                "generated_at": format_dt(datetime.now(timezone.utc)),
                "items": [event for event in items],
            }
        else:
            # Legacy shape: latest N rows, post-filtered in Python.
            fetch_cap = page_cap * 4
            events = list_recent_events(db, limit=fetch_cap)
            items = _filter_events(
                events, decision=decision, event_type=event_type, source_ip=source_ip
            )[:page_cap]
            active_filters = {
                key: value
                for key, value in {
                    "decision": decision,
                    "event_type": event_type,
                    "source_ip": source_ip,
                }.items()
                if value
            }
            payload = {
                "total": len(items),
                "limit": limit,
                "filters": active_filters,
                "generated_at": format_dt(datetime.now(timezone.utc)),
                "items": [event for event in items],
            }

    serializer = serialize_event_compact if compact else serialize_event
    if not pre_serialized:
        payload["items"] = [serializer(event) for event in payload.get("items", [])]
    # Pretty-printed (default) so the console URL is readable when opened in a
    # browser; compact=1 trades that off for wire size under load.
    body = json.dumps(payload, ensure_ascii=False, indent=None if compact else 2)
    return Response(
        content=body,
        media_type="application/json; charset=utf-8",
    )