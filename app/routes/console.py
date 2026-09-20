import json
from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from app.core.config import get_settings
from app.core.db import SessionLocal
from app.services.events import (
    RISK_TIER_LABELS,
    format_dt,
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
    request: Request, limit: int = 50, decision: str = "", event_type: str = "", source_ip: str = ""
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
    # Fetch a wider window so post-filters still fill the requested page size.
    fetch_cap = min(max(limit, 1), 200) * 4
    with SessionLocal() as db:
        events = list_recent_events(db, limit=fetch_cap)

    items = _filter_events(events, decision=decision, event_type=event_type, source_ip=source_ip)[
        : min(max(limit, 1), 200)
    ]
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
        "items": [serialize_event(event) for event in items],
    }
    # Pretty-printed so the console URL is readable when opened in a browser.
    return Response(
        content=json.dumps(payload, ensure_ascii=False, indent=2),
        media_type="application/json; charset=utf-8",
    )
