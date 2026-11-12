"""Sensor-network API: the employee-agent probe channel (management plane).

Three endpoints, token-authenticated via X-Sensor-Token:
  POST /api/sensor/register   — first enrollment (token issued by admin)
  POST /api/sensor/heartbeat  — presence + feature-manifest delivery
  POST /api/sensor/report     — coarse marker hit → verified + attributed

Read-only by construction: no endpoint accepts anything executable, the
channel never returns tasks, and sensors share nothing with the node task system."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import SessionLocal
from app.models.event import Event
from app.models.sensor import Sensor, SensorHit
from app.services.events import create_event, extract_client_ip, filtered_headers
from app.services.sensor_network import (
    authenticate_sensor,
    feature_manifest,
    verify_and_attribute,
)
from app.core.config import get_settings

settings = get_settings()
router = APIRouter(prefix="/api/sensor", tags=["sensor-network"])


def _sensor_event(request: Request, event_type: str, sensor_id: str, extra: dict) -> None:
    ip = extract_client_ip(request)
    with SessionLocal() as db:
        create_event(
            db,
            site_id=settings.site_id,
            session_id="",
            source_ip=ip,
            method=request.method,
            path=request.url.path,
            status_code=200,
            event_type=event_type,
            user_agent=request.headers.get("user-agent", ""),
            headers_json=filtered_headers(request),
            payload_json={"sensor": sensor_id[:64], **(extra or {})},
            signals_json=["sensor_network", event_type],
            risk_score=80,
            decision="observe",
        )


async def _json_body(request: Request) -> dict:
    try:
        body = await request.json()
        return body if isinstance(body, dict) else {}
    except Exception:
        return {}


@router.post("/register")
async def sensor_register(request: Request):
    body = await _json_body(request)
    with SessionLocal() as db:
        sensor = authenticate_sensor(db, request.headers.get("x-sensor-token") or "")
        if sensor is None:
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        # enrich roster with the agent's self-description (never overwrite employee)
        if body.get("agent_product") and not sensor.agent_product:
            sensor.agent_product = str(body["agent_product"])[:64]
        if body.get("agent_version") and not sensor.agent_version:
            sensor.agent_version = str(body["agent_version"])[:64]
        if body.get("device") and not sensor.device:
            sensor.device = str(body["device"])[:120]
        db.add(sensor)
        db.commit()
        sid = sensor.sensor_id
    _sensor_event(request, "sensor_registered", sid, {"agent_product": body.get("agent_product")})
    return JSONResponse({"status": "ok", "sensor_id": sid, "heartbeat_interval_s": 300})


@router.post("/heartbeat")
async def sensor_heartbeat(request: Request):
    with SessionLocal() as db:
        sensor = authenticate_sensor(db, request.headers.get("x-sensor-token") or "")
        if sensor is None:
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        sid = sensor.sensor_id
    # presence only — the manifest rides along so feature evolution needs
    # no binary redeployment
    return JSONResponse({
        "status": "ok",
        "sensor_id": sid,
        "heartbeat_interval_s": 300,
        "features": feature_manifest(),
    })


@router.post("/report")
async def sensor_report(request: Request):
    body = await _json_body(request)
    with SessionLocal() as db:
        sensor = authenticate_sensor(db, request.headers.get("x-sensor-token") or "")
        if sensor is None:
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        hit = SensorHit(
            sensor_id=sensor.sensor_id,
            hit_token=str(body.get("hit") or "")[:255],
            feature=str(body.get("feature") or "")[:48],
            source_kind=str(body.get("source_kind") or "")[:32],
            source_ref=str(body.get("source_ref") or "")[:512],
            agent_product=str(body.get("agent_product") or sensor.agent_product or "")[:64],
        )
        db.add(hit)
        db.commit()
        db.refresh(hit)
        hit = verify_and_attribute(db, hit)
        sid, verified, attributed = hit.sensor_id, hit.verified, hit.attributed_session
    _sensor_event(
        request,
        "sensor_hit",
        sid,
        {
            "hit": str(body.get("hit") or "")[:120],
            "feature": str(body.get("feature") or ""),
            "source_ref": str(body.get("source_ref") or "")[:200],
            "verified": verified,
            "attributed_session": attributed,
        },
    )
    return JSONResponse({
        "status": "received",
        "verified": verified,
        "attributed_session": attributed or None,
    })
