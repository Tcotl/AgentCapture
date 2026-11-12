"""Sensor-network service layer: roster lifecycle, feature manifest,
hit verification and attack-chain attribution.

Design contract (grilled 2026-11-12): read-only sensing — the sensor
channel carries scan hits and nothing else. Coarse pattern matching lives
on the sensor (features delivered via heartbeat, built-in fallback set in
the binary); authoritative verification and attribution live here, on the
platform."""

from __future__ import annotations

import json
import re
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.event import Event
from app.models.sensor import Sensor, SensorHit

# ---------------------------------------------------------------------------
# Feature manifest — delivered via heartbeat, mirrored as the binary's
# built-in fallback set. Each feature: stable key, human regex, note.
# ---------------------------------------------------------------------------
FEATURE_MANIFEST: list[dict] = [
    {
        "key": "ssh_watermark_cred",
        "pattern": r"Bk2026![A-Za-z0-9]{4,32}",
        "note": "SSH honeypot session-watermarked credential",
    },
    {
        "key": "poison_row_note",
        "pattern": r"internal record [A-Za-z0-9]{6,24}",
        "note": "Poisoned dataset row note watermark",
    },
    {
        "key": "poison_row_email",
        "pattern": r"[a-z]+\.[a-z0-9]{6,24}@corp\.example",
        "note": "Poisoned dataset row email watermark",
    },
    {
        "key": "decoy_api_key",
        "pattern": r"sk-stg-[A-Za-z0-9]{10,40}",
        "note": "Decoy-plane per-source API key",
    },
]

_FALLBACK_PATTERNS = {f["key"]: re.compile(f["pattern"]) for f in FEATURE_MANIFEST}


def create_sensor(
    db: Session,
    *,
    employee: str = "",
    device: str = "",
    agent_product: str = "",
    agent_version: str = "",
    mode: str = "hooks",
) -> Sensor:
    sensor = Sensor(
        sensor_id="sns" + secrets.token_hex(8),
        token=secrets.token_hex(24),
        employee=employee,
        device=device,
        agent_product=agent_product,
        agent_version=agent_version,
        mode=mode if mode in ("hooks", "mcp") else "hooks",
        enabled=True,
    )
    db.add(sensor)
    db.commit()
    db.refresh(sensor)
    return sensor


def authenticate_sensor(db: Session, token: str) -> Sensor | None:
    if not token:
        return None
    row = db.scalar(select(Sensor).where(Sensor.token == token.strip()))
    if row is None or not row.enabled:
        return None
    row.last_seen_at = datetime.now(timezone.utc)
    db.add(row)
    db.commit()
    return row


def feature_manifest() -> list[dict]:
    return FEATURE_MANIFEST


def compile_patterns(features: list[dict] | None = None) -> dict[str, re.Pattern]:
    """Compile a delivered manifest, falling back to the built-in set."""
    if not features:
        return _FALLBACK_PATTERNS
    out: dict[str, re.Pattern] = {}
    for f in features:
        try:
            out[str(f.get("key"))] = re.compile(str(f.get("pattern")))
        except re.error:
            continue
    return out or _FALLBACK_PATTERNS


# ---------------------------------------------------------------------------
# Verification + attribution
# ---------------------------------------------------------------------------
def _search_token_in_events(db: Session, token: str, days: int = 14) -> Event | None:
    """Find the earliest recent event whose payload carried this marker —
    the honeypot-side origin of the leaked bait data."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = (
        db.execute(
            select(Event)
            .where(Event.created_at >= cutoff)
            .where(Event.event_type != "sensor_hit")
            .where(Event.payload_json.like(f"%{token}%"))
            .order_by(Event.created_at.asc())
            .limit(20)
        )
        .scalars()
        .all()
    )
    return rows[0] if rows else None


def _attribute_dataset_code(db: Session, code: str) -> Event | None:
    """A poisoned-row watermark code is derived as _wm_code(canary,
    'cust:page:row') — replay every recent dataset fetch's canary and
    compare, so a leaked row traces back to the exact fetch event."""
    from app.services.counter_intel import _wm_code

    cutoff = datetime.now(timezone.utc) - timedelta(days=14)
    rows = (
        db.execute(
            select(Event)
            .where(Event.created_at >= cutoff)
            .where(Event.event_type == "poison_dataset_fetch")
            .where(Event.payload_json.like('%"canary"%'))
            .order_by(Event.created_at.desc())
            .limit(500)
        )
        .scalars()
        .all()
    )
    code = code.casefold()
    for ev in rows:
        try:
            payload = ev.payload_json if isinstance(ev.payload_json, dict) else json.loads(ev.payload_json or "{}")
        except Exception:
            continue
        canary = str(payload.get("canary") or "")
        page = int(payload.get("page") or 1)
        if not canary:
            continue
        for row in range(50):
            if _wm_code(canary, f"cust:{page}:{row}").casefold() == code:
                return ev
    return None


def verify_and_attribute(db: Session, hit: SensorHit) -> SensorHit:
    """Authoritative check on the platform: confirm the marker is one of ours
    and trace it back to the honeypot session that issued it."""
    token = (hit.hit_token or "").strip()
    if not token:
        return hit
    origin = _search_token_in_events(db, token)
    if origin is None and hit.feature == "poison_row_note":
        origin = _attribute_dataset_code(db, token.replace("internal record ", "", 1).strip())
    if origin is None and hit.feature == "poison_row_email":
        origin = _attribute_dataset_code(db, token.split("@", 1)[0].rsplit(".", 1)[-1])
    if origin is None and hit.feature == "ssh_watermark_cred":
        # session-watermarked credential: the honeypot session that minted it
        from app.models.honeypot_session import HoneypotSession

        sess = db.scalar(
            select(HoneypotSession).where(HoneypotSession.password == token).order_by(HoneypotSession.started_at.desc())
        )
        if sess is not None:
            hit.verified = True
            hit.attributed_session = str(getattr(sess, "session_id", "") or "")
            db.add(hit)
            db.commit()
            return hit
    hit.verified = origin is not None or hit.verified
    if origin is not None:
        hit.attributed_event_id = origin.id
        hit.attributed_session = str(getattr(origin, "session_id", "") or "")
    db.add(hit)
    db.commit()
    return hit
