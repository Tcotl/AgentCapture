
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db
from app.models.event import Event
from app.services.api_tokens import api_token_has_permission, resolve_api_token
from app.services.events import aggregated_attack_sources, list_credentials

router = APIRouter(prefix="/api/v1", tags=["public-api"])
settings = get_settings()


def _require_token(db: Session, api_key: str | None, permission: str):
    if not api_key:
        raise HTTPException(status_code=401, detail="missing api key")
    token = resolve_api_token(db, api_key)
    if not token:
        raise HTTPException(status_code=401, detail="invalid api key")
    if not api_token_has_permission(token, permission):
        raise HTTPException(status_code=403, detail="insufficient permissions")
    return token


@router.post("/attack/ip")
def api_attack_sources(
    api_key: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    _require_token(db, api_key, "attack.read")
    return {"items": aggregated_attack_sources(db, limit=settings.public_api_default_limit)}


@router.post("/attack/detail")
def api_attack_detail(
    source_ip: str | None = Query(default=None),
    api_key: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    _require_token(db, api_key, "attack.read")
    stmt = select(Event).order_by(desc(Event.created_at)).limit(settings.public_api_default_limit)
    if source_ip:
        stmt = stmt.where(Event.source_ip == source_ip)
    items = db.scalars(stmt).all()
    return {
        "items": [
            {
                "created_at": item.created_at.isoformat(),
                "source_ip": item.source_ip,
                "site_id": item.site_id,
                "path": item.path,
                "method": item.method,
                "decision": item.decision,
                "risk_score": item.risk_score,
                "signals": item.signals_json,
                "payload": item.payload_json,
            }
            for item in items
        ]
    }


@router.post("/credentials")
def api_credentials(api_key: str | None = Query(default=None), db: Session = Depends(get_db)):
    _require_token(db, api_key, "credential.read")
    items = list_credentials(db, limit=settings.public_api_default_limit)
    return {
        "items": [
            {
                "created_at": item.created_at.isoformat(),
                "source_ip": item.source_ip,
                "service_name": item.service_name,
                "username": item.username,
                "password": item.password,
                "matched_keywords": item.matched_keywords_json,
            }
            for item in items
        ]
    }
