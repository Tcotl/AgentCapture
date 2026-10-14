from fastapi import APIRouter, Depends, Request, Response

from app.core.config import get_settings
from app.core.db import SessionLocal
from app.schemas.events import BeaconPayload
from app.services.events import create_event, extract_client_ip, filtered_headers
from app.services.risk_engine import classify_beacon

router = APIRouter(prefix="/collect", tags=["collect"])
settings = get_settings()


def _embedded_gate(request: Request) -> Response | None:
    """Console-plane callback channel: 404 while the embedded honeypot is
    disabled (the web honeypot plane's own /collect stays available)."""
    from app.services.system_settings import embedded_disabled_response

    return embedded_disabled_response(request)


def _require_embedded(request: Request) -> None:
    """Route dependency: bare 404 (raised before body validation) while the
    embedded honeypot master switch is off. No-op on the web honeypot plane."""
    from fastapi import HTTPException

    gated = _embedded_gate(request)
    if gated is not None:
        raise HTTPException(status_code=404, detail="Not Found")

@router.get("/internet-verify", dependencies=[Depends(_require_embedded)])
def internet_system_verify(token: str, request: Request):
    """Onboarding self-check for embedded internet systems.

    The generated config preview includes a curl to this endpoint through
    the business domain; a hit proves the decoy prefixes actually reach the
    platform, and the ledger row flips to 监测模式 automatically.
    """
    import hashlib
    import hmac

    from fastapi import HTTPException
    from fastapi.responses import JSONResponse
    from sqlalchemy import select

    from app.models.internet_system import InternetSystem

    source_ip = extract_client_ip(request)
    with SessionLocal() as db:
        systems = db.scalars(select(InternetSystem).order_by(InternetSystem.id)).all()
        matched = None
        secret = (get_settings().secret_key or "ac").encode("utf-8")
        for item in systems:
            expect = hmac.new(
                secret, f"isv:{item.id}".encode("utf-8"), hashlib.sha256
            ).hexdigest()[:24]
            if hmac.compare_digest(expect, (token or "")):
                matched = item
                break
        if matched is None:
            raise HTTPException(status_code=404, detail="Not Found")
        if matched.status != "监测模式":
            matched.status = "监测模式"
            db.add(matched)
            db.commit()
        return JSONResponse(
            {
                "status": "ok",
                "system": matched.domain,
                "state": matched.status,
                "note": "链路验证成功，台账已翻为监测模式",
            }
        )


@router.post("/beacon", status_code=204, dependencies=[Depends(_require_embedded)])
def collect_beacon(payload: BeaconPayload, request: Request) -> Response:
    gated = _embedded_gate(request)
    if gated:
        return gated
    decision = classify_beacon(
        webdriver=payload.webdriver,
        headless_hint=payload.headless_hint,
    )
    # /collect/* is skipped by CaptureAndInjectMiddleware, so resolve the
    # session from the cookie it issued on the page that loaded beacon.js.
    session_id = request.cookies.get(settings.session_cookie_name) or getattr(
        request.state, "session_id", "unknown"
    )

    with SessionLocal() as db:
        create_event(
            db,
            site_id=settings.site_id,
            session_id=session_id,
            source_ip=extract_client_ip(request),
            method=request.method,
            path=request.url.path,
            status_code=204,
            event_type="beacon",
            user_agent=request.headers.get("user-agent", ""),
            headers_json=filtered_headers(request),
            payload_json=payload.model_dump(),
            signals_json=decision.signals,
            risk_score=decision.score,
            decision=decision.decision,
        )

    return Response(status_code=204)


@router.post("/scan", status_code=204, dependencies=[Depends(_require_embedded)])
def collect_scan(payload: dict, request: Request) -> Response:
    gated = _embedded_gate(request)
    if gated:
        return gated
    session_id = request.cookies.get(settings.session_cookie_name) or getattr(
        request.state, "session_id", "unknown"
    )
    with SessionLocal() as db:
        create_event(
            db,
            site_id=settings.site_id,
            session_id=session_id,
            source_ip=extract_client_ip(request),
            method=request.method,
            path=request.url.path,
            status_code=204,
            event_type="scan",
            user_agent=request.headers.get("user-agent", ""),
            headers_json=filtered_headers(request),
            payload_json=payload,
            signals_json=["scan_connection_observed"],
            risk_score=25,
            decision="observe",
        )
    return Response(status_code=204)
