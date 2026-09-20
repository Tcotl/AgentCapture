"""Agent-control protocol endpoints for managed beacons.

Ported from PentestManusWeb ``system/pages/managed_hosts.py`` (AGPL-3.0-only).
Three-layer auth model preserved from the source: listener
``registration_token`` (register) -> ``session_key`` (routing) ->
``lease_token`` (task execution).

Event pipeline integration (honeypot-specific): registration and task
completion are recorded as ``Event`` rows; high-frequency checkin/lease/
heartbeat calls are not, so a 5s beacon cadence does not flood the console.
"""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.core.config import get_settings
from app.core.db import SessionLocal
from app.models.managed import ManagedHost, ManagedListener, ManagedSession
from app.services.events import create_event, extract_client_ip, filtered_headers
from app.services.managed_runtime import (
    add_evidence,
    complete_task,
    fail_task,
    heartbeat_task,
    lease_task_for_session,
    managed_now,
    mark_task_progress,
    serialize_host,
    serialize_listener,
    serialize_session,
    serialize_task,
)

router = APIRouter(prefix="/api/agent-control", tags=["agent-control"])
settings = get_settings()


def _get_session(db, session_key: str) -> ManagedSession | None:
    if not session_key:
        return None
    return db.scalar(select(ManagedSession).where(ManagedSession.session_key == session_key))


def _session_error(status_code: int) -> JSONResponse:
    return JSONResponse({"detail": "invalid sessionKey"}, status_code=status_code)


def _log_managed_event(
    request: Request,
    event_type: str,
    signals: list[str],
    payload: dict,
    score: int,
    decision: str = "observe",
):
    source_ip = extract_client_ip(request)
    with SessionLocal() as db:
        create_event(
            db,
            site_id=settings.site_id,
            session_id=f"managed-{source_ip}",
            source_ip=source_ip,
            method=request.method,
            path=request.url.path,
            status_code=200,
            event_type=event_type,
            user_agent=request.headers.get("user-agent", ""),
            headers_json=filtered_headers(request),
            payload_json=payload,
            signals_json=signals,
            risk_score=score,
            decision=decision,
        )


class RegisterPayload(BaseModel):
    listenerId: int
    registrationToken: str
    hostUid: str
    displayName: str = ""
    hostname: str = ""
    platform: str = "unknown"
    architecture: str = "unknown"
    osVersion: str = ""
    username: str = ""
    internalIps: list[str] = Field(default_factory=list)
    externalIps: list[str] = Field(default_factory=list)
    capabilities: dict = Field(default_factory=dict)
    integrityState: str = ""
    metadata: dict = Field(default_factory=dict)


@router.post("/register")
def agent_register(payload: RegisterPayload, request: Request):
    source_ip = extract_client_ip(request)
    with SessionLocal() as db:
        listener = db.get(ManagedListener, payload.listenerId)
        if not listener:
            return JSONResponse({"detail": "listener not found"}, status_code=404)
        if listener.status != "active":
            return JSONResponse({"detail": "listener disabled"}, status_code=403)
        if (
            not listener.registration_token
            or listener.registration_token != payload.registrationToken
        ):
            return JSONResponse({"detail": "invalid registration token"}, status_code=403)

        now = managed_now()
        host = db.scalar(
            select(ManagedHost).where(
                ManagedHost.listener_id == listener.id,
                ManagedHost.host_uid == payload.hostUid,
            )
        )
        external = list(dict.fromkeys([source_ip, *payload.externalIps]))[:20]
        internal = list(dict.fromkeys(payload.internalIps))[:20]
        if host:
            host.display_name = payload.displayName or host.display_name
            host.hostname = payload.hostname or host.hostname
            host.platform = payload.platform or host.platform
            host.architecture = payload.architecture or host.architecture
            host.os_version = payload.osVersion or host.os_version
            host.username = payload.username or host.username
            host.internal_ips = internal or host.internal_ips
            host.external_ips = external or host.external_ips
            host.capabilities = payload.capabilities or host.capabilities
            host.integrity_state = payload.integrityState or host.integrity_state
            host.metadata_json = {**(host.metadata_json or {}), **(payload.metadata or {})}
            host.last_seen_at = now
        else:
            host = ManagedHost(
                listener_id=listener.id,
                host_uid=payload.hostUid,
                display_name=payload.displayName or payload.hostname or payload.hostUid,
                hostname=payload.hostname or None,
                platform=payload.platform or "unknown",
                architecture=payload.architecture or "unknown",
                os_version=payload.osVersion or None,
                username=payload.username or None,
                internal_ips=internal,
                external_ips=external,
                capabilities=payload.capabilities or {},
                integrity_state=payload.integrityState or None,
                metadata_json=payload.metadata or {},
                last_seen_at=now,
            )
        db.add(host)
        db.flush()

        # Every registration opens a fresh session (source semantics).
        import secrets as _secrets

        session = ManagedSession(
            host_id=host.id,
            listener_id=listener.id,
            session_key=_secrets.token_hex(16),
            transport=listener.transport,
            status="active",
            heartbeat_at=now,
        )
        db.add(session)
        db.commit()
        db.refresh(host)
        db.refresh(session)

        _log_managed_event(
            request,
            "c2_managed_register",
            ["c2_heartbeat", "ai_agent_detected"],
            {"hostUid": payload.hostUid, "listener": listener.name, "sessionId": session.id},
            score=90,
        )
        return {
            "listener": serialize_listener(listener),
            "host": serialize_host(host),
            "session": serialize_session(session),
        }


class CheckinPayload(BaseModel):
    sessionKey: str
    metadata: dict = Field(default_factory=dict)
    internalIps: list[str] = Field(default_factory=list)
    externalIps: list[str] = Field(default_factory=list)
    capabilities: dict = Field(default_factory=dict)
    integrityState: str = ""


@router.post("/checkin")
def agent_checkin(payload: CheckinPayload, request: Request):
    with SessionLocal() as db:
        session = _get_session(db, payload.sessionKey)
        if not session or session.status == "closed":
            return _session_error(404)
        now = managed_now()
        session.heartbeat_at = now
        session.status = "active"
        host = db.get(ManagedHost, session.host_id)
        if host:
            host.last_seen_at = now
            host.status = "online"
            host.internal_ips = list(
                dict.fromkeys([*(host.internal_ips or []), *payload.internalIps])
            )[:20]
            host.capabilities = payload.capabilities or host.capabilities
            host.integrity_state = payload.integrityState or host.integrity_state
            if payload.metadata:
                host.metadata_json = {**(host.metadata_json or {}), **payload.metadata}
            db.add(host)
        db.add(session)
        db.commit()
        db.refresh(session)
        db.refresh(host)
        return {"host": serialize_host(host), "session": serialize_session(session)}


class HeartbeatPayload(BaseModel):
    sessionKey: str


@router.post("/heartbeat")
def agent_heartbeat(payload: HeartbeatPayload):
    with SessionLocal() as db:
        session = _get_session(db, payload.sessionKey)
        if not session or session.status == "closed":
            return _session_error(404)
        session.heartbeat_at = managed_now()
        db.add(session)
        host = db.get(ManagedHost, session.host_id)
        if host:
            host.last_seen_at = managed_now()
            db.add(host)
        db.commit()
        return {"ok": True, "heartbeatAt": session.heartbeat_at.isoformat()}


class LeasePayload(BaseModel):
    sessionKey: str


@router.post("/tasks/lease")
def agent_lease_task(payload: LeasePayload):
    with SessionLocal() as db:
        session = _get_session(db, payload.sessionKey)
        if not session or session.status == "closed":
            return _session_error(404)
        task = lease_task_for_session(db, session=session)
        if not task:
            return {"task": None}
        data = serialize_task(task)
        data["taskId"] = data["id"]
        data["arguments"] = data["arguments"]
        return {"task": data}


class TaskOpPayload(BaseModel):
    sessionKey: str
    leaseToken: str
    summary: str = ""
    metadata: dict = Field(default_factory=dict)
    resultSummary: str = ""
    message: str = ""
    payload: dict = Field(default_factory=dict)
    evidenceType: str = "summary"
    title: str = ""
    contentText: str | None = None


def _task_op(task_id: int, request: Request, body: TaskOpPayload, op: str):
    with SessionLocal() as db:
        session = _get_session(db, body.sessionKey)
        if not session or session.status == "closed":
            return _session_error(404)
        try:
            if op == "heartbeat":
                task = heartbeat_task(
                    db, task_id=task_id, session=session, lease_token=body.leaseToken
                )
            elif op == "progress":
                task = mark_task_progress(
                    db,
                    task_id=task_id,
                    session=session,
                    lease_token=body.leaseToken,
                    summary=body.summary,
                    metadata=body.metadata or None,
                )
            elif op == "complete":
                task = complete_task(
                    db,
                    task_id=task_id,
                    session=session,
                    lease_token=body.leaseToken,
                    result_summary=body.resultSummary,
                    payload=body.payload or None,
                )
                _log_managed_event(
                    request,
                    "c2_task_result",
                    ["c2_task_completed"],
                    {
                        "task_id": task_id,
                        "task_type": task.task_type,
                        "summary": (task.result_summary or "")[:200],
                    },
                    score=95,
                )
            elif op == "fail":
                task = fail_task(
                    db,
                    task_id=task_id,
                    session=session,
                    lease_token=body.leaseToken,
                    message=body.message or "task failed",
                    payload=body.payload or None,
                )
                _log_managed_event(
                    request,
                    "c2_task_result",
                    ["c2_task_completed"],
                    {"task_id": task_id, "task_type": task.task_type, "failed": True},
                    score=95,
                )
            elif op == "evidence":
                _asserted = heartbeat_task(
                    db, task_id=task_id, session=session, lease_token=body.leaseToken
                )
                item = add_evidence(
                    db,
                    host_id=_asserted.host_id,
                    session_id=_asserted.session_id,
                    task_id=_asserted.id,
                    evidence_type=body.evidenceType or "summary",
                    title=body.title,
                    content_text=body.contentText,
                    payload=body.payload or None,
                )
                return {
                    "evidence": {
                        "id": item.id,
                        "evidenceType": item.evidence_type,
                        "title": item.title,
                    }
                }
            else:  # pragma: no cover - dispatch table is closed
                return JSONResponse({"detail": "unknown op"}, status_code=400)
        except LookupError:
            return JSONResponse({"detail": "task not found"}, status_code=404)
        except PermissionError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=409)
        data = serialize_task(task)
        data["taskId"] = data["id"]
        return {"task": data}


@router.post("/tasks/{task_id}/heartbeat")
def agent_task_heartbeat(task_id: int, payload: TaskOpPayload, request: Request):
    return _task_op(task_id, request, payload, "heartbeat")


@router.post("/tasks/{task_id}/progress")
def agent_task_progress(task_id: int, payload: TaskOpPayload, request: Request):
    return _task_op(task_id, request, payload, "progress")


@router.post("/tasks/{task_id}/evidence")
def agent_task_evidence(task_id: int, payload: TaskOpPayload, request: Request):
    return _task_op(task_id, request, payload, "evidence")


@router.post("/tasks/{task_id}/complete")
def agent_task_complete(task_id: int, payload: TaskOpPayload, request: Request):
    return _task_op(task_id, request, payload, "complete")


@router.post("/tasks/{task_id}/fail")
def agent_task_fail(task_id: int, payload: TaskOpPayload, request: Request):
    return _task_op(task_id, request, payload, "fail")
