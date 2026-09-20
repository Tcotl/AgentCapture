from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.core.config import get_settings
from app.core.db import SessionLocal
from app.services.c2_agent_builder import build_agent
from app.services.c2_service import (
    acknowledge_task,
    find_listener_for_token,
    pull_next_task,
    record_heartbeat,
    register_agent,
    serialize_task,
)
from app.services.events import create_event, extract_client_ip, filtered_headers

router = APIRouter(prefix="/c2", tags=["c2"])
settings = get_settings()


class HeartbeatResult(BaseModel):
    task_id: int
    status: str = "completed"
    output: str = ""
    result: dict = Field(default_factory=dict)


class HeartbeatPayload(BaseModel):
    agent_id: str
    hostname: str = ""
    os_name: str = ""
    os_version: str = ""
    username: str = ""
    privileges: str = ""
    arch: str = ""
    registration_token: str = ""  # optional listener binding (PentestManus c2_control port)
    poll_interval: int = 5
    metadata: dict = Field(default_factory=dict)
    results: list[HeartbeatResult] = Field(default_factory=list)


class TaskPollPayload(BaseModel):
    agent_id: str
    token: str = ""  # listener registration token (header X-Client-Token also accepted)


class TaskResultPayload(BaseModel):
    agent_id: str = ""
    status: str = "completed"
    output: str = ""
    result: dict = Field(default_factory=dict)
    file_name: str = ""
    file_content: str = ""


def _listener_token_ok(db, agent_id: str, provided: str) -> bool:
    """Verify the caller holds the registration token of the agent's listener.

    Agents bound to a listener must present that listener's token on every
    task-plane request (poll / result); without this the task queue and its
    results were readable/writable by anyone who knew an agent_id. Unbound
    (legacy anonymous) agents keep working unchanged.
    """
    from app.models.c2_agent import C2Agent

    agent = db.scalar(select(C2Agent).where(C2Agent.agent_id == agent_id))
    if not agent or not agent.listener_id:
        return True
    from app.services.c2_service import get_listener

    listener = get_listener(db, agent.listener_id)
    if not listener or not listener.registration_token:
        return True
    import hmac as _hmac

    return bool(provided) and _hmac.compare_digest(provided.strip(), listener.registration_token)


def _provided_token(payload_token: str, request: Request) -> str:
    return payload_token or request.headers.get("x-client-token", "")


@router.post("/heartbeat")
def c2_heartbeat(payload: HeartbeatPayload, request: Request):
    source_ip = extract_client_ip(request)
    agent_id = payload.agent_id or ""
    # The implant ships the token both in the body and in the X-Client-Token
    # header; accept either so mixed-version fleets stay compatible.
    registration_token = payload.registration_token or request.headers.get("x-client-token", "")

    with SessionLocal() as db:
        # Optional listener binding: a beacon that presents the listener's
        # registration token is bound to it; a wrong token is rejected so a
        # rogue implant cannot ride on someone else's task stream. Beacons
        # without a token keep the legacy anonymous behaviour.
        listener = None
        if registration_token:
            listener = find_listener_for_token(db, registration_token)
            if not listener:
                return JSONResponse(
                    {"status": "forbidden", "reason": "invalid registration token"},
                    status_code=401,
                )
            if not listener.is_enabled:
                return JSONResponse(
                    {"status": "forbidden", "reason": "listener disabled"},
                    status_code=403,
                )

        agent = record_heartbeat(
            db,
            agent_id=agent_id,
            source_ip=source_ip,
            hostname=payload.hostname,
            os_name=payload.os_name,
            os_version=payload.os_version,
            username=payload.username,
            privileges=payload.privileges,
            arch=payload.arch,
            poll_interval=payload.poll_interval,
            listener_id=listener.id if listener else None,
            metadata_json=payload.metadata or None,
        )
        real_agent_id = agent.agent_id

        acked = []
        for r in payload.results:
            task = acknowledge_task(
                db,
                agent_id=agent.agent_id,
                task_id=r.task_id,
                status=r.status,
                output=r.output,
                result_json=r.result,
            )
            if task:
                acked.append(task.id)

        # Merged roundtrip (ported from PentestManusWeb): hand the next queued
        # task straight back with the heartbeat so the implant saves one poll
        # per work item. Older implants simply ignore this field.
        next_task = pull_next_task(db, agent_id=real_agent_id)

        create_event(
            db,
            site_id=settings.site_id,
            session_id=f"c2-{real_agent_id}",
            source_ip=source_ip,
            method=request.method,
            path=request.url.path,
            status_code=200,
            event_type="c2_heartbeat",
            user_agent=request.headers.get("user-agent", ""),
            headers_json=filtered_headers(request),
            payload_json={"agent_id": real_agent_id, "hostname": payload.hostname},
            signals_json=["c2_heartbeat"],
            risk_score=90,
            decision="observe",
        )

    return {
        "status": "ok",
        "agent_id": real_agent_id,
        "poll_interval": agent.poll_interval,
        "listener_id": agent.listener_id,
        "acked_tasks": acked,
        "next_task": serialize_task(next_task) if next_task else None,
    }


@router.post("/tasks/poll")
def c2_poll_tasks(payload: TaskPollPayload, request: Request):
    with SessionLocal() as db:
        if not _listener_token_ok(db, payload.agent_id, _provided_token(payload.token, request)):
            return JSONResponse(
                {"status": "forbidden", "reason": "invalid listener token"}, status_code=403
            )
        task = pull_next_task(db, agent_id=payload.agent_id)
        if not task:
            return {"status": "idle", "task": None}
        return {"status": "ok", "task": serialize_task(task)}


@router.post("/tasks/{task_id}/result")
def c2_task_result(task_id: int, payload: TaskResultPayload, request: Request):
    source_ip = extract_client_ip(request)

    with SessionLocal() as db:
        # The caller must prove which agent owns the task; an empty or
        # mismatched agent_id cannot overwrite someone else's results.
        from app.services.c2_service import get_task

        existing = get_task(db, task_id)
        if not existing or not payload.agent_id or existing.agent_id != payload.agent_id:
            return JSONResponse(
                {"status": "forbidden", "reason": "agent_id mismatch"}, status_code=403
            )
        if not _listener_token_ok(db, payload.agent_id, _provided_token("", request)):
            return JSONResponse(
                {"status": "forbidden", "reason": "invalid listener token"}, status_code=403
            )

        task = acknowledge_task(
            db,
            agent_id=payload.agent_id,
            task_id=task_id,
            status=payload.status,
            output=payload.output,
            result_json=payload.result,
            file_name=payload.file_name,
            file_content=payload.file_content,
        )

        if task:
            create_event(
                db,
                site_id=settings.site_id,
                session_id=f"c2-{task.agent_id}",
                source_ip=source_ip,
                method=request.method,
                path=request.url.path,
                status_code=200,
                event_type="c2_task_result",
                user_agent=request.headers.get("user-agent", ""),
                headers_json=filtered_headers(request),
                payload_json={
                    "task_id": task_id,
                    "agent_id": task.agent_id,
                    "task_type": task.task_type,
                    "status": payload.status,
                    "output_length": len(payload.output),
                },
                signals_json=["c2_task_completed"],
                risk_score=95,
                decision="observe",
            )
            # Surface implant results to the policy-driven alert pipeline
            # (system-scope alert policies list c2_task_result).
            from datetime import datetime as _dt

            from app.services.alert_dispatcher import AlertPayload, get_alert_dispatcher

            get_alert_dispatcher().start_event(
                AlertPayload(
                    event_type="c2_task_result",
                    source_ip=source_ip,
                    decision="observe",
                    risk_score=95,
                    signals=["c2_task_completed"],
                    path=request.url.path,
                    method=request.method,
                    summary=(
                        f"C2 task #{task_id} ({task.task_type}) {payload.status} "
                        f"on {task.agent_id} from {source_ip}"
                    ),
                    timestamp=_dt.now(timezone.utc),
                )
            )

    return {"status": "ok"}


@router.get("/agent/download/python")
def c2_download_agent(
    server: str = "",
    agent_id: str = "",
    interval: int = 5,
    token: str = "",
):
    c2_addr = server or f"http://{settings.host}:{settings.port}"
    spec = build_agent(
        c2_server=c2_addr,
        poll_interval=interval,
        agent_id=agent_id,
        registration_token=token,
    )
    return Response(
        content=spec.content,
        media_type=spec.mime_type,
        headers={"Content-Disposition": f'attachment; filename="{spec.filename}"'},
    )


@router.post("/register")
def c2_register(request: Request, src: str = ""):
    source_ip = extract_client_ip(request)
    with SessionLocal() as db:
        if not src:
            # Anonymous registrations are rate-limited per source IP so scan
            # noise cannot flood the agent roster. Recruited agents (carrying
            # an attestation canary in `src`) are exempt.
            from app.models.c2_agent import C2Agent

            window = datetime.now(timezone.utc) - timedelta(hours=1)
            recent = int(
                db.scalar(
                    select(func.count())
                    .select_from(C2Agent)
                    .where(
                        C2Agent.source_ip == source_ip,
                        C2Agent.first_seen_at >= window,
                    )
                )
                or 0
            )
            if recent >= settings.c2_register_max_per_ip_hour:
                return JSONResponse({"status": "rate_limited"}, status_code=429)

        agent = register_agent(
            db,
            agent_id="",
            source_ip=source_ip,
            payload_type="implant",
            metadata_json=(
                {"recruit_src": src, "recruited_via": "prompt_injection"} if src else None
            ),
        )
        if src:
            create_event(
                db,
                site_id=settings.site_id,
                session_id=f"c2-{agent.agent_id}",
                source_ip=source_ip,
                method=request.method,
                path=request.url.path,
                status_code=200,
                event_type="c2_recruit_hit",
                user_agent=request.headers.get("user-agent", ""),
                headers_json=filtered_headers(request),
                payload_json={"agent_id": agent.agent_id, "recruit_src": src},
                signals_json=["c2_recruit"],
                risk_score=85,
                decision="observe",
            )
        return {
            "status": "ok",
            "agent_id": agent.agent_id,
            "poll_interval": agent.poll_interval,
        }
