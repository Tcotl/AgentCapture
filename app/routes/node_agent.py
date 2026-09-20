from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db
from app.models.node import Node
from app.services.node_runtime import acknowledge_task, pull_next_task, record_heartbeat

router = APIRouter(prefix="/api/node", tags=["node-agent"])


def _require_node_token(request: Request) -> None:
    """Optional shared-secret guard for node endpoints.

    When NODE_AUTH_TOKEN is configured, every node API call must carry a
    matching X-Node-Token header. Empty token keeps legacy open behavior.
    """
    token = get_settings().node_auth_token
    if token and request.headers.get("x-node-token") != token:
        raise HTTPException(status_code=401, detail="invalid node token")


class HeartbeatTaskResult(BaseModel):
    task_id: int
    status: str = Field(default="completed")
    result: dict = Field(default_factory=dict)


class NodeHeartbeatPayload(BaseModel):
    node_name: str
    status: str = "online"
    version: str | None = None
    listen_address: str | None = None
    callback_address: str | None = None
    metrics: dict = Field(default_factory=dict)
    services: list = Field(default_factory=list)
    results: list[HeartbeatTaskResult] = Field(default_factory=list)


class NodePullPayload(BaseModel):
    node_name: str


class NodeAckPayload(BaseModel):
    node_name: str
    task_id: int
    status: str = "completed"
    result: dict = Field(default_factory=dict)


def _resolve_node(db: Session, node_name: str) -> Node:
    node = db.scalar(select(Node).where(Node.name == node_name))
    if not node:
        raise HTTPException(status_code=404, detail="node not found")
    return node


@router.post("/heartbeat")
def node_heartbeat(payload: NodeHeartbeatPayload, request: Request, db: Session = Depends(get_db)):
    _require_node_token(request)
    node = _resolve_node(db, payload.node_name)
    if payload.listen_address:
        node.listen_address = payload.listen_address
    if payload.callback_address:
        node.callback_address = payload.callback_address
    source_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (request.client.host if request.client else "unknown")
    heartbeat = record_heartbeat(
        db,
        node=node,
        source_ip=source_ip,
        status=payload.status,
        version=payload.version,
        metrics_json=payload.metrics,
        services_json=payload.services,
        payload_json=payload.model_dump(),
    )
    acked = []
    for item in payload.results:
        task = acknowledge_task(db, node=node, task_id=item.task_id, status=item.status, result_json=item.result)
        if task:
            acked.append(task.id)
    return {
        "status": "ok",
        "server_time": datetime.now(timezone.utc).isoformat(),
        "heartbeat_id": heartbeat.id,
        "acked_tasks": acked,
    }


@router.post("/tasks/pull")
def node_pull_tasks(payload: NodePullPayload, request: Request, db: Session = Depends(get_db)):
    _require_node_token(request)
    node = _resolve_node(db, payload.node_name)
    task = pull_next_task(db, node=node)
    if not task:
        return {"status": "idle", "task": None}
    return {
        "status": "ok",
        "task": {
            "id": task.id,
            "task_type": task.task_type,
            "priority": task.priority,
            "payload": task.task_payload_json,
            "notes": task.notes,
            "created_at": task.created_at.isoformat(),
        },
    }


@router.post("/tasks/ack")
def node_ack_task(payload: NodeAckPayload, request: Request, db: Session = Depends(get_db)):
    _require_node_token(request)
    node = _resolve_node(db, payload.node_name)
    task = acknowledge_task(db, node=node, task_id=payload.task_id, status=payload.status, result_json=payload.result)
    if not task:
        raise HTTPException(status_code=404, detail="task not found")
    return {"status": "ok", "task_id": task.id, "task_status": task.status}
