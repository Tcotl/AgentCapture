from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
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


class NodeEnrollPayload(BaseModel):
    node_name: str = Field(min_length=1, max_length=120)
    zone: str = Field(default="", max_length=64)
    listen_address: str = Field(default="0.0.0.0", max_length=255)


def _resolve_node(db: Session, node_name: str) -> Node:
    node = db.scalar(select(Node).where(Node.name == node_name))
    if not node:
        raise HTTPException(status_code=404, detail="node not found")
    return node


@router.post("/enroll")
def node_enroll(payload: NodeEnrollPayload, request: Request, db: Session = Depends(get_db)):
    """子节点主动接入：自助注册到主控制台（幂等，已存在则原样返回）。"""
    _require_node_token(request)
    node = db.scalar(select(Node).where(Node.name == payload.node_name))
    created = False
    zone_provided = bool(payload.zone.strip())
    if node and zone_provided and node.network_zone != payload.zone.strip()[:64]:
        node.network_zone = payload.zone.strip()[:64]
        db.add(node)
        db.commit()
    if not node:
        node = Node(
            name=payload.node_name.strip(),
            node_type="remote",
            listen_address=payload.listen_address or "0.0.0.0",
            callback_address=payload.listen_address or "0.0.0.0",
            status="online",
            network_zone=payload.zone.strip()[:64],
        )
        db.add(node)
        db.commit()
        created = True
    if created:
        from app.services.execution import log_execution

        log_execution(
            db,
            actor_username=f"node:{node.name}",
            action="enroll",
            module="nodes",
            target_type="node",
            target_ref=node.name,
            detail_json={"zone": node.network_zone, "listen": node.listen_address},
        )
    return {
        "status": "ok",
        "created": created,
        "node_name": node.name,
        "node_id": node.id,
        "network_zone": getattr(node, "network_zone", "") or "",
        "heartbeat": {"method": "POST", "path": "/api/node/heartbeat",
                      "body": {"node_name": node.name, "status": "online"}},
    }


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


@router.get("/agent-script")
def node_agent_script():
    """下发节点执行器脚本（子节点快捷接入直接 curl 下载）。"""
    path = Path(__file__).resolve().parents[2] / "scripts" / "node_agent.py"
    if not path.exists():
        raise HTTPException(status_code=404, detail="node agent script not bundled in this deployment")
    return Response(
        path.read_text(encoding="utf-8"),
        media_type="text/x-python",
        headers={"Content-Disposition": 'attachment; filename="node_agent.py"'},
    )


@router.get("/join")
def node_join_script(
    request: Request,
    name: str = "",
    token: str = "",
    zone: str = "",
    listen: str = "0.0.0.0",
    ports: str = "22,3306,6379,21,9200",
):
    """快捷接入：生成子节点一键接入脚本（下载执行器 + 自助注册 + systemd 常驻）。

    令牌已配置时必须携带匹配的 token 查询参数；生成的链接内嵌令牌，
    请通过内部渠道分发给下属单位。
    """
    settings_ = get_settings()
    expected = settings_.node_auth_token
    if expected and token != expected:
        raise HTTPException(status_code=403, detail="invalid join token")
    token = token.replace('"', "").replace("\\", "").replace("$", "").replace("`", "")
    import re as _re

    clean_name = _re.sub(r"[^A-Za-z0-9._-]", "", name).strip("-._")[:120]
    if not clean_name:
        raise HTTPException(status_code=400, detail="name required")
    zone_clean = _re.sub(r"[^\w\u4e00-\u9fff-]", "", zone).strip()[:64]
    ports_clean = ",".join(p for p in (_re.sub(r"[^0-9]", "", x) for x in ports.split(",")) if p) or "22,3306,6379,21,9200"
    host = (request.url.hostname or "").lower()
    ac_host = host if host not in {"127.0.0.1", "localhost", "0.0.0.0"} else "<AC_IP>"
    ac_port = settings_.port
    token_header = f'-H "X-Node-Token: {token}" ' if token else ""
    script = f"""#!/usr/bin/env bash
# AgentCapture 快捷接入脚本 — {clean_name} @ http://{ac_host}:{ac_port}
# 生成于 {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}；链接内嵌令牌，请勿外传
set -e

AC="{ac_host}"
PORT="{ac_port}"
NAME="{clean_name}"
ZONE="{zone_clean}"
PORTS="{ports_clean}"
TOKEN="{token}"
INSTALL_DIR=/opt/agentcapture-node

mkdir -p "$INSTALL_DIR"
curl -fsS {token_header}"http://$AC:$PORT/api/node/agent-script" -o "$INSTALL_DIR/node_agent.py"

cat > /etc/systemd/system/agentcapture-node.service <<UNIT
[Unit]
Description=AgentCapture node agent
After=network.target

[Service]
WorkingDirectory=$INSTALL_DIR
Environment=NODE_AUTH_TOKEN=$TOKEN
Environment=ZONE=$ZONE\nExecStart=/usr/bin/python3 $INSTALL_DIR/node_agent.py --server http://$AC:$PORT --name $NAME --token "$TOKEN" --enroll --zone "$ZONE" --apply --target-host $AC --allow-ports $PORTS
Restart=always

[Install]
WantedBy=multi-user.target
UNIT

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable --now agentcapture-node
  echo "agentcapture-node service started (journalctl -u agentcapture-node -f)"
else
  echo "systemd unavailable, falling back to nohup"
  nohup python3 -u $INSTALL_DIR/node_agent.py --server http://$AC:$PORT --name $NAME --token "$TOKEN" --enroll --zone "$ZONE" --apply --target-host $AC --allow-ports $PORTS >/var/log/agentcapture-node.log 2>&1 &
  echo "agent started, log: /var/log/agentcapture-node.log"
fi

echo "AgentCapture node '$NAME' joined -> http://$AC:$PORT"
"""
    return Response(
        script,
        media_type="application/x-sh",
        headers={"Content-Disposition": f'attachment; filename="join-{clean_name}.sh"'},
    )
