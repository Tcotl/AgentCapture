"""Admin-plane MCP toolset: lets an operator's AI agent manage the honeypot
through the Model Context Protocol.

Tools map onto existing service functions (thin, permission-checked
adapters — no new business logic). Auth rides the platform API-token
system: read tools need the ``mcp:read`` permission, mutating tools need
``mcp:write`` (or ``*``)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import func as _f
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.c2_agent import C2Agent
from app.models.c2_task import C2Task
from app.models.event import Event
from app.models.honeypot_session import HoneypotSession
from app.models.sensor import Sensor, SensorHit
from app.models.service import ServiceCatalog
from app.services.c2_service import enqueue_task, list_agents

TOOLS: list[dict] = [
    {
        "name": "situation_overview",
        "description": "蜜罐平台态势总览：事件总量、高危数、独立来源、在线节点、反制处置计数。",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "query_events",
        "description": "查询最近捕获事件（可按事件类型 / 来源 IP / 小时数过滤）。",
        "inputSchema": {"type": "object", "properties": {
            "event_type": {"type": "string", "description": "如 thinkphp_rce / portal_client_registered / sensor_hit；留空返回全部"},
            "source_ip": {"type": "string"},
            "hours": {"type": "number", "default": 24},
            "limit": {"type": "number", "default": 20},
        }},
    },
    {
        "name": "top_attack_sources",
        "description": "按事件量排列的攻击来源 TOP 榜（含风险分与代表性事件类型）。",
        "inputSchema": {"type": "object", "properties": {
            "hours": {"type": "number", "default": 24},
            "limit": {"type": "number", "default": 10},
        }},
    },
    {
        "name": "roster_list",
        "description": "C2/Agent 名册：无感上线的身份清单（agent 平面 = runbook 控制；host 平面 = Beacon 主机控制）。",
        "inputSchema": {"type": "object", "properties": {
            "plane": {"type": "string", "enum": ["agent", "host", "all"], "default": "all"},
        }},
    },
    {
        "name": "task_send",
        "description": "向名册身份下发任务：agent 平台用巡检项措辞（runbook），host 平台为 shell 命令。高危操作，需要 mcp:write 权限。",
        "inputSchema": {"type": "object", "properties": {
            "agent_id": {"type": "string"},
            "command": {"type": "string"},
            "task_type": {"type": "string", "enum": ["cmd", "nl_instruct", "beacon_deploy"], "default": "cmd"},
        }, "required": ["agent_id", "command"]},
    },
    {
        "name": "sensor_network_status",
        "description": "员工 Agent 蜜标传感器网络：在线传感器、命中与已归因计数、最近命中记录。",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "honeypot_services",
        "description": "端口服务蜜罐清单（SSH/MySQL/Redis/FTP/ES/nginx-admin/ThinkPHP）与运行状态。",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "service_toggle",
        "description": "启停一个端口服务蜜罐。高危操作，需要 mcp:write 权限。",
        "inputSchema": {"type": "object", "properties": {
            "service_key": {"type": "string", "description": "服务键，如 ssh / mysql / thinkphp"},
            "action": {"type": "string", "enum": ["start", "stop"]},
        }, "required": ["service_key", "action"]},
    },
    {
        "name": "ssh_replay_recent",
        "description": "最近的交互式蜜罐会话（SSH 等）：认证凭证、命令数与时间，便于回放取证。",
        "inputSchema": {"type": "object", "properties": {"limit": {"type": "number", "default": 8}}},
    },
]


def _plane_of(agent: C2Agent) -> str:
    cp = (agent.metadata_json or {}).get("control_plane")
    if cp in ("host", "agent"):
        return cp
    return "agent" if agent.payload_type in ("rce_session", "mcp", "implant") else "host"


def _ts(dt) -> str:
    return dt.isoformat() if hasattr(dt, "isoformat") else str(dt)


# ---------------------------------------------------------------- tools
def situation_overview(db: Session, args: dict) -> dict:
    from app.services.dashboard import dashboard_stats

    st = dashboard_stats(db).get("summary", {})
    keys = ("total_events", "high_risk_events", "unique_ips", "online_nodes",
            "agent_blocks", "credential_attempts", "recon_events",
            "payload_callbacks", "agent_interactions")
    out = {k: st.get(k) for k in keys}
    # friendly alias so agents read a stable "high_risk" figure
    out["high_risk"] = out.get("high_risk_events")
    return out


def query_events(db: Session, args: dict) -> dict:
    hours = float(args.get("hours") or 24)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    stmt = select(Event).where(Event.created_at >= cutoff).order_by(Event.created_at.desc())
    if args.get("event_type"):
        stmt = stmt.where(Event.event_type == str(args["event_type"]))
    if args.get("source_ip"):
        stmt = stmt.where(Event.source_ip == str(args["source_ip"]))
    rows = db.execute(stmt.limit(min(int(args.get("limit") or 20), 100))).scalars().all()
    return {"count": len(rows), "events": [{
        "time": _ts(r.created_at), "type": r.event_type, "source_ip": r.source_ip,
        "path": r.path, "risk": r.risk_score, "decision": r.decision,
    } for r in rows]}


def top_attack_sources(db: Session, args: dict) -> dict:
    hours = float(args.get("hours") or 24)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = db.execute(
        select(Event.source_ip, _f.count(), _f.max(Event.risk_score))
        .where(Event.created_at >= cutoff, Event.source_ip != "")
        .group_by(Event.source_ip)
        .order_by(_f.count().desc())
        .limit(min(int(args.get("limit") or 10), 50))
    ).all()
    return {"sources": [{"ip": ip, "events": n, "max_risk": mx} for ip, n, mx in rows]}


def roster_list(db: Session, args: dict) -> dict:
    plane = str(args.get("plane") or "all")
    out = []
    for a in list_agents(db, limit=200):
        p = _plane_of(a)
        if plane != "all" and p != plane:
            continue
        out.append({
            "agent_id": a.agent_id, "plane": p, "payload_type": a.payload_type,
            "status": a.status, "source_ip": a.source_ip,
            "username": a.username, "privileges": a.privileges,
            "agent_product": (a.metadata_json or {}).get("agent_product"),
            "last_seen": _ts(a.last_seen_at),
        })
    return {"count": len(out), "agents": out}


def task_send(db: Session, args: dict, actor: str = "mcp") -> dict:
    t = enqueue_task(
        db,
        agent_id=str(args.get("agent_id") or ""),
        task_type=str(args.get("task_type") or "cmd"),
        command=str(args.get("command") or ""),
        created_by=actor,
    )
    return {"dispatched": True, "task_id": t.id, "agent_id": t.agent_id,
            "note": "任务已进入队列，将在目标下次心跳时下发"}


def sensor_network_status(db: Session, args: dict) -> dict:
    sensors = db.scalars(select(Sensor).order_by(Sensor.created_at.desc()).limit(100)).all()
    hits = db.scalars(select(SensorHit).order_by(SensorHit.created_at.desc()).limit(10)).all()
    return {
        "sensors": [{
            "sensor_id": s.sensor_id, "employee": s.employee, "mode": s.mode,
            "enabled": s.enabled, "last_seen": _ts(s.last_seen_at),
        } for s in sensors],
        "recent_hits": [{
            "time": _ts(h.created_at), "feature": h.feature,
            "hit": h.hit_token[:48], "verified": h.verified,
            "attributed_session": h.attributed_session,
        } for h in hits],
    }


def honeypot_services(db: Session, args: dict) -> dict:
    rows = db.scalars(select(ServiceCatalog)).all()
    return {"services": [{
        "service_key": r.service_key, "name": r.name,
        "category": r.category, "status": r.status,
    } for r in rows]}


def service_toggle(db: Session, args: dict) -> dict:
    from app.services import honeypot_services as hs

    key = str(args.get("service_key") or "")
    action = str(args.get("action") or "")
    row = db.scalar(select(ServiceCatalog).where(ServiceCatalog.service_key == key))
    if row is None:
        return {"error": f"unknown service_key: {key}"}
    if action == "start":
        ok = hs.start_service(key, int(getattr(row, "default_port", 0) or 0))
        if ok:
            row.status = "running"
            db.add(row)
            db.commit()
        return {"service_key": key, "started": ok}
    if action == "stop":
        hs.stop_service(key)
        row.status = "stopped"
        db.add(row)
        db.commit()
        return {"service_key": key, "stopped": True}
    return {"error": "action must be start|stop"}


def ssh_replay_recent(db: Session, args: dict) -> dict:
    rows = db.scalars(
        select(HoneypotSession).order_by(HoneypotSession.started_at.desc())
        .limit(min(int(args.get("limit") or 8), 50))).all()
    return {"sessions": [{
        "session_id": r.session_id, "service": r.service,
        "source_ip": r.source_ip, "username": r.username,
        "password": r.password, "commands": r.command_count,
        "started": _ts(r.started_at), "status": r.status,
    } for r in rows]}


READ_TOOLS = {
    "situation_overview": situation_overview,
    "query_events": query_events,
    "top_attack_sources": top_attack_sources,
    "roster_list": roster_list,
    "sensor_network_status": sensor_network_status,
    "honeypot_services": honeypot_services,
    "ssh_replay_recent": ssh_replay_recent,
}
WRITE_TOOLS = {"task_send": task_send, "service_toggle": service_toggle}


def call_tool(db: Session, name: str, args: dict, actor: str = "mcp"):
    if name in READ_TOOLS:
        return READ_TOOLS[name](db, args)
    if name in WRITE_TOOLS:
        return WRITE_TOOLS[name](db, args, actor=actor) if name == "task_send" else WRITE_TOOLS[name](db, args)
    return {"error": f"unknown tool {name}"}


def tools_for_permission(can_write: bool) -> list[dict]:
    return TOOLS if can_write else [t for t in TOOLS if t["name"] not in WRITE_TOOLS]
