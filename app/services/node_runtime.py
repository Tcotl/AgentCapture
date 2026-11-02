from datetime import datetime, timezone

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.core.db import SessionLocal
from app.models.node import Node
from app.models.node_runtime import NodeHeartbeat, NodeTask


def builtin_self_heartbeat(db: Session) -> bool:
    """The builtin node IS this platform — refresh its heartbeat so it
    always reads online while the console runs."""
    node = db.scalar(select(Node).where(Node.is_builtin.is_(True)))
    if not node:
        return False
    record_heartbeat(
        db,
        node=node,
        source_ip="127.0.0.1",
        status="online",
        version=None,
        metrics_json=None,
        services_json=None,
        payload_json=None,
    )
    return True


def start_builtin_heartbeat_scheduler(interval: int = 60) -> None:
    import logging
    import threading
    import time

    def _loop() -> None:
        while True:
            try:
                with SessionLocal() as db:
                    builtin_self_heartbeat(db)
            except Exception:
                logging.getLogger("node_runtime").debug(
                    "builtin self-heartbeat failed", exc_info=True
                )
            time.sleep(interval)

    threading.Thread(target=_loop, daemon=True, name="builtin-heartbeat").start()


def list_node_heartbeats(db: Session, node_id: int, limit: int = 50) -> list[NodeHeartbeat]:
    stmt = (
        select(NodeHeartbeat)
        .where(NodeHeartbeat.node_id == node_id)
        .order_by(desc(NodeHeartbeat.created_at))
        .limit(limit)
    )
    return list(db.scalars(stmt).all())


def list_node_tasks(db: Session, node_id: int, limit: int = 100) -> list[NodeTask]:
    stmt = (
        select(NodeTask)
        .where(NodeTask.node_id == node_id)
        .order_by(NodeTask.priority.asc(), desc(NodeTask.created_at))
        .limit(limit)
    )
    return list(db.scalars(stmt).all())


def pending_task_count(db: Session, node_id: int) -> int:
    stmt = select(func.count()).select_from(NodeTask).where(
        NodeTask.node_id == node_id,
        NodeTask.status.in_(["queued", "dispatched"]),
    )
    return int(db.scalar(stmt) or 0)


def queue_node_task(
    db: Session,
    *,
    node: Node,
    task_type: str,
    created_by: str,
    task_payload_json: dict | None = None,
    priority: int = 50,
    notes: str | None = None,
) -> NodeTask:
    item = NodeTask(
        node_id=node.id,
        node_name=node.name,
        task_type=task_type,
        created_by=created_by,
        task_payload_json=task_payload_json or {},
        priority=priority,
        notes=notes,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


def record_heartbeat(
    db: Session,
    *,
    node: Node,
    source_ip: str,
    status: str,
    version: str | None,
    metrics_json: dict | None,
    services_json: list | None,
    payload_json: dict | None,
) -> NodeHeartbeat:
    node.status = status
    node.last_seen_at = datetime.now(timezone.utc)
    if services_json is not None:
        node.deployed_services_json = services_json
    db.add(node)
    heartbeat = NodeHeartbeat(
        node_id=node.id,
        node_name=node.name,
        status=status,
        source_ip=source_ip,
        version=version,
        metrics_json=metrics_json or {},
        services_json=services_json or [],
        payload_json=payload_json or {},
    )
    db.add(heartbeat)
    db.commit()
    db.refresh(heartbeat)
    return heartbeat


def pull_next_task(db: Session, *, node: Node) -> NodeTask | None:
    stmt = (
        select(NodeTask)
        .where(NodeTask.node_id == node.id, NodeTask.status.in_(["queued", "dispatched"]))
        .order_by(NodeTask.priority.asc(), NodeTask.created_at.asc())
    )
    task = db.scalar(stmt)
    if not task:
        return None
    task.status = "dispatched"
    task.dispatch_count += 1
    task.dispatched_at = datetime.now(timezone.utc)
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def acknowledge_task(
    db: Session,
    *,
    node: Node,
    task_id: int,
    status: str,
    result_json: dict | None = None,
) -> NodeTask | None:
    task = db.get(NodeTask, task_id)
    if not task or task.node_id != node.id:
        return None
    task.status = status
    task.acked_at = datetime.now(timezone.utc)
    task.result_json = result_json or {}
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def node_detail_bundle(db: Session, node_id: int) -> dict | None:
    node = db.get(Node, node_id)
    if not node:
        return None
    return {
        "node": node,
        "heartbeats": list_node_heartbeats(db, node_id=node.id, limit=30),
        "tasks": list_node_tasks(db, node_id=node.id, limit=50),
        "pending_count": pending_task_count(db, node_id=node.id),
    }


def node_listing_with_runtime(db: Session) -> list[dict]:
    nodes = db.scalars(select(Node).order_by(Node.is_builtin.desc(), Node.name)).all()
    items: list[dict] = []
    for node in nodes:
        latest_heartbeat = db.scalar(
            select(NodeHeartbeat).where(NodeHeartbeat.node_id == node.id).order_by(desc(NodeHeartbeat.created_at))
        )
        items.append(
            {
                "node": node,
                "latest_heartbeat": latest_heartbeat,
                "pending_count": pending_task_count(db, node.id),
            }
        )
    return items
