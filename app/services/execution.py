from datetime import datetime

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models.execution import ExecutionHistory


def log_execution(
    db: Session,
    *,
    actor_username: str,
    action: str,
    module: str,
    target_type: str,
    target_ref: str,
    status: str = "success",
    detail_json: dict | None = None,
) -> ExecutionHistory:
    item = ExecutionHistory(
        actor_username=actor_username,
        action=action,
        module=module,
        target_type=target_type,
        target_ref=target_ref,
        status=status,
        detail_json=detail_json or {},
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


def list_execution_history(db: Session, limit: int = 100) -> list[ExecutionHistory]:
    stmt = select(ExecutionHistory).order_by(desc(ExecutionHistory.created_at)).limit(limit)
    return list(db.scalars(stmt).all())


def filter_execution_history(
    db: Session,
    *,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    actor_username: str = "",
    module: str = "",
    status: str = "",
    limit: int = 2000,
) -> list[ExecutionHistory]:
    """Filtered, time-scoped query over ``ExecutionHistory`` for list/export."""
    stmt = select(ExecutionHistory)
    if date_from:
        stmt = stmt.where(ExecutionHistory.created_at >= date_from)
    if date_to:
        stmt = stmt.where(ExecutionHistory.created_at < date_to)
    if actor_username:
        stmt = stmt.where(ExecutionHistory.actor_username == actor_username)
    if module:
        stmt = stmt.where(ExecutionHistory.module == module)
    if status:
        stmt = stmt.where(ExecutionHistory.status == status)
    stmt = stmt.order_by(desc(ExecutionHistory.created_at)).limit(limit)
    return list(db.scalars(stmt).all())
