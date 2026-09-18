"""Managed-host C2 runtime: presence, lease lifecycle, serializers, overview.

Trimmed port of PentestManusWeb ``system/managed_runtime.py`` (AGPL-3.0-only).
The port keeps the lease/presence semantics (90s stale, 300s offline, 90s
lease TTL, max 3 retries) and the camelCase wire format, and drops the
evaluation-projection coupling that is PentestManus-specific.

State is advanced lazily: every console read calls :func:`refresh_presence`,
so no background thread is required.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models.managed import (
    ManagedEvidence,
    ManagedHost,
    ManagedListener,
    ManagedSession,
    ManagedTask,
)

MANAGED_STALE_AFTER_SECONDS = 90
MANAGED_OFFLINE_AFTER_SECONDS = 300
# Hosts offline longer than this get metadata flag archived=true so stale
# test/recon hosts stop cluttering the roster (roster can filter them).
# 0 disables. Archived hosts revive on their next heartbeat.
MANAGED_HOST_ARCHIVE_DAYS = 30
MANAGED_LEASE_TTL_SECONDS = 90
MANAGED_LEASE_MAX_RETRIES = 3

TASK_STATUS_TERMINAL = {"completed", "failed", "cancelled", "blocked"}

# Transports the console UI offers (protocol x direction); the API accepts
# the three additional *_poll variants for forward-compat with saved records.
LISTENER_TRANSPORT_OPTIONS = [
    "http_bind",
    "http_reverse",
    "https_bind",
    "https_reverse",
    "tcp_bind",
    "tcp_reverse",
    "udp_bind",
    "udp_reverse",
    "dns_bind",
    "dns_reverse",
    "icmp_bind",
    "icmp_reverse",
]
MANAGED_LISTENER_TRANSPORTS = LISTENER_TRANSPORT_OPTIONS + [
    "http_poll",
    "https_poll",
    "dns_poll",
]

# Capability catalog shipped with every overview; the console builds its
# quick-action buttons from it and the server normalizes tasks against it.
MANAGED_CAPABILITY_CATALOG: list[dict[str, Any]] = [
    {
        "capabilityKey": "command-execution",
        "label": "命令执行",
        "actions": [
            {
                "actionKey": "command_run",
                "taskType": "command_run",
                "label": "执行命令",
                "description": "在受管主机执行 shell 命令并回收 stdout/stderr/退出码。",
                "riskLevel": "medium",
                "executionMode": "single-shot",
                "requiresCommandText": True,
                "requiresApproval": False,
                "defaultArguments": {"timeoutSeconds": 60},
            },
            {
                "actionKey": "process_inspect",
                "taskType": "process_inspect",
                "label": "进程枚举",
                "description": "枚举目标主机进程列表（ps/tasklist）。",
                "riskLevel": "low",
                "executionMode": "single-shot",
                "requiresCommandText": False,
                "requiresApproval": False,
                "defaultArguments": {"includeTree": False},
            },
            {
                "actionKey": "process_kill",
                "taskType": "process_kill",
                "label": "终止进程",
                "description": "按 PID 向目标进程发送信号（默认 SIGTERM）。",
                "riskLevel": "high",
                "executionMode": "single-shot",
                "requiresCommandText": False,
                "requiresApproval": True,
                "defaultArguments": {"pid": 0, "signal": 15},
            },
            {
                "actionKey": "user_list",
                "taskType": "user_list",
                "label": "用户枚举",
                "description": "枚举本地账号与所属组（passwd/dscl/net user）。",
                "riskLevel": "low",
                "executionMode": "single-shot",
                "requiresCommandText": False,
                "requiresApproval": False,
                "defaultArguments": {},
            },
        ],
    },
    {
        "capabilityKey": "file-collection",
        "label": "文件操作",
        "actions": [
            {
                "actionKey": "file_list",
                "taskType": "file_list",
                "label": "列目录",
                "description": "列出指定路径下的条目（名称/类型/大小/时间戳）。",
                "riskLevel": "low",
                "executionMode": "single-shot",
                "requiresCommandText": True,
                "requiresApproval": False,
                "defaultArguments": {"path": ""},
            },
            {
                "actionKey": "file_collect",
                "taskType": "file_collect",
                "label": "回传文件",
                "description": "把目标文件打包为证据回传（≤20 个，单文件 ≤8MB）。",
                "riskLevel": "medium",
                "executionMode": "single-shot",
                "requiresCommandText": True,
                "requiresApproval": False,
                "defaultArguments": {"maxBytes": 8 * 1024 * 1024},
            },
            {
                "actionKey": "file_write",
                "taskType": "file_write",
                "label": "写文件",
                "description": "向目标路径写入内容（content 或 contentBase64）。",
                "riskLevel": "high",
                "executionMode": "single-shot",
                "requiresCommandText": True,
                "requiresApproval": True,
                "defaultArguments": {},
            },
        ],
    },
    {
        "capabilityKey": "network-operations",
        "label": "网络操作",
        "actions": [
            {
                "actionKey": "network_inspect",
                "taskType": "network_inspect",
                "label": "端口探测",
                "description": "对指定 host:port 列表做 TCP 可达性探测（≤50 个）。",
                "riskLevel": "medium",
                "executionMode": "single-shot",
                "requiresCommandText": True,
                "requiresApproval": False,
                "defaultArguments": {"targets": []},
            },
        ],
    },
    {
        "capabilityKey": "host-interaction",
        "label": "主机交互",
        "actions": [
            {
                "actionKey": "screenshot",
                "taskType": "screenshot",
                "label": "截屏",
                "description": "捕获目标桌面截图（scrot/import/screencapture/powershell）。",
                "riskLevel": "medium",
                "executionMode": "single-shot",
                "requiresCommandText": False,
                "requiresApproval": False,
                "defaultArguments": {},
            },
        ],
    },
]

HIGH_RISK_TASK_TYPES = {
    "credential_apply",
    "pivot_action",
    "lateral_movement",
    "port_forward",
    "persistence_action",
    "file_write",
    "process_kill",
}

_ACTION_INDEX: dict[str, dict[str, Any]] = {
    action["taskType"]: {**action, "capabilityKey": cap["capabilityKey"]}
    for cap in MANAGED_CAPABILITY_CATALOG
    for action in cap["actions"]
}


def managed_now() -> datetime:
    return datetime.now(timezone.utc)




def get_capability_catalog() -> list[dict[str, Any]]:
    return MANAGED_CAPABILITY_CATALOG


def listener_approval_policy(listener: ManagedListener) -> dict:
    meta = listener.metadata_json or {}
    policy = meta.get("approvalPolicy")
    return policy if isinstance(policy, dict) else {}


def task_requires_approval(
    listener: ManagedListener | None,
    *,
    task_type: str,
    risk_level: str,
) -> tuple[bool, str | None]:
    """Mirror the source approval triggers (catalog / risk level / policy)."""
    action = _ACTION_INDEX.get(task_type)
    if action and action.get("requiresApproval"):
        return True, "actionPolicy"
    if risk_level in {"high", "critical"}:
        return True, "riskLevel"
    if listener:
        policy = listener_approval_policy(listener)
        if task_type in (policy.get("requireApprovalFor") or []):
            return True, "listenerPolicy"
    if task_type in HIGH_RISK_TASK_TYPES:
        return True, "taskType"
    return False, None


def normalize_transport(transport: str) -> str:
    value = (transport or "https_reverse").strip().lower()
    return value if value in MANAGED_LISTENER_TRANSPORTS else "https_reverse"


# ---------------------------------------------------------------------------
# Serializers (camelCase wire format mirrors the source contract)
# ---------------------------------------------------------------------------


def _as_utc(value: datetime | None) -> datetime | None:
    """SQLite DateTime columns read back naive; normalize before arithmetic."""
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _rel(value: datetime | None) -> str:
    """Human relative time used by the host table's last-heartbeat column."""
    value = _as_utc(value)
    if not value:
        return "-"
    seconds = max(0, int((managed_now() - value).total_seconds()))
    if seconds < 5:
        return "刚刚"
    if seconds < 60:
        return f"{seconds} 秒前"
    if seconds < 3600:
        return f"{seconds // 60} 分钟前"
    if seconds < 86400:
        return f"{seconds // 3600} 小时前"
    return f"{seconds // 86400} 天前"


def serialize_listener(listener: ManagedListener) -> dict[str, Any]:
    return {
        "id": listener.id,
        "name": listener.name,
        "transport": listener.transport,
        "bindAddress": listener.bind_address,
        "bindPort": listener.bind_port,
        "tlsEnabled": bool(listener.tls_enabled),
        "status": listener.status,
        "payloadType": (listener.metadata_json or {}).get("payloadType") or "",
        "metadata": listener.metadata_json or {},
        "createdBy": listener.created_by,
        "createdAt": _iso(listener.created_at),
        "updatedAt": _iso(listener.updated_at),
    }


def serialize_host(
    host: ManagedHost, *, sessions: list[ManagedSession] | None = None
) -> dict[str, Any]:
    sessions = sessions if sessions is not None else []
    return {
        "id": host.id,
        "listenerId": host.listener_id,
        "hostUid": host.host_uid,
        "displayName": host.display_name,
        "hostname": host.hostname,
        "platform": host.platform,
        "architecture": host.architecture,
        "osVersion": host.os_version,
        "username": host.username,
        "internalIps": list(host.internal_ips or []),
        "externalIps": list(host.external_ips or []),
        "capabilities": host.capabilities or {},
        "integrityState": host.integrity_state,
        "status": host.status,
        "labels": list(host.labels or []),
        "metadata": host.metadata_json or {},
        "lastSeenAt": _iso(host.last_seen_at),
        "lastSeenRel": _rel(host.last_seen_at),
        "activeSessionCount": sum(1 for s in sessions if s.status == "active"),
        "createdAt": _iso(host.created_at),
        "updatedAt": _iso(host.updated_at),
    }


def serialize_session(session: ManagedSession) -> dict[str, Any]:
    heartbeat_at = _as_utc(session.heartbeat_at)
    heartbeat_age = int((managed_now() - heartbeat_at).total_seconds()) if heartbeat_at else None
    return {
        "id": session.id,
        "hostId": session.host_id,
        "listenerId": session.listener_id,
        "sessionKey": session.session_key,
        "transport": session.transport,
        "status": session.status,
        "heartbeatAt": _iso(session.heartbeat_at),
        "heartbeatAgeSeconds": heartbeat_age,
        "activeTaskId": session.active_task_id,
        "createdAt": _iso(session.created_at),
        "updatedAt": _iso(session.updated_at),
    }


def serialize_task(task: ManagedTask) -> dict[str, Any]:
    return {
        "id": task.id,
        "hostId": task.host_id,
        "sessionId": task.session_id,
        "listenerId": task.listener_id,
        "taskType": task.task_type,
        "title": task.title,
        "commandText": task.command_text,
        "arguments": task.arguments_json or {},
        "riskLevel": task.risk_level,
        "status": task.status,
        "requiresApproval": bool(task.requires_approval),
        "approvalStatus": task.approval_status,
        "leaseToken": None if task.status in TASK_STATUS_TERMINAL else task.lease_token,
        "taskCode": task.task_code,
        "retryCount": task.retry_count,
        "resultSummary": task.result_summary,
        "createdBy": task.created_by,
        "createdAt": _iso(task.created_at),
        "updatedAt": _iso(task.updated_at),
        "completedAt": _iso(task.completed_at),
    }


def serialize_evidence(item: ManagedEvidence) -> dict[str, Any]:
    return {
        "id": item.id,
        "hostId": item.host_id,
        "sessionId": item.session_id,
        "taskId": item.task_id,
        "evidenceType": item.evidence_type,
        "title": item.title,
        "contentText": item.content_text,
        "payload": item.payload_json or {},
        "sha256": item.sha256,
        "createdAt": _iso(item.created_at),
    }


# ---------------------------------------------------------------------------
# Presence (lazy sweep on every console read)
# ---------------------------------------------------------------------------


def _presence_for(heartbeat_at: datetime | None, now: datetime) -> str:
    heartbeat_at = _as_utc(heartbeat_at)
    if not heartbeat_at:
        return "closed"
    age = (now - heartbeat_at).total_seconds()
    if age > MANAGED_OFFLINE_AFTER_SECONDS:
        return "closed"
    if age > MANAGED_STALE_AFTER_SECONDS:
        return "stale"
    return "active"


def _host_presence(last_seen_at: datetime | None, now: datetime) -> str:
    last_seen_at = _as_utc(last_seen_at)
    if not last_seen_at:
        return "offline"
    age = (now - last_seen_at).total_seconds()
    if age > MANAGED_OFFLINE_AFTER_SECONDS:
        return "offline"
    if age > MANAGED_STALE_AFTER_SECONDS:
        return "stale"
    return "online"


def refresh_presence(db: Session) -> dict[str, int]:
    """Flip host/session presence + reclaim stale leases. Lazy, idempotent."""
    now = managed_now()
    sessions = list(db.scalars(select(ManagedSession)).all())
    for session in sessions:
        session.status = _presence_for(session.heartbeat_at, now)
        db.add(session)

    reclaimed = expire_stale_leases(db, now=now)

    hosts = list(db.scalars(select(ManagedHost)).all())
    archive_cutoff = (
        now - timedelta(days=MANAGED_HOST_ARCHIVE_DAYS)
        if MANAGED_HOST_ARCHIVE_DAYS > 0 else None
    )
    for host in hosts:
        host.status = _host_presence(host.last_seen_at, now)
        # Archive long-dead hosts lazily: a metadata flag (not a status) so
        # presence math is untouched, and the next heartbeat clears it.
        if archive_cutoff is not None:
            last = _as_utc(host.last_seen_at)
            if last and last < archive_cutoff:
                meta = host.metadata_json or {}
                if not meta.get("archived"):
                    meta["archived"] = True
                    meta["archived_at"] = now.isoformat()
                    host.metadata_json = meta
        elif host.metadata_json and host.metadata_json.get("archived"):
            meta = dict(host.metadata_json)
            meta.pop("archived", None)
            meta.pop("archived_at", None)
            host.metadata_json = meta
        db.add(host)
    db.commit()
    return reclaimed


def expire_stale_leases(db: Session, *, now: datetime | None = None) -> dict[str, int]:
    """Requeue or fail tasks whose lease TTL elapsed (max 3 retries)."""
    now = now or managed_now()
    reclaimed = 0
    failed = 0
    rows = db.scalars(
        select(ManagedTask).where(
            ManagedTask.status.in_(["leased", "running"]),
            ManagedTask.lease_expires_at.is_not(None),
        )
    ).all()
    for task in rows:
        expires = _as_utc(task.lease_expires_at)
        if expires is None or expires >= now:
            continue
        if task.retry_count + 1 > MANAGED_LEASE_MAX_RETRIES:
            task.status = "failed"
            task.result_summary = "lease expired repeatedly; agent never returned"
            task.completed_at = now
            failed += 1
        else:
            task.retry_count += 1
            task.status = "queued"
            reclaimed += 1
        task.lease_token = None
        task.leased_at = None
        task.lease_expires_at = None
        db.add(task)
        if task.session_id:
            session = db.get(ManagedSession, task.session_id)
            if session and session.active_task_id == task.id:
                session.active_task_id = None
                db.add(session)
    if reclaimed or failed:
        db.commit()
    return {"reclaimedTasks": reclaimed, "failedTasks": failed}


# ---------------------------------------------------------------------------
# Task lifecycle (lease queue state machine)
# ---------------------------------------------------------------------------


def enqueue_managed_task(
    db: Session,
    *,
    host_id: int,
    task_type: str,
    command_text: str = "",
    arguments: dict | None = None,
    risk_level: str = "",
    created_by: str = "",
) -> ManagedTask:
    host = db.get(ManagedHost, host_id)
    if not host:
        raise ValueError("host not found")
    listener = db.get(ManagedListener, host.listener_id) if host.listener_id else None
    action = _ACTION_INDEX.get(task_type) or {}
    level = risk_level or action.get("riskLevel", "low")
    needs_approval, _reason = task_requires_approval(
        listener, task_type=task_type, risk_level=level
    )
    task = ManagedTask(
        host_id=host.id,
        listener_id=host.listener_id,
        task_type=task_type,
        title=action.get("label") or task_type,
        command_text=(command_text or "")[:12000] or None,
        arguments_json=arguments or dict(action.get("defaultArguments") or {}),
        risk_level=level,
        requires_approval=needs_approval,
        approval_status="pending" if needs_approval else "not_required",
        status="pending_approval" if needs_approval else "queued",
        metadata_json={
            "capabilityKey": action.get("capabilityKey") or "",
            "actionKey": action.get("actionKey") or task_type,
        },
        created_by=created_by or None,
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def _host_supports_task(host: ManagedHost, task_type: str) -> bool:
    capabilities = host.capabilities or {}
    if not capabilities:
        return True  # unknown inventory -> optimistic lease
    tokens = [
        action
        for key, value in capabilities.items()
        if isinstance(value, dict)
        for action in (value.get("actions") or [])
    ]
    return not tokens or task_type in tokens


def lease_task_for_session(db: Session, *, session: ManagedSession) -> ManagedTask | None:
    now = managed_now()
    candidates = db.scalars(
        select(ManagedTask)
        .where(
            ManagedTask.host_id == session.host_id,
            ManagedTask.status == "queued",
            ManagedTask.approval_status.in_(["not_required", "approved"]),
        )
        .order_by(ManagedTask.created_at.asc(), ManagedTask.id.asc())
    ).all()
    host = db.get(ManagedHost, session.host_id)
    for task in candidates:
        if task.session_id and task.session_id != session.id:
            continue
        if host and not _host_supports_task(host, task.task_type):
            continue
        task.status = "leased"
        task.session_id = session.id
        task.lease_token = secrets.token_urlsafe(18)
        task.leased_at = now
        task.lease_expires_at = now + timedelta(seconds=MANAGED_LEASE_TTL_SECONDS)
        task.task_code = task.task_code or f"MT-{secrets.token_hex(3)}"
        db.add(task)
        session.active_task_id = task.id
        db.add(session)
        db.commit()
        db.refresh(task)
        return task
    return None


def _assert_lease(
    db: Session, task_id: int, session: ManagedSession, lease_token: str
) -> ManagedTask:
    task = db.get(ManagedTask, task_id)
    if not task:
        raise LookupError("task not found")
    if task.status in TASK_STATUS_TERMINAL or task.status in {"queued", "pending_approval"}:
        raise PermissionError(f"task is {task.status}")
    if task.session_id != session.id or task.lease_token != lease_token or not lease_token:
        raise PermissionError("lease mismatch")
    return task


def heartbeat_task(
    db: Session, *, task_id: int, session: ManagedSession, lease_token: str
) -> ManagedTask:
    task = _assert_lease(db, task_id, session, lease_token)
    task.lease_expires_at = managed_now() + timedelta(seconds=MANAGED_LEASE_TTL_SECONDS)
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def mark_task_progress(
    db: Session,
    *,
    task_id: int,
    session: ManagedSession,
    lease_token: str,
    summary: str = "",
    metadata: dict | None = None,
) -> ManagedTask:
    task = _assert_lease(db, task_id, session, lease_token)
    if task.status == "leased":
        task.status = "running"
    if not task.started_at:
        task.started_at = managed_now()
    if summary:
        task.result_summary = summary
    if metadata:
        task.metadata_json = {**(task.metadata_json or {}), **metadata}
    task.lease_expires_at = managed_now() + timedelta(seconds=MANAGED_LEASE_TTL_SECONDS)
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def _release_lease(db: Session, task: ManagedTask) -> None:
    task.lease_token = None
    task.leased_at = None
    task.lease_expires_at = None
    if task.session_id:
        session = db.get(ManagedSession, task.session_id)
        if session and session.active_task_id == task.id:
            session.active_task_id = None
            db.add(session)


def complete_task(
    db: Session,
    *,
    task_id: int,
    session: ManagedSession,
    lease_token: str,
    result_summary: str = "",
    payload: dict | None = None,
) -> ManagedTask:
    task = _assert_lease(db, task_id, session, lease_token)
    task.status = "completed"
    task.completed_at = managed_now()
    if result_summary:
        task.result_summary = result_summary[:4096]
    if payload:
        task.result_json = payload
    _release_lease(db, task)
    db.add(task)
    if result_summary:
        add_evidence(
            db,
            host_id=task.host_id,
            session_id=task.session_id,
            task_id=task.id,
            evidence_type="summary",
            title=f"{task.task_type}: {result_summary[:120]}",
            content_text=result_summary[:4096],
        )
    db.commit()
    db.refresh(task)
    return task


def fail_task(
    db: Session,
    *,
    task_id: int,
    session: ManagedSession,
    lease_token: str,
    message: str,
    payload: dict | None = None,
) -> ManagedTask:
    task = _assert_lease(db, task_id, session, lease_token)
    task.status = "failed"
    task.completed_at = managed_now()
    task.result_summary = (message or "task failed")[:4096]
    if payload:
        task.result_json = payload
    _release_lease(db, task)
    db.add(task)
    add_evidence(
        db,
        host_id=task.host_id,
        session_id=task.session_id,
        task_id=task.id,
        evidence_type="stderr",
        title=f"{task.task_type} failed",
        content_text=task.result_summary,
    )
    db.commit()
    db.refresh(task)
    return task


def review_task(
    db: Session, *, task_id: int, action: str, reviewer: str, reason: str = ""
) -> ManagedTask | None:
    """approve / reject / cancel transitions, mirroring the source contract."""
    task = db.get(ManagedTask, task_id)
    if not task or task.status in TASK_STATUS_TERMINAL:
        return None
    now = managed_now()
    if action == "approve" and task.approval_status == "pending":
        task.approval_status = "approved"
        task.status = "queued"
    elif action == "reject" and task.approval_status == "pending":
        task.approval_status = "rejected"
        task.status = "cancelled"
        task.completed_at = now
        _release_lease(db, task)
    elif action == "cancel" and task.status in {"queued", "leased", "running", "pending_approval"}:
        task.status = "cancelled"
        task.approval_status = "cancelled"
        task.completed_at = now
        _release_lease(db, task)
    else:
        return None
    task.reviewed_by = reviewer or None
    task.review_reason = reason or None
    task.updated_at = now
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def add_evidence(
    db: Session,
    *,
    host_id: int | None,
    session_id: int | None,
    task_id: int | None,
    evidence_type: str,
    title: str = "",
    content_text: str | None = None,
    payload: dict | None = None,
) -> ManagedEvidence:
    body = content_text or ""
    item = ManagedEvidence(
        host_id=host_id,
        session_id=session_id,
        task_id=task_id,
        evidence_type=evidence_type,
        title=title[:200] or None,
        content_text=body[:4096] or None,
        payload_json=payload or {},
        sha256=hashlib.sha256(body.encode("utf-8", "replace")).hexdigest() if body else None,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


# ---------------------------------------------------------------------------
# Console aggregation
# ---------------------------------------------------------------------------


def build_shell_transcript(tasks: list[ManagedTask]) -> list[dict[str, Any]]:
    """Merged operator/output stream shown in the console dock."""
    lines: list[dict[str, Any]] = []
    for task in tasks:
        if task.command_text:
            lines.append(
                {
                    "kind": "operator",
                    "stream": "operator",
                    "text": f"$ {task.command_text}",
                    "taskId": task.id,
                    "at": _iso(task.created_at),
                }
            )
        if task.status in TASK_STATUS_TERMINAL and task.result_summary:
            lines.append(
                {
                    "kind": "result",
                    "stream": "stderr" if task.status in {"failed", "cancelled"} else "stdout",
                    "text": task.result_summary,
                    "taskId": task.id,
                    "at": _iso(task.completed_at),
                }
            )
    return sorted(lines, key=lambda row: row["at"] or "")[-120:]


def build_overview(db: Session) -> dict[str, Any]:
    """Single aggregation payload powering all five console tabs."""
    reclaimed = refresh_presence(db)
    listeners = list(db.scalars(select(ManagedListener).order_by(ManagedListener.id.desc())).all())
    hosts = list(db.scalars(select(ManagedHost).order_by(ManagedHost.last_seen_at.desc())).all())
    sessions = list(db.scalars(select(ManagedSession).order_by(desc(ManagedSession.id))).all())
    tasks = list(db.scalars(select(ManagedTask).order_by(desc(ManagedTask.id)).limit(30)).all())
    evidence = list(
        db.scalars(select(ManagedEvidence).order_by(desc(ManagedEvidence.id)).limit(20)).all()
    )

    sessions_by_host: dict[int, list[ManagedSession]] = {}
    for session in sessions:
        sessions_by_host.setdefault(session.host_id, []).append(session)

    active_sessions = [s for s in sessions if s.status == "active"]
    leased = [t for t in tasks if t.status in {"leased", "running"}]
    queued = [t for t in tasks if t.status == "queued"]
    pending_approvals = [t for t in tasks if t.approval_status == "pending"]
    now = managed_now()

    return {
        "stats": {
            "listeners": len(listeners),
            "hosts": len(hosts),
            "onlineHosts": sum(1 for h in hosts if h.status == "online"),
            "sessions": len(sessions),
            "activeSessions": len(active_sessions),
            "queuedTasks": len(queued),
            "pendingApprovals": len(pending_approvals),
            "evidence": len(evidence),
        },
        "runtimeSummary": {
            "leaseTtlSeconds": MANAGED_LEASE_TTL_SECONDS,
            "activeHostCount": sum(1 for h in hosts if h.status == "online"),
            "activeSessionCount": len(active_sessions),
            "leasedTaskCount": len(leased),
            "runningTaskCount": sum(1 for t in leased if t.status == "running"),
            "staleLeaseCount": sum(
                1
                for t in leased
                if _as_utc(t.lease_expires_at) and _as_utc(t.lease_expires_at) < now
            ),
        },
        "leaseDiagnostics": reclaimed,
        "capabilityCatalog": get_capability_catalog(),
        "listeners": [serialize_listener(listener) for listener in listeners[:20]],
        "hosts": [
            serialize_host(host, sessions=sessions_by_host.get(host.id, [])) for host in hosts[:30]
        ],
        "sessions": [serialize_session(session) for session in sessions[:30]],
        "tasks": [serialize_task(task) for task in tasks],
        "evidence": [serialize_evidence(item) for item in evidence],
        "shellTranscript": build_shell_transcript(tasks),
        "pendingApprovals": [serialize_task(task) for task in pending_approvals],
        "generatedAt": _iso(now),
    }
