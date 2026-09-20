from collections import defaultdict
from datetime import datetime, timedelta, timezone
import platform
import socket

import psutil
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.core.db import APP_STARTED_AT
from app.models.credential import CredentialObservation
from app.models.decoy import DecoyDeployment, DecoyTemplate
from app.models.event import Event
from app.models.execution import ExecutionHistory
from app.models.intel import ThreatIntelEntry
from app.models.login_log import LoginLog
from app.models.node import Node
from app.models.notification import AlertChannel, AlertPolicy
from app.models.service import ServiceCatalog, ServiceTemplate
from app.models.user import User


def _system_status() -> dict:
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    uptime = datetime.now(timezone.utc) - APP_STARTED_AT
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": round(vm.percent, 2),
        "memory_used_mb": round(vm.used / 1024 / 1024, 2),
        "disk_percent": round(disk.percent, 2),
        "disk_used_gb": round(disk.used / 1024 / 1024 / 1024, 2),
        "uptime_seconds": int(uptime.total_seconds()),
    }


def dashboard_stats(db: Session) -> dict:
    total_events = int(db.scalar(select(func.count()).select_from(Event)) or 0)
    high_risk_events = int(
        db.scalar(select(func.count()).select_from(Event).where(Event.risk_score >= 70)) or 0
    )
    unique_ips = int(db.scalar(select(func.count(func.distinct(Event.source_ip))).select_from(Event)) or 0)
    online_nodes = int(
        db.scalar(select(func.count()).select_from(Node).where(Node.status == "online")) or 0
    )
    services_count = int(db.scalar(select(func.count()).select_from(ServiceCatalog)) or 0)
    templates_count = int(db.scalar(select(func.count()).select_from(ServiceTemplate)) or 0)
    decoy_count = int(db.scalar(select(func.count()).select_from(DecoyTemplate)) or 0)
    deployments_count = int(db.scalar(select(func.count()).select_from(DecoyDeployment)) or 0)
    users_count = int(db.scalar(select(func.count()).select_from(User)) or 0)
    alert_channels = int(db.scalar(select(func.count()).select_from(AlertChannel)) or 0)
    alert_policies = int(db.scalar(select(func.count()).select_from(AlertPolicy)) or 0)
    intel_entries = int(db.scalar(select(func.count()).select_from(ThreatIntelEntry)) or 0)
    login_failures = int(
        db.scalar(
            select(func.count()).select_from(LoginLog).where(LoginLog.login_status == "failed")
        )
        or 0
    )
    credential_attempts = int(db.scalar(select(func.count()).select_from(CredentialObservation)) or 0)
    execution_count = int(db.scalar(select(func.count()).select_from(ExecutionHistory)) or 0)
    recon_events = int(
        db.scalar(select(func.count()).select_from(Event).where(Event.event_type == "recon_fingerprint")) or 0
    )
    agent_interactions = int(
        db.scalar(
            select(func.count()).select_from(Event).where(
                Event.event_type.in_(["agent_interaction", "agent_verification"])
            )
        )
        or 0
    )
    agent_blocks = int(
        db.scalar(
            select(func.count()).select_from(Event).where(
                Event.decision == "block",
                Event.signals_json.contains("ai_agent_"),
            )
        )
        or 0
    )
    payload_downloads = int(
        db.scalar(
            select(func.count()).select_from(Event).where(Event.event_type == "payload_download")
        )
        or 0
    )
    payload_callbacks = int(
        db.scalar(
            select(func.count()).select_from(Event).where(Event.event_type == "payload_callback")
        )
        or 0
    )

    return {
        "system": _system_status(),
        "summary": {
            "total_events": total_events,
            "high_risk_events": high_risk_events,
            "unique_ips": unique_ips,
            "online_nodes": online_nodes,
            "services_count": services_count,
            "templates_count": templates_count,
            "decoy_count": decoy_count,
            "deployments_count": deployments_count,
            "users_count": users_count,
            "alert_channels": alert_channels,
            "alert_policies": alert_policies,
            "intel_entries": intel_entries,
            "login_failures": login_failures,
            "credential_attempts": credential_attempts,
            "execution_count": execution_count,
            "recon_events": recon_events,
            "agent_interactions": agent_interactions,
            "agent_blocks": agent_blocks,
            "payload_downloads": payload_downloads,
            "payload_callbacks": payload_callbacks,
        },
    }


def attack_trends(db: Session, days: int = 7) -> list[dict]:
    threshold = datetime.now(timezone.utc) - timedelta(days=days - 1)
    events = db.scalars(select(Event).where(Event.created_at >= threshold).order_by(Event.created_at)).all()
    buckets: dict[str, int] = defaultdict(int)
    for event in events:
        day = event.created_at.astimezone(timezone.utc).strftime("%Y-%m-%d")
        buckets[day] += 1
    results = []
    for offset in range(days):
        day = (threshold + timedelta(days=offset)).strftime("%Y-%m-%d")
        results.append({"day": day, "count": buckets.get(day, 0)})
    return results


def attack_trends_previous(db: Session, days: int = 7) -> list[int]:
    """Event counts for the period immediately before ``attack_trends``'s window.

    Returns only the counts (aligned by offset) for the comparison line.
    """
    end = datetime.now(timezone.utc) - timedelta(days=days - 1)
    start = end - timedelta(days=days)
    events = db.scalars(
        select(Event).where(Event.created_at >= start, Event.created_at < end)
    ).all()
    buckets: dict[str, int] = defaultdict(int)
    for event in events:
        day = event.created_at.astimezone(timezone.utc).strftime("%Y-%m-%d")
        buckets[day] += 1
    return [buckets.get((start + timedelta(days=offset)).strftime("%Y-%m-%d"), 0) for offset in range(days)]


def attack_chain(db: Session) -> dict:
    events = db.scalars(select(Event).order_by(desc(Event.created_at)).limit(1000)).all()
    credentials = db.scalars(select(CredentialObservation)).all()
    return {
        "scan": sum(1 for item in events if item.event_type == "scan" or "high_request_velocity" in (item.signals_json or [])),
        "attack": sum(1 for item in events if item.event_type == "http_request"),
        "login_attempt": len(credentials),
        "high_risk_login": sum(1 for item in credentials if item.matched_keywords_json),
        "compromise_hint": int(
            db.scalar(
                select(func.count()).select_from(DecoyDeployment).where(DecoyDeployment.status == "triggered")
            )
            or 0
        ),
    }
