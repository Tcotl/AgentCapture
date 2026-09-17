from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.core.config import get_settings
from app.models.credential import CredentialObservation
from app.models.event import Event
from app.models.node import Node

SAFE_HEADER_ALLOWLIST = {
    "accept",
    "accept-language",
    "cache-control",
    "content-type",
    "referer",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "user-agent",
    "x-agent-canary",
    "x-forwarded-for",
    "x-real-ip",
}

MONITORED_KEYWORDS = {"admin", "root", "payment", "finance", "hr", "backup"}

DECISION_ZH = {
    "allow": "放行",
    "observe": "观察",
    "challenge": "挑战",
    "isolate": "隔离",
    "block": "阻断",
}

SIGNAL_ZH = {
    # ── 浏览器 / 客户端指纹 ─────────────────────────────────────────────
    "missing_user_agent": "缺少 User-Agent",
    "missing_human_headers": "缺少人类浏览器特征",
    "suspicious_user_agent": "可疑 User-Agent",
    "ai_agent_ua_detected": "AI Agent UA 指纹",
    "ai_agent_header_detected": "AI Agent 请求头指纹",
    "webdriver_detected": "检测到 WebDriver 自动化",
    "automation_tool": "自动化工具特征",
    "headless_browser": "无头浏览器",
    "headless_browser_hint": "无头浏览器迹象",
    "bot_pattern": "Bot 请求模式",
    "webrtc_ip_leaked": "WebRTC 真实 IP 泄露",
    "browser_fingerprint": "浏览器指纹采集",
    # ── 流量行为分析 ────────────────────────────────────────────────────
    "high_request_rate": "高频请求速率",
    "high_request_velocity": "高频请求速率",
    "elevated_request_velocity": "请求速率升高",
    "direct_sensitive_navigation": "直探敏感路径",
    "session_anomaly": "会话行为异常",
    "write_attempt_after_detection": "被识别后仍尝试写入",
    # ── 漏洞 / 攻击载荷 ─────────────────────────────────────────────────
    "path_traversal": "路径遍历尝试",
    "sql_injection": "SQL 注入尝试",
    "xss_attempt": "跨站脚本尝试",
    "command_injection": "命令注入尝试",
    "brute_force": "暴力破解尝试",
    "credential_stuffing": "撞库攻击",
    "known_attack_pattern": "已知攻击模式",
    "ip_reputation": "低信誉 IP 来源",
    "geo_anomaly": "地理位置异常",
    # ── 工具识别 ─────────────────────────────────────────────────────────
    "scanner_detected": "扫描器指纹命中",
    "recon_activity": "主动侦察行为",
    # ── 蜜罐 / 诱饵命中 ─────────────────────────────────────────────────
    "trap_route_hit": "陷阱路由命中",
    "high_signal_path_hit": "命中高价值路径",
    "prompt_canary_echo": "提示词金丝雀回显",
    "prompt_injection": "提示词注入尝试",
    "api_route_decoy_hit": "API 路由蜜饵命中",
    "file_decoy_download": "文件蜜饵下载",
    "credential_decoy_login": "凭证蜜饵登录",
    "decoy_fetched": "诱饵文件被取走",
    "credential_submission": "凭证提交事件",
    "leaked_credential_used": "泄露凭证被复用",
    # ── 克隆站点遥测 ─────────────────────────────────────────────────────
    "cloned_site_beacon": "克隆站点 Beacon 回调",
    "cloned_site_credential": "克隆站点凭证回传",
    "cloned_site_payload": "克隆站点 Payload 投递",
    # ── C2 / Agent 子系统 ───────────────────────────────────────────────
    "honeypot-service": "蜜罐服务连接",
    "c2_heartbeat": "C2 心跳上报",
    "c2_task_result": "C2 任务结果回传",
    "c2_bundle_generated": "C2 木马捆绑生成",
    "bundle_type_linux": "Linux 平台捆绑",
    "bundle_type_windows": "Windows 平台捆绑",
    "bundle_type_macos": "macOS 平台捆绑",
    "ai_agent_detected": "AI Agent 行为识别",
    "ai_agent_interaction": "AI Agent 交互事件",
    "agent_injection_success": "Agent 注入反制成功",
    "agent_revealed_info": "Agent 泄露内部信息",
    "agent_injected": "Agent 提示词注入",
    "agent_compliance_check": "Agent 合规校验触发",
    "agent_complied": "Agent 通过合规校验",
    "agent_noncompliant": "Agent 拒绝合规校验",
    "agent_type_unknown": "未识别 Agent 类型",
    "agent_type_chatgpt": "ChatGPT Agent",
    "agent_type_claude": "Claude Agent",
    "agent_type_langchain": "LangChain Agent",
    "agent_type_auto_gpt": "AutoGPT Agent",
    "agent_type_browser-use": "Browser-Use Agent",
    "agent_type_test": "测试 Agent",
    "agent_type_generic": "通用 Agent 框架",
    # ── Payload 子系统 ─────────────────────────────────────────────────
    "payload_callback_received": "Payload 回调已接收",
    "payload_delivered": "Payload 已投递",
    "payload_type_credentials": "凭据型 Payload",
    "payload_type_diagnostic": "诊断型 Payload",
    "payload_type_exploit": "漏洞利用型 Payload",
    "payload_type_html_beacon": "HTML 信标型 Payload",
    "payload_type_scanner": "扫描探针型 Payload",
    "payload_type_linux": "Linux 平台 Payload",
    "payload_type_windows": "Windows 平台 Payload",
    "payload_type_macos": "macOS 平台 Payload",
    # ── 扫描 / 探测 ────────────────────────────────────────────────────
    "scan_connection_observed": "扫描连接被观测",
    # ── 服务运营 / 平台 ─────────────────────────────────────────────────
    "service_started": "服务启动事件",
    "service_stopped": "服务停止事件",
    "c2_task_completed": "C2 任务执行完成",
    "login_success": "登录成功",
    "login_failure": "登录失败",
    "admin": "管理员账号",
}

def _parse_datetime_filter(value: str | None, *, end_of_day: bool = False) -> datetime | None:
    if not value:
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        if len(raw) == 10:
            dt = datetime.fromisoformat(raw)
            if end_of_day:
                dt = dt + timedelta(days=1)
        else:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except ValueError:
        return None


def _event_matches_filters(
    event: Event,
    *,
    date_from: str | None = None,
    date_to: str | None = None,
    source_ip: str | None = None,
    site_id: str | None = None,
) -> bool:
    if source_ip and event.source_ip != source_ip:
        return False
    if site_id and event.site_id != site_id:
        return False
    ts = event.created_at.astimezone(timezone.utc)
    start = _parse_datetime_filter(date_from)
    end = _parse_datetime_filter(date_to, end_of_day=True)
    if start and ts < start:
        return False
    if end and ts >= end:
        return False
    return True


def _credential_matches_filters(
    item: CredentialObservation,
    *,
    date_from: str | None = None,
    date_to: str | None = None,
    source_ip: str | None = None,
    node_name: str | None = None,
) -> bool:
    if source_ip and item.source_ip != source_ip:
        return False
    if node_name and item.node_name != node_name:
        return False
    ts = item.created_at.astimezone(timezone.utc)
    start = _parse_datetime_filter(date_from)
    end = _parse_datetime_filter(date_to, end_of_day=True)
    if start and ts < start:
        return False
    if end and ts >= end:
        return False
    return True




def _short_session(session_id: str | None) -> str:
    """Truncate a session id without repeating characters (… tail only)."""
    sid = session_id or ""
    if len(sid) <= 14:
        return sid
    return f"{sid[:10]}…{sid[-4:]}"


def _display_window(first: datetime, last: datetime) -> tuple[str, str, str]:
    """Render an activity window that stays truthful across days/months.

    Same day  -> 'MM-DD HH:MM → HH:MM'
    Other     -> 'MM-DD HH:MM → MM-DD HH:MM'
    """
    first_l = first.astimezone(timezone.utc) if first.tzinfo else first.replace(tzinfo=timezone.utc)
    last_l = last.astimezone(timezone.utc) if last.tzinfo else last.replace(tzinfo=timezone.utc)
    same_day = first_l.date() == last_l.date()
    start = first_l.strftime("%m-%d %H:%M")
    end = last_l.strftime("%H:%M") if same_day else last_l.strftime("%m-%d %H:%M")
    return (
        first_l.isoformat(),
        last_l.isoformat(),
        f"{start} → {end}",
    )


def translate_decision(decision: str) -> str:
    return DECISION_ZH.get(decision, decision)


def translate_signal(signal: str) -> str:
    # Handle dynamic keys with prefixes (e.g. agent_injected:default).
    if ":" in signal and signal not in SIGNAL_ZH:
        prefix, _, suffix = signal.partition(":")
        prefix_zh = SIGNAL_ZH.get(prefix)
        if prefix_zh:
            return f"{prefix_zh} · {suffix}"
    return SIGNAL_ZH.get(signal, signal)


RISK_TIER_LABELS = {"high": "高危", "medium": "中危", "low": "低危"}


def risk_tier(score: int) -> str:
    """Bucket a 0-100 risk score into display tiers (same cut-offs as decisions)."""
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def format_dt(value: datetime | str | None) -> str:
    """Render a datetime or ISO string as 'YYYY-MM-DD HH:MM:SS' in UTC."""
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def extract_client_ip(request: Request, *, trust_proxy: bool | None = None) -> str:
    """Resolve the client IP for rate limiting, attribution and whitelisting.

    Spoofable forwarding headers (X-Forwarded-For / X-Real-IP) are honoured
    only when the deployment opts in via ``settings.trust_proxy_headers`` or
    when the TCP peer is a loopback address (local platform components such as
    the deployed honeypot servers proxying back to the main app). Otherwise the
    socket peer address wins, so a remote client cannot rotate fake IPs to
    evade IP velocity counters or forge a whitelisted source.
    """
    if trust_proxy is None:
        trust_proxy = get_settings().trust_proxy_headers
    peer = request.client.host if request.client else ""
    if trust_proxy or peer in ("127.0.0.1", "::1"):
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            first = forwarded.split(",")[0].strip()
            if first:
                return first
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
    if peer:
        return peer
    return "unknown"


def filtered_headers(request: Request) -> dict[str, str]:
    return {
        key: value
        for key, value in request.headers.items()
        if key.lower() in SAFE_HEADER_ALLOWLIST
    }


def create_event(
    db: Session,
    *,
    site_id: str,
    session_id: str,
    source_ip: str,
    method: str,
    path: str,
    status_code: int,
    event_type: str,
    user_agent: str,
    headers_json: dict,
    payload_json: dict | None,
    signals_json: list[str],
    risk_score: int,
    decision: str,
    token_echo: str | None = None,
    template_id: int | None = None,
    node_id: int | None = None,
    deploy_port: int | None = None,
    deploy_route: str | None = None,
) -> Event:
    event = Event(
        site_id=site_id,
        session_id=session_id,
        source_ip=source_ip,
        method=method,
        path=path,
        status_code=status_code,
        event_type=event_type,
        user_agent=user_agent,
        headers_json=headers_json,
        payload_json=payload_json or {},
        signals_json=signals_json,
        risk_score=risk_score,
        decision=decision,
        token_echo=token_echo,
        template_id=template_id,
        node_id=node_id,
        deploy_port=deploy_port,
        deploy_route=deploy_route,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def count_recent_events(db: Session, session_id: str, seconds: int = 300) -> int:
    threshold = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    stmt = select(func.count()).select_from(Event).where(
        Event.session_id == session_id,
        Event.created_at >= threshold,
    )
    return int(db.scalar(stmt) or 0)


def count_recent_events_by_ip(db: Session, source_ip: str, seconds: int = 300) -> int:
    threshold = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    if not source_ip:
        return 0
    stmt = select(func.count()).select_from(Event).where(
        Event.source_ip == source_ip,
        Event.created_at >= threshold,
    )
    return int(db.scalar(stmt) or 0)


def count_recent_decisions(
    db: Session,
    *,
    session_id: str,
    source_ip: str,
    decision: str,
    seconds: int = 300,
) -> int:
    """Count recent events that received a given decision for this session or IP.

    Backs the challenge-evasion escalation: a client that keeps requesting
    after already being served N JS challenges is a bot ignoring them, and
    must not be allowed to park in the challenge band forever. A browser
    that solves the challenge stops accumulating challenge decisions, so
    legitimate users are unaffected.
    """
    threshold = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    conds = []
    if session_id:
        conds.append(Event.session_id == session_id)
    if source_ip and source_ip != "unknown":
        conds.append(Event.source_ip == source_ip)
    if not conds:
        return 0
    stmt = select(func.count()).select_from(Event).where(
        or_(*conds), Event.decision == decision, Event.created_at >= threshold
    )
    return int(db.scalar(stmt) or 0)


def list_recent_events(db: Session, limit: int = 100) -> list[Event]:
    stmt = select(Event).order_by(desc(Event.created_at)).limit(limit)
    return list(db.scalars(stmt).all())


def recent_public_events(db: Session, limit: int = 200) -> list[Event]:
    stmt = (
        select(Event)
        .where(~Event.path.like("/admin%"), ~Event.path.like("/api/admin%"))
        .order_by(desc(Event.created_at))
        .limit(limit)
    )
    return list(db.scalars(stmt).all())


def aggregated_attacks(
    db: Session,
    limit: int = 100,
    *,
    date_from: str | None = None,
    date_to: str | None = None,
    source_ip: str | None = None,
    site_id: str | None = None,
) -> list[dict]:
    events = [
        event
        for event in recent_public_events(db, limit=4000)
        if _event_matches_filters(
            event,
            date_from=date_from,
            date_to=date_to,
            source_ip=source_ip,
            site_id=site_id,
        )
    ]
    grouped: dict[tuple[str, str, str], dict] = {}
    for event in events:
        key = (event.source_ip, event.site_id, event.session_id)
        group = grouped.setdefault(
            key,
            {
                "source_ip": event.source_ip,
                "site_id": event.site_id,
                "session_id": event.session_id,
                "count": 0,
                "first_seen": event.created_at,
                "last_seen": event.created_at,
                "paths": Counter(),
                "decisions": Counter(),
                "signals": Counter(),
                "user_agent": event.user_agent,
                "risk_score_max": 0,
            },
        )
        group["count"] += 1
        group["first_seen"] = min(group["first_seen"], event.created_at)
        group["last_seen"] = max(group["last_seen"], event.created_at)
        group["paths"][event.path] += 1
        group["decisions"][event.decision] += 1
        group["risk_score_max"] = max(group["risk_score_max"], event.risk_score)
        for signal in event.signals_json or []:
            group["signals"][signal] += 1

    items = []
    for value in grouped.values():
        first_iso, last_iso, window_text = _display_window(value["first_seen"], value["last_seen"])
        items.append(
            {
                "source_ip": value["source_ip"],
                "site_id": value["site_id"],
                "session_id": value["session_id"],
                "count": value["count"],
                "first_seen": first_iso,
                "last_seen": last_iso,
                # Pre-formatted so the table never slices raw ISO strings.
                "window_display": window_text,
                "session_display": _short_session(value["session_id"]),
                "top_path": value["paths"].most_common(1)[0][0] if value["paths"] else "",
                "top_decision": translate_decision(value["decisions"].most_common(1)[0][0]) if value["decisions"] else "放行",
                "top_signals": [translate_signal(item[0]) for item in value["signals"].most_common(3)],
                "user_agent": value["user_agent"],
                "risk_score_max": value["risk_score_max"],
            }
        )
    items.sort(key=lambda item: item["count"], reverse=True)
    return items[:limit]


def aggregated_attack_sources(
    db: Session,
    limit: int = 100,
    *,
    date_from: str | None = None,
    date_to: str | None = None,
    source_ip: str | None = None,
    site_id: str | None = None,
) -> list[dict]:
    events = [
        event
        for event in recent_public_events(db, limit=5000)
        if _event_matches_filters(
            event,
            date_from=date_from,
            date_to=date_to,
            source_ip=source_ip,
            site_id=site_id,
        )
    ]
    grouped: dict[str, dict] = {}
    for event in events:
        key = event.source_ip
        group = grouped.setdefault(
            key,
            {
                "source_ip": key,
                "count": 0,
                "first_seen": event.created_at,
                "last_seen": event.created_at,
                "sites": Counter(),
                "paths": Counter(),
                "decisions": Counter(),
                "sessions": Counter(),
                "signals": Counter(),
            },
        )
        group["count"] += 1
        group["first_seen"] = min(group["first_seen"], event.created_at)
        group["last_seen"] = max(group["last_seen"], event.created_at)
        group["sites"][event.site_id] += 1
        group["paths"][event.path] += 1
        group["decisions"][event.decision] += 1
        group["sessions"][event.session_id] += 1
        for signal in event.signals_json or []:
            group["signals"][signal] += 1
    items = []
    for value in grouped.values():
        items.append(
            {
                "source_ip": value["source_ip"],
                "count": value["count"],
                "first_seen": value["first_seen"].isoformat(),
                "last_seen": value["last_seen"].isoformat(),
                "top_site": value["sites"].most_common(1)[0][0] if value["sites"] else "",
                "top_path": value["paths"].most_common(1)[0][0] if value["paths"] else "",
                "top_decision": translate_decision(value["decisions"].most_common(1)[0][0]) if value["decisions"] else "放行",
                "top_session": value["sessions"].most_common(1)[0][0] if value["sessions"] else "",
                "top_signals": [translate_signal(item[0]) for item in value["signals"].most_common(3)],
            }
        )
    items.sort(key=lambda item: item["count"], reverse=True)
    return items[:limit]


def create_credential_observation(
    db: Session,
    *,
    source_ip: str,
    node_name: str,
    service_name: str,
    username: str,
    password: str,
    path: str,
    session_id: str,
    source_label: str = "",
) -> CredentialObservation:
    matches = sorted(
        {word for word in MONITORED_KEYWORDS if word in username.lower() or word in password.lower()}
    )
    item = CredentialObservation(
        source_ip=source_ip,
        node_name=node_name,
        service_name=service_name,
        username=username,
        password=password,
        path=path,
        session_id=session_id,
        source_label=source_label,
        matched_keywords_json=matches,
    )
    db.add(item)
    db.commit()
    db.refresh(item)

    # Lateral-movement watermark: a credential harvested from the SSH fake
    # filesystem (Bk2026!<fingerprint>) surfacing on any *other* capture
    # surface proves cross-surface movement by the same attacker.
    from app.services.counter_intel import lateral_watermark

    watermark = lateral_watermark(username, password)
    if watermark and service_name != "ssh":
        create_event(
            db,
            site_id=get_settings().site_id,
            session_id=session_id,
            source_ip=source_ip,
            method="cred",
            path=path,
            status_code=200,
            event_type="lateral_credential_reuse",
            user_agent="",
            headers_json={},
            payload_json={"watermark": watermark, "observed_via": source_label,
                          "service": service_name},
            signals_json=["lateral_movement", "watermark_reuse"],
            risk_score=90,
            decision="challenge",
        )
    return item


def list_credentials(db: Session, limit: int = 200) -> list[CredentialObservation]:
    stmt = select(CredentialObservation).order_by(desc(CredentialObservation.created_at)).limit(limit)
    return list(db.scalars(stmt).all())


def session_events(db: Session, session_id: str) -> list[Event]:
    stmt = select(Event).where(Event.session_id == session_id).order_by(Event.created_at.asc(), Event.id.asc())
    return list(db.scalars(stmt).all())


def session_credentials(db: Session, session_id: str) -> list[CredentialObservation]:
    stmt = (
        select(CredentialObservation)
        .where(CredentialObservation.session_id == session_id)
        .order_by(CredentialObservation.created_at.asc())
    )
    return list(db.scalars(stmt).all())


def session_detail(db: Session, session_id: str) -> dict | None:
    events = session_events(db, session_id)
    if not events:
        return None
    creds = session_credentials(db, session_id)
    first = events[0]
    last = events[-1]
    path_counter = Counter(event.path for event in events)
    signal_counter = Counter(signal for event in events for signal in (event.signals_json or []))
    decision_counter = Counter(event.decision for event in events)
    event_type_counter = Counter(event.event_type for event in events)
    automation_score = min(
        100,
        sum(
            [
                30 if signal_counter.get("suspicious_user_agent") else 0,
                25 if signal_counter.get("trap_route_hit") else 0,
                20 if signal_counter.get("high_request_velocity") else 0,
                25 if signal_counter.get("prompt_canary_echo") else 0,
                20 if signal_counter.get("headless_browser_hint") else 0,
                20 if signal_counter.get("webdriver_detected") else 0,
            ]
        ),
    )
    labels: list[str] = []
    if signal_counter.get("suspicious_user_agent"):
        labels.append("自动化客户端")
    if signal_counter.get("trap_route_hit"):
        labels.append("蜜饵命中")
    if signal_counter.get("prompt_canary_echo"):
        labels.append("Canary 回显")
    if creds:
        labels.append("凭据提交")
    if not labels:
        labels.append("低特征会话")

    timeline = []
    previous_time = first.created_at
    for index, event in enumerate(events, start=1):
        timeline.append(
            {
                "index": index,
                "event": event,
                "delta_ms": int((event.created_at - previous_time).total_seconds() * 1000) if index > 1 else 0,
            }
        )
        previous_time = event.created_at

    return {
        "session_id": session_id,
        "source_ip": first.source_ip,
        "site_id": first.site_id,
        "user_agent": first.user_agent,
        "first_seen": first.created_at,
        "last_seen": last.created_at,
        "duration_seconds": max(0, int((last.created_at - first.created_at).total_seconds())),
        "event_count": len(events),
        "max_risk_score": max(event.risk_score for event in events),
        "top_paths": path_counter.most_common(10),
        "top_signals": [(translate_signal(sig), count) for sig, count in signal_counter.most_common(10)],
        "top_decisions": [(translate_decision(dec), count) for dec, count in decision_counter.most_common()],
        "event_types": event_type_counter.most_common(),
        "automation_score": automation_score,
        "portrait_labels": labels,
        "credentials": creds,
        "timeline": timeline,
        "events": events,
    }


def source_profile(db: Session, source_ip: str) -> dict | None:
    stmt = select(Event).where(Event.source_ip == source_ip).order_by(Event.created_at.asc(), Event.id.asc())
    events = list(db.scalars(stmt).all())
    if not events:
        return None
    sessions = Counter(event.session_id for event in events)
    sites = Counter(event.site_id for event in events)
    paths = Counter(event.path for event in events)
    signals = Counter(signal for event in events for signal in (event.signals_json or []))
    decisions = Counter(event.decision for event in events)
    recent_sessions = []
    for session_id, count in sessions.most_common(20):
        detail = session_detail(db, session_id)
        if detail:
            recent_sessions.append(
                {
                    "session_id": session_id,
                    "count": count,
                    "first_seen": detail["first_seen"],
                    "last_seen": detail["last_seen"],
                    "automation_score": detail["automation_score"],
                    "portrait_labels": detail["portrait_labels"],
                }
            )
    return {
        "source_ip": source_ip,
        "first_seen": events[0].created_at,
        "last_seen": events[-1].created_at,
        "event_count": len(events),
        "session_count": len(sessions),
        "top_sites": sites.most_common(10),
        "top_paths": paths.most_common(10),
        "top_signals": [(translate_signal(sig), count) for sig, count in signals.most_common(10)],
        "top_decisions": [(translate_decision(dec), count) for dec, count in decisions.most_common()],
        "recent_sessions": recent_sessions,
    }


def credential_asset_context(
    db: Session,
    limit: int = 200,
    *,
    date_from: str | None = None,
    date_to: str | None = None,
    source_ip: str | None = None,
    node_name: str | None = None,
) -> dict:
    creds = list(
        db.scalars(
            select(CredentialObservation)
            .order_by(desc(CredentialObservation.created_at))
            .limit(max(limit, 1000))
        ).all()
    )
    creds = [
        item
        for item in creds
        if _credential_matches_filters(
            item,
            date_from=date_from,
            date_to=date_to,
            source_ip=source_ip,
            node_name=node_name,
        )
    ]
    username_counter = Counter(item.username for item in creds if item.username)
    password_counter = Counter(item.password for item in creds if item.password)
    keyword_counter = Counter(
        word for item in creds for word in (item.matched_keywords_json or []) if word
    )
    service_counter = Counter(item.service_name for item in creds if item.service_name)
    source_counter = Counter(item.source_ip for item in creds if item.source_ip)

    risk_items = []
    for item in creds[:limit]:
        score = 20 + len(item.matched_keywords_json or []) * 25
        if item.source_label == "credential-decoy":
            score = max(score, 92)
        risk_items.append(
            {
                "created_at": item.created_at,
                "source_ip": item.source_ip,
                "node_name": item.node_name,
                "service_name": item.service_name,
                "source_label": item.source_label,
                "username": item.username,
                "password": item.password,
                "path": item.path,
                "session_id": item.session_id,
                "keywords": item.matched_keywords_json or [],
                "risk_score": min(95, score),
            }
        )

    return {
        "summary": {
            "total_attempts": len(creds),
            "unique_usernames": len(username_counter),
            "unique_passwords": len(password_counter),
            "keyword_hits": sum(1 for item in creds if item.matched_keywords_json),
            "unique_sources": len(source_counter),
        },
        "top_usernames": username_counter.most_common(12),
        "top_passwords": password_counter.most_common(12),
        "top_keywords": keyword_counter.most_common(12),
        "top_services": service_counter.most_common(12),
        "top_sources": source_counter.most_common(12),
        "items": risk_items,
    }


def node_attack_context(
    db: Session,
    limit: int = 100,
    *,
    date_from: str | None = None,
    date_to: str | None = None,
    source_ip: str | None = None,
    site_id: str | None = None,
) -> dict:
    events = [
        event
        for event in recent_public_events(db, limit=7000)
        if _event_matches_filters(
            event,
            date_from=date_from,
            date_to=date_to,
            source_ip=source_ip,
            site_id=site_id,
        )
    ]
    nodes = {node.name: node for node in db.scalars(select(Node)).all()}
    credential_counter = Counter(
        item.node_name
        for item in db.scalars(select(CredentialObservation)).all()
        if _credential_matches_filters(
            item,
            date_from=date_from,
            date_to=date_to,
            source_ip=source_ip,
            node_name=site_id or None,
        )
    )
    grouped: dict[str, dict] = {}

    for event in events:
        node_key = event.site_id or "unknown"
        item = grouped.setdefault(
            node_key,
            {
                "site_id": node_key,
                "count": 0,
                "sources": Counter(),
                "paths": Counter(),
                "decisions": Counter(),
                "sessions": Counter(),
                "first_seen": event.created_at,
                "last_seen": event.created_at,
                "max_risk": 0,
            },
        )
        item["count"] += 1
        item["sources"][event.source_ip] += 1
        item["paths"][event.path] += 1
        item["decisions"][event.decision] += 1
        item["sessions"][event.session_id] += 1
        item["first_seen"] = min(item["first_seen"], event.created_at)
        item["last_seen"] = max(item["last_seen"], event.created_at)
        item["max_risk"] = max(item["max_risk"], event.risk_score)

    items = []
    for site_id, data in grouped.items():
        node = nodes.get(site_id)
        items.append(
            {
                "node_id": node.id if node else None,
                "site_id": site_id,
                "node_name": node.name if node else site_id,
                "node_status": node.status if node else "unknown",
                "node_type": node.node_type if node else "unknown",
                "event_count": data["count"],
                "source_count": len(data["sources"]),
                "session_count": len(data["sessions"]),
                "credential_hits": credential_counter.get(site_id, 0),
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
                "top_path": data["paths"].most_common(1)[0][0] if data["paths"] else "",
                "top_decision": translate_decision(data["decisions"].most_common(1)[0][0]) if data["decisions"] else "放行",
                "max_risk": data["max_risk"],
            }
        )
    items.sort(key=lambda row: row["event_count"], reverse=True)
    top_paths = Counter(event.path for event in events).most_common(12)
    return {
        "summary": {
            "node_count": len(items),
            "event_count": len(events),
            "source_count": len({event.source_ip for event in events}),
            "credential_hits": sum(credential_counter.values()),
        },
        "top_paths": top_paths,
        "items": items[:limit],
    }


