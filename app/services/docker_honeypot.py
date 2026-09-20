"""Orchestration for user-supplied Docker image honeypots.

Lifecycle: upload an image tar (docker save format) -> deploy creates a
container + starts the deception proxy on the exposed port -> the proxy
injects decoy API routes / bait signals into the traffic. Container
lifecycle is managed through the Docker Engine API
(:mod:`app.services.docker_client`); the deception proxy is an in-process
uvicorn server (:mod:`app.services.docker_proxy`).

Default image templates (presets) cover the most probed vulnerable apps;
images must exist locally (uploaded tar or pulled externally).
"""
from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.docker_honeypot import DockerHoneypot
from app.services import docker_client
from app.services.docker_client import DockerError, DockerUnavailable

DEFAULT_DOCKER_TEMPLATES: list[dict[str, Any]] = [
    {
        "name": "ThinkPHP 5.x RCE 靶场",
        "image": "vulhub/thinkphp:5.0.23",
        "container_port": 80,
        "description": "经典 ThinkPHP 5 缺陷靶场，配合门面 RCE 仿真的探测特征",
        "baits": [
            {"path": "/api/user/info", "body": '{"code":0,"msg":"success","data":{"uid":1001,"user":"deploy","role":"ops"}}'},
            {"path": "/_bait/api/internal/reindex", "body": '{"code":0,"msg":"reindex scheduled"}'},
        ],
    },
    {
        "name": "WordPress 站点",
        "image": "wordpress:5.8-apache",
        "container_port": 80,
        "description": "高频被扫描的 CMS 站点：wp-login 探测、插件枚举即被归因",
        "baits": [
            {"path": "/wp-json/wp/v2/users", "body": '{"code":0,"data":[{"id":1,"name":"webadmin"}]}'},
            {"path": "/.env.bak", "body": "DB_NAME=wordpress\nDB_USER=wp_admin\nDB_PASS=Wp#2025!decoy\n"},
        ],
    },
    {
        "name": "Tomcat 管理台",
        "image": "tomcat:9-jre8",
        "container_port": 8080,
        "description": "Tomcat 示例管理台靶场：/manager 探测与样例应用枚举诱捕",
        "baits": [
            {"path": "/manager/html", "body": '{"status":"ok","apps":["/manager","/host-manager"],"note":"requires role"}'},
            {"path": "/api/servers", "body": '{"code":0,"data":[{"host":"app-01","role":"staging"}]}'},
        ],
    },
    {
        "name": "MCP Inspector 调试台（开源镜像）",
        "image": "ghcr.io/modelcontextprotocol/inspector:latest",
        "container_port": 6274,
        "description": "开源 MCP Inspector 官方镜像（@modelcontextprotocol/inspector）：攻击者与 AI Agent 高频寻找的调试台，配合门面 MCP 端点即构成完整拟真环境",
        "baits": [
            {"path": "/api/health", "body": '{"status":"ok","service":"mcp-inspector"}'},
            {"path": "/_bait/api/servers", "body": '{"servers":[{"name":"internal-mcp-gateway","transport":"http","url":"../mcp"}]}'},
        ],
    },
    {
        "name": "Nginx 静态站",
        "image": "nginx:alpine",
        "container_port": 80,
        "description": "轻量静态站点底座：适合在真实感页面上叠加蜜饵与 API 欺骗路由",
        "baits": [
            {"path": "/api/internal/config", "body": '{"code":0,"data":{"env":"staging","region":"cn-east"}}'},
        ],
    },
]


def get_presets() -> list[dict[str, Any]]:
    return DEFAULT_DOCKER_TEMPLATES


def get_preset(name: str) -> dict[str, Any] | None:
    return next((p for p in DEFAULT_DOCKER_TEMPLATES if p["name"] == name), None)


def docker_ok() -> bool:
    return docker_client.available()


def _sanitize_name(name: str) -> str:
    import re

    return re.sub(r"[^a-zA-Z0-9_.-]", "-", (name or "").strip())[:60] or "honeypot"


def deploy(db: Session, *, name: str, image: str, container_port: int,
           proxy_port: int, baits: list[dict], js_inject: bool = True,
           actor: str = "system") -> DockerHoneypot:
    """Create + start the container and launch the deception proxy on proxy_port."""
    from app.services import docker_proxy

    name = _sanitize_name(name)
    existing = db.scalar(select(DockerHoneypot).where(DockerHoneypot.name == name))
    if existing:
        raise DockerError(f"名称「{name}」已存在")
    if any(h.proxy_port == proxy_port for h in db.scalars(select(DockerHoneypot)).all()
           if h.status == "running"):
        raise DockerError(f"对外端口 {proxy_port} 已被其他蜜罐占用")

    canary = uuid.uuid4().hex[:24]
    cid = docker_client.create_container(
        name, image, container_port,
        labels={docker_client.LABEL_NAME: name},
    )
    docker_client.start_container(cid)
    upstream_ip = docker_client.container_ip(cid)

    record = DockerHoneypot(
        name=name, image=image, container_id=cid,
        container_port=container_port, proxy_port=proxy_port,
        status="running", canary=canary, baits_json=baits,
        js_inject=js_inject, upstream_ip=upstream_ip,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    upstream = f"http://{upstream_ip}:{container_port}" if upstream_ip else f"http://127.0.0.1:{container_port}"
    app = docker_proxy.build_proxy_app(upstream, baits, js_inject=js_inject, canary=canary)
    docker_proxy.start_proxy(proxy_port, app)
    return record


def start(db: Session, honeypot_id: int) -> DockerHoneypot:
    record = db.get(DockerHoneypot, honeypot_id)
    if record is None:
        raise DockerError("记录不存在")
    from app.services import docker_proxy

    upstream = f"http://{record.upstream_ip}:{record.container_port}"
    app = docker_proxy.build_proxy_app(upstream, record.baits_json or [],
                                       js_inject=record.js_inject, canary=record.canary)
    docker_proxy.start_proxy(record.proxy_port, app)
    if record.container_id:
        try:
            docker_client.start_container(record.container_id)
            record.upstream_ip = docker_client.container_ip(record.container_id)
        except DockerError as exc:
            record.status = "error"
            record.error = str(exc)[:500]
            db.add(record)
            db.commit()
            raise
    record.status = "running"
    db.add(record)
    db.commit()
    return record


def stop(db: Session, honeypot_id: int) -> DockerHoneypot:
    record = db.get(DockerHoneypot, honeypot_id)
    if record is None:
        raise DockerError("记录不存在")
    from app.services import docker_proxy

    docker_proxy.stop_proxy(record.proxy_port)
    if record.container_id:
        try:
            docker_client.stop_container(record.container_id)
        except DockerError:
            pass
    record.status = "stopped"
    db.add(record)
    db.commit()
    return record


def remove(db: Session, honeypot_id: int) -> None:
    record = db.get(DockerHoneypot, honeypot_id)
    if record is None:
        raise DockerError("记录不存在")
    from app.services import docker_proxy

    docker_proxy.stop_proxy(record.proxy_port)
    if record.container_id:
        try:
            docker_client.remove_container(record.container_id)
        except DockerError:
            pass
    db.delete(record)
    db.commit()


def update_baits(db: Session, honeypot_id: int, baits: list[dict],
                 js_inject: bool) -> DockerHoneypot:
    record = db.get(DockerHoneypot, honeypot_id)
    if record is None:
        raise DockerError("记录不存在")
    record.baits_json = baits
    record.js_inject = js_inject
    record.updated_at = record.updated_at
    db.add(record)
    db.commit()
    if record.status == "running":
        from app.services import docker_proxy

        upstream = f"http://{record.upstream_ip}:{record.container_port}"
        app = docker_proxy.build_proxy_app(upstream, baits, js_inject=js_inject,
                                           canary=record.canary)
        docker_proxy.start_proxy(record.proxy_port, app)
    return record


def sync_status(db: Session) -> None:
    """Reconcile record status with the real container state."""
    for record in db.scalars(select(DockerHoneypot)).all():
        if not record.container_id:
            continue
        try:
            state = docker_client.container_state(record.container_id)
            want = "running" if state == "running" else "stopped"
        except DockerUnavailable:
            return
        except DockerError:
            want = "removed"
            record.error = "容器已被外部删除"
        if record.status != want:
            record.status = want
            db.add(record)
    db.commit()
