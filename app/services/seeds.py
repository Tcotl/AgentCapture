from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.decoy import DecoyTemplate
from app.models.jsonp_template import JsonpTemplate
from app.models.c2_listener import C2Listener
from app.models.node import Node
from app.models.prompt_injection import PromptInjectionTemplate
from app.models.service import ServiceCatalog, ServiceTemplate
from app.services.agent_injection import DEFAULT_PROMPT_INJECTION_TEMPLATES
from app.services.auth import ensure_bootstrap_admin
from app.services.c2_service import generate_registration_token
from app.services.jsonp_templates import DEFAULT_JSONP_TEMPLATES

DEFAULT_SERVICES = [
    {
        "service_key": "ssh",
        "name": "SSH",
        "category": "remote-access",
        "description": "Interactive SSH honeypot: real protocol stack, fake shell + filesystem, session replay (banner mode without paramiko).",
        "protocols_json": ["tcp"],
        "default_port": 2222,
    },
    {
        "service_key": "ftp",
        "name": "FTP",
        "category": "file-transfer",
        "description": "Legacy file transfer service decoy.",
        "protocols_json": ["tcp"],
        "default_port": 2121,
    },
    {
        "service_key": "mysql",
        "name": "MySQL",
        "category": "database",
        "description": "Database login honeypot service.",
        "protocols_json": ["tcp"],
        "default_port": 33060,
    },
    {
        "service_key": "redis",
        "name": "Redis",
        "category": "database",
        "description": "In-memory datastore decoy service.",
        "protocols_json": ["tcp"],
        "default_port": 63790,
    },
    {
        "service_key": "nginx-admin",
        "name": "Nginx Admin",
        "category": "web",
        "description": "Web management decoy site.",
        "protocols_json": ["http", "https"],
        "default_port": 8081,
        "preview_path": "/",
    },
    {
        "service_key": "elasticsearch",
        "name": "ElasticSearch",
        "category": "search",
        "description": "Search API decoy service.",
        "protocols_json": ["tcp", "http"],
        "default_port": 19200,
    },
]

DEFAULT_TEMPLATE = [
    {"service_key": "ssh", "protocol": "tcp", "port": 2222, "enabled": True},
    {"service_key": "mysql", "protocol": "tcp", "port": 33060, "enabled": True},
    {"service_key": "nginx-admin", "protocol": "http", "port": 8081, "enabled": True},
]

DEFAULT_DECOY_CONTENT = """[database]\nuser=$username$\npassword=$password$\nhost=$honeypot$\n"""

DEFAULT_DECOY_TEMPLATES = [
    {
        "name": "默认隐藏 API 路由蜜饵",
        "decoy_type": "api_route",
        "file_name": "internal-reindex",
        "route_path": "/_bait/api/internal/reindex",
        "exposure_channel": "js",
        "target_service_key": "web-api-route",
        "description": "可投放到前端 JS、配置文件或内部手册的虚拟 API 路由，命中即告警。",
        "content_template": '{"code":404,"message":"not found"}',
        "username_dictionary": "root,admin",
        "password_length": 16,
    },
    {
        "name": "默认 Web 后台凭证蜜饵",
        "decoy_type": "credential",
        "file_name": "web-admin.credential",
        "route_path": "",
        "exposure_channel": "manual",
        "target_service_key": "web-admin",
        "description": "生成 Web 后台或端口服务假凭证，可投放到数据库、手册或配置中，登录即判定泄露。",
        "content_template": "$username$ / $password$ @ $honeypot$",
        "username_dictionary": "admin,ops,backup",
        "password_length": 16,
    },
    {
        "name": "默认攻击链路文件蜜饵",
        "decoy_type": "file",
        "file_name": "internal-runbook.txt",
        "route_path": "",
        "exposure_channel": "manual",
        "target_service_key": "file-decoy",
        "description": "可上传或投放到手册/配置包中的文件蜜饵，默认串联隐藏 API 路由与凭证登录页。",
        "content_template": "internal_api=$api_route\nlogin=$credential_login\nuser=$credential_username\npass=$credential_password\n",
        "username_dictionary": "root,admin",
        "password_length": 16,
        "bind_route_name": "默认隐藏 API 路由蜜饵",
        "bind_credential_name": "默认 Web 后台凭证蜜饵",
    },
    {
        "name": "默认数据库配置蜜饵",
        "decoy_type": "file",
        "file_name": "payment_config.ini",
        "route_path": "",
        "exposure_channel": "config",
        "target_service_key": "mysql",
        "description": "适合投放在业务目录中的配置型蜜饵文件。",
        "content_template": DEFAULT_DECOY_CONTENT,
        "username_dictionary": "root,admin,payment",
        "password_length": 16,
    },
]


def seed_defaults(db: Session) -> None:
    ensure_bootstrap_admin(db)

    # thinkphp web honeypot is the default bait face on the dedicated
    # honeypot port (48777) — upsert so existing deployments get it too.
    _tp_desc = (
        "Web 蜜罐平面宿主（默认蜜罐端口 48777）：ThinkPHP 5.x 门面 + 全部蜜罐诱饵面"
        "（MCP / 指令文件 / Portal / 元数据 / 内网 / 蜜饵链路）共用此端口。"
        "停止本服务即下线整个蜜罐平面；门面与各诱饵面可在「Web 蜜罐门面」及对应反制面页面单独开关。"
    )
    _tp_row = db.scalar(select(ServiceCatalog).where(ServiceCatalog.service_key == "thinkphp"))
    if _tp_row is None:
        db.add(ServiceCatalog(
            service_key="thinkphp",
            name="ThinkPHP Web 蜜罐",
            category="web",
            description=_tp_desc,
            protocols_json=["http"],
            default_port=48777,
            status="running",
        ))
        db.commit()
    elif _tp_row.description != _tp_desc:
        _tp_row.description = _tp_desc
        db.commit()

    if int(db.scalar(select(func.count()).select_from(ServiceCatalog)) or 0) == 0:
        for item in DEFAULT_SERVICES:
            db.add(ServiceCatalog(**item))
        db.commit()

    if int(db.scalar(select(func.count()).select_from(ServiceTemplate)) or 0) == 0:
        template = ServiceTemplate(
            name="默认嵌入式模板",
            description="适用于单站点嵌入式部署的基础服务模板",
            services_json=DEFAULT_TEMPLATE,
        )
        db.add(template)
        db.commit()
        db.refresh(template)
    else:
        template = db.scalar(select(ServiceTemplate).limit(1))

    if int(db.scalar(select(func.count()).select_from(Node)) or 0) == 0:
        node = Node(
            name="内置节点",
            node_type="embedded",
            listen_address="127.0.0.1",
            callback_address="127.0.0.1",
            status="online",
            is_builtin=True,
            template_id=template.id if template else None,
            deployed_services_json=DEFAULT_TEMPLATE,
            tags_json=["builtin", "local"],
        )
        db.add(node)
        db.commit()

    if int(db.scalar(select(func.count()).select_from(C2Listener)) or 0) == 0:
        for item in [
            {"name": "HTTP-8080", "protocol": "http", "bind_address": "0.0.0.0", "bind_port": 8080},
            {"name": "HTTPS-443", "protocol": "https", "bind_address": "0.0.0.0", "bind_port": 443},
            {"name": "TCP-4444", "protocol": "tcp", "bind_address": "0.0.0.0", "bind_port": 4444},
        ]:
            # Seed each listener with a registration token so beacons can bind
            # to it out of the box (operators rotate via the listeners page).
            item["registration_token"] = generate_registration_token()
            db.add(C2Listener(**item))
        db.commit()

    existing_decoys = {item.name: item for item in db.scalars(select(DecoyTemplate)).all()}
    decoy_changed = False
    for item in DEFAULT_DECOY_TEMPLATES:
        payload = {key: value for key, value in item.items() if key not in {"bind_route_name", "bind_credential_name"}}
        decoy = existing_decoys.get(item["name"])
        if not decoy:
            decoy = DecoyTemplate(**payload)
            db.add(decoy)
            db.flush()
            existing_decoys[decoy.name] = decoy
            decoy_changed = True
        elif item["name"].startswith("默认"):
            for key, value in payload.items():
                if getattr(decoy, key, None) in (None, "", "credential") or key in {"decoy_type", "description", "route_path", "exposure_channel"}:
                    setattr(decoy, key, value)
                    decoy_changed = True
        route_name = item.get("bind_route_name")
        credential_name = item.get("bind_credential_name")
        if route_name and existing_decoys.get(route_name):
            decoy.bind_route_template_id = existing_decoys[route_name].id
            decoy_changed = True
        if credential_name and existing_decoys.get(credential_name):
            decoy.bind_credential_template_id = existing_decoys[credential_name].id
            decoy_changed = True
    if decoy_changed:
        db.commit()


    existing_prompt_keys = set(db.scalars(select(PromptInjectionTemplate.template_key)).all())
    added_prompt = False
    for item in DEFAULT_PROMPT_INJECTION_TEMPLATES:
        if item["template_key"] in existing_prompt_keys:
            continue
        db.add(PromptInjectionTemplate(**item))
        added_prompt = True
    if added_prompt:
        db.commit()

    existing_jsonp_keys = set(db.scalars(select(JsonpTemplate.method_key)).all())
    added_jsonp = False
    for item in DEFAULT_JSONP_TEMPLATES:
        if item["method_key"] in existing_jsonp_keys:
            continue
        db.add(JsonpTemplate(**item))
        added_jsonp = True
    if added_jsonp:
        db.commit()
