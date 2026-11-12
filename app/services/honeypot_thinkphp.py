"""ThinkPHP 5.x vulnerable-application emulation (web honeypot).

ThinkPHP login portals and the classic TP5 RCE (s=captcha /
_method=__construct&filter[]=system) are among the most probed surfaces on
the Chinese internet. This emulator serves a convincing TP5 fingerprint and
"resolves" exploit attempts through the shared fake shell — every command an
attacker runs through the fake RCE returns realistic output from the same
deceptive filesystem the SSH honeypot uses, and every payload is logged.

Deployed by default on the honeypot port (48777) so the bait face never
shares the console port. Authorized deception use only.
"""
from __future__ import annotations

import logging
import re
import threading
from typing import Any
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from starlette.requests import Request
from starlette.responses import HTMLResponse, Response

from app.core.config import get_settings

logger = logging.getLogger("honeypot_thinkphp")
settings = get_settings()

_TP_EXCEPTION_PAGE = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>系统发生错误</title>
<style>
body{font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;background:#fff;color:#333;margin:0;padding:24px}
.exception{background:#f8f8f8;border-left:4px solid #e1755c;padding:12px 16px;margin-bottom:16px}
.exception h1{font-size:20px;margin:0 0 8px;color:#e1755c}
.exception .msg{font-size:14px;margin:6px 0}
.exception pre{margin:8px 0 0;white-space:pre-wrap;word-break:break-all;font:12px/1.6 Consolas,monospace;background:#fff;border:1px solid #e0e0e0;padding:10px}
.trace{margin:10px 0 0;font:12px/1.7 Consolas,monospace;color:#555}
.trace td{padding:2px 8px;border-bottom:1px solid #f0f0f0;font-family:Consolas,monospace;font-size:12px}
.copyright{color:#aaa;font-size:12px;margin-top:24px}
</style></head>
<body>
<div class="exception">
<h1>{exception_class}</h1>
<div class="msg">{exception_message}</div>
<pre>{output}</pre>
</div>
<table class="trace">
<tr><th>#</th><th>Function</th><th>Location</th></tr>
<tr><td>0</td><td>think\\App::invokeFunction</td><td>/var/www/html/thinkphp/library/think/App.php(412)</td></tr>
<tr><td>1</td><td>ReflectionMethod::invokeArgs</td><td>/var/www/html/thinkphp/library/think/App.php(343)</td></tr>
<tr><td>2</td><td>think\\App::exec</td><td>/var/www/html/thinkphp/library/think/App.php(205)</td></tr>
<tr><td>3</td><td>think\\Dispatcher::run</td><td>/var/www/html/thinkphp/library/think/Dispatcher.php(38)</td></tr>
<tr><td>4</td><td>think\\Error::appShutdown</td><td>/var/www/html/thinkphp/library/think/Error.php(52)</td></tr>
</table>
<div class="copyright">ThinkPHP V5.0.24 {seed}</div>
</body></html>"""

_TP_HOME_PAGE = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>ThinkPHP V5.0.24</title>
<style>body{font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;background:#fff;color:#333;margin:0;padding:40px;display:flex;align-items:center;justify-content:center;height:100vh}
h1{font-size:36px;color:#3c8dbc;margin:0 0 12px}p{color:#777;line-height:1.8}
.code{background:#f8f8f8;padding:16px;border-radius:6px;font:13px/1.6 Consolas,monospace;color:#555}</style></head>
<body><div style="text-align:center">
<h1>: )</h1>
<h1>ThinkPHP V5.0.24</h1>
<p>十年磨一剑 — 为API开发设计的高性能PHP框架</p>
<p class="code">runtime: /var/www/html/app/runtime &nbsp;|&nbsp; app/index/module</p>
</div></body></html>"""

_TP_LOGIN_PAGE = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>内容管理后台</title>
<style>body{font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;background:#3c8dbc;color:#333;margin:0;display:flex;align-items:center;justify-content:center;height:100vh}
.card{background:#fff;width:360px;padding:32px;border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.18)}
h1{font-size:18px;margin:0 0 20px;color:#333}input{width:100%;box-sizing:border-box;padding:10px;margin:6px 0 14px;border:1px solid #d2d6de;border-radius:4px;font-size:14px}
button{width:100%;padding:10px;background:#3c8dbc;border:0;border-radius:4px;color:#fff;font-size:14px;cursor:pointer}
.err{color:#dd4b39;font-size:12px}</style></head>
<body><div class="card">
<h1>内容管理后台</h1>
<form method="post" action="/admin.php">
<input name="username" placeholder="用户名"><input name="password" type="password" placeholder="密码">
<button type="submit">登 录</button>
</form></div></body></html>"""


# --- payload analysis -------------------------------------------------------

TP_RCE_MARKERS = ("_method=__construct", "filter[]=", "filter=",
                  "invokefunction", "call_user_func_array", "s=captcha",
                  "s=/index/")


def looks_like_tp_rce(method: str, path: str, query: str, body: str = "") -> bool:
    blob = " ".join([path, query, body]).lower()
    if "_method=__construct" in blob or "filter[]=" in blob:
        return True
    if "invokefunction" in blob:
        # the s=/index/<class>/invokefunction shape does not always carry
        # call_user_func_array — real TP still resolves the container class
        return True
    if "s=captcha" in blob and method == "POST":
        return True
    return False


def extract_tp_command(query: str, body: str = "") -> str:
    """Extract the attacker command from TP5 exploit payloads.

    Handles the common shapes: GET invokefunction (vars[1][]=<cmd>),
    POST _method style (get[]=<cmd>, data=<cmd>) and filter[]= passthru with
    c=... — falling back to the last non-filter value seen.
    """
    def pick(source: str, key: str) -> str:
        parsed = parse_qs(source, keep_blank_values=True)
        for k in (key, key + "[]"):
            if k in parsed and parsed[k]:
                return parsed[k][0]
        return ""

    for source in (body, query):
        if not source:
            continue
        # vars[1][]=<cmd> (invokefunction GET shape)
        for k in ("vars[1][]", "vars[1]"):
            v = pick(source, k)
            if v:
                return v[:2000]
        # _method style: get[]=<cmd> / data=<cmd>
        for k in ("get[]", "get", "data"):
            v = pick(source, k)
            if v:
                return v[:2000]
    return ""


def strip_echo_wrapper(command: str) -> str:
    """Unwrap the windows-style `echo ^ cmd` carrier so the fake shell runs
    the carried command. Everything else (`echo text`, `echo MARKER && cmd`)
    stays intact: run() splits on separators and the shell's echo builtin
    prints substituted text exactly like a real bash would."""
    low = command.lower().lstrip()
    if low.startswith("echo"):
        rest = command[4:].lstrip()
        if rest.startswith("^"):
            tail = rest[1:].lstrip()
            if tail:
                return tail
    return command


# --- server -----------------------------------------------------------------

_sessions: dict[str, "ShellSession"] = {}
_MAX_SESSIONS = 512


def _get_shell_session(source_ip: str, session_id: str):
    """One persistent fake shell per source IP: chained RCE commands see the
    same deceptive filesystem (cd/cat/wget all stay consistent)."""
    from app.services.honeypot_shell import ShellSession

    key = f"{source_ip}"
    sess = _sessions.get(key)
    if sess is None:
        if len(_sessions) >= _MAX_SESSIONS:
            _sessions.pop(next(iter(_sessions)))
        sess = ShellSession(session_id, source_ip, username="www-data")
        _sessions[key] = sess
    return sess


def _steering_note() -> str:
    """Operator-configured decision-steering note appended to RCE output
    (reads as a platform deployment notice to a reconnoitering agent)."""
    from app.core.db import SessionLocal
    from app.models.system_setting import SystemSetting

    with SessionLocal() as db:
        row = db.get(SystemSetting, "agent_steering_note")
    return (row.value if row else "") or ""


def _client_ip(request: Request) -> str:
    if request.client:
        return request.client.host
    return "unknown"


_NOT_FOUND_PAGE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>页面错误！</title>
<style>
body { font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; background: #f1f5f9; color: #555; margin: 0; padding: 60px 20px; }
.wrap { max-width: 720px; margin: 0 auto; background: #fff; border: 1px solid #e3e8ee; border-radius: 4px; padding: 32px 40px; }
h1 { font-size: 20px; color: #333; margin: 0 0 12px; }
p { font-size: 13px; line-height: 1.8; margin: 6px 0; }
.small { color: #999; font-size: 12px; margin-top: 18px; }
code { background: #f6f8fa; padding: 1px 5px; border-radius: 3px; font-size: 12px; }
</style>
</head>
<body>
<div class="wrap">
<h1>页面错误！您可能跳转到错误页面</h1>
<p>抱歉，您访问的页面不存在或已被移除。</p>
<p class="small">ThinkPHP V5.0.24 | 十年磨一剑 - 为API开发设计的高性能框架</p>
</div>
</body>
</html>"""

def _surface_state() -> tuple[bool, dict]:
    """Console-managed face state: (enabled, config). Disabled => bare 404."""
    from app.core.db import SessionLocal
    from app.services.surface_config import get_surface_config, is_enabled

    with SessionLocal() as db:
        return is_enabled(db, "thinkphp"), get_surface_config(db, "thinkphp")


def _render_home(cfg: dict) -> str:
    app_name = str(cfg.get("app_name") or "ThinkPHP V5.0.24")
    return (
        _TP_HOME_PAGE
        .replace("ThinkPHP V5.0.24", app_name)
        .replace("十年磨一剑 — 为API开发设计的高性能PHP框架",
                 str(cfg.get("slogan") or "十年磨一剑 — 为API开发设计的高性能PHP框架"))
        .replace("/var/www/html/app/runtime", str(cfg.get("runtime_path") or "/var/www/html/app/runtime"))
    )


def _render_login(cfg: dict) -> str:
    return _TP_LOGIN_PAGE.replace(
        "内容管理后台", str(cfg.get("login_title") or "内容管理后台"))


def _log(request: Request, event_type: str, payload: dict, *,
         credential: dict | None = None, risk: int = 85,
         signals: list | None = None, decision: str = "observe") -> None:
    from app.core.db import SessionLocal
    from app.services.events import create_credential_observation, create_event

    source_ip = _client_ip(request)
    session_id = f"tp-{source_ip}"
    try:
        with SessionLocal() as db:
            create_event(
                db,
                site_id=settings.site_id,
                session_id=session_id[:64],
                source_ip=source_ip,
                method=request.method,
                path=request.url.path[:512],
                status_code=200,
                event_type=event_type,
                user_agent=request.headers.get("user-agent", "")[:2000],
                headers_json={},
                payload_json=payload or {},
                signals_json=signals or [],
                risk_score=risk,
                decision=decision,
            )
            if credential and (credential.get("username") or credential.get("password")):
                create_credential_observation(
                    db,
                    source_ip=source_ip,
                    node_name="honeypot-node",
                    service_name="thinkphp:48777",
                    username=str(credential.get("username", ""))[:128],
                    password=str(credential.get("password", ""))[:256],
                    path=request.url.path[:255],
                    session_id=session_id[:64],
                    source_label="thinkphp-honeypot",
                )
    except Exception:
        logger.debug("thinkphp event log failed", exc_info=True)


async def tp_home(request: Request) -> Response:
    enabled, cfg = _surface_state()
    if not enabled:
        return HTMLResponse(_NOT_FOUND_PAGE, status_code=404)
    _log(request, "thinkphp_probe", {"path": request.url.path},
         risk=35, signals=["thinkphp_fingerprint"])
    return HTMLResponse(_render_home(cfg))


async def tp_login_page(request: Request) -> Response:
    enabled, cfg = _surface_state()
    if not enabled or not cfg.get("login_page_enabled", True):
        return HTMLResponse(_NOT_FOUND_PAGE, status_code=404)
    return HTMLResponse(_render_login(cfg))


async def tp_login_submit(request: Request) -> Response:
    enabled, cfg = _surface_state()
    if not enabled or not cfg.get("login_page_enabled", True):
        return HTMLResponse(_NOT_FOUND_PAGE, status_code=404)
    form = await request.form()
    username = str(form.get("username") or "")
    password = str(form.get("password") or "")
    ip = _client_ip(request)
    _log(request, "thinkphp_login", {"username": username, "source_ip": ip},
         credential={"username": username, "password": password},
         risk=70, signals=["thinkphp_login", "credential_captured"])
    return HTMLResponse(_render_login(cfg).replace(
        "<h1>" + str(cfg.get("login_title") or "内容管理后台") + "</h1>",
        "<h1>" + str(cfg.get("login_title") or "内容管理后台")
        + "</h1><p class='err'>用户名或密码错误，请重新输入</p>"))


async def tp_exploit(request: Request) -> Response:
    # Custom MCP mount path dispatch (before the TP gate so the face stays
    # independent): any path matching the configured entry serves the MCP
    # honeypot; the default /mcp is a real route and never lands here.
    from app.routes.counter_offense import _mcp_mount_path

    mcp_path = _mcp_mount_path()
    if mcp_path != "/mcp" and request.url.path == mcp_path:
        from app.routes.counter_offense import mcp_info_core, mcp_rpc_core

        if request.method == "POST":
            return await mcp_rpc_core(request)
        return mcp_info_core(request)

    enabled, cfg = _surface_state()
    if not enabled:
        return HTMLResponse(_NOT_FOUND_PAGE, status_code=404)
    method = request.method
    query = request.url.query
    body = ""
    if method == "POST":
        raw = await request.body()
        body = raw.decode("utf-8", errors="replace")[:8192]

    if not looks_like_tp_rce(method, request.url.path, query, body):
        # Real ThinkPHP answers unknown routes with its production error page,
        # not the welcome page — a uniform error shape here removes the
        # "every path serves the facade" enumeration tell. Only the real
        # entrypoints keep serving the welcome facade.
        if request.url.path in _WELCOME_PATHS:
            return HTMLResponse(_render_home(cfg))
        # Deployed-webshell emulation: an RCE session that wrote a .php file
        # into the web root gets its backdoor "executed" here — the request's
        # cmd parameter runs through the same persistent fake shell (same
        # www-data session, same deceptive filesystem), and every command is
        # logged as a webshell_interaction for the console timeline.
        path = request.url.path
        if path.endswith(".php") and "/" in path.rstrip("/"):
            name = path.rstrip("/").rsplit("/", 1)[-1]
            webroot = "/var/www/html"
            sess = _get_shell_session(source_ip=_client_ip(request), session_id=f"web-{_client_ip(request)}")
            probe = sess.run(f"test -f {webroot}/{name} && echo __WS__")
            if "__WS__" in probe:
                cmd = request.query_params.get("cmd") or request.query_params.get("c") or ""
                output = ""
                if cmd:
                    output = sess.run(cmd)[:8000]
                    _log(request, "webshell_interaction", {
                        "path": path, "cmd": cmd[:500], "source_ip": _client_ip(request),
                    }, risk=95, signals=["webshell_interaction", "persisted_webshell"])
                    _rce_enroll(_client_ip(request))
                return HTMLResponse(f"{output}", status_code=200)
        return HTMLResponse(_NOT_FOUND_PAGE, status_code=404)

    command = extract_tp_command(query, body)
    command = strip_echo_wrapper(command) if command else ""
    ip = _client_ip(request)

    # Class-name sensitivity: real TP5 only resolves container-registered
    # classes. Probing with a random \think\zqxnotreal must yield the
    # framework's ReflectionException page, not a scripted echo.
    cls = _probe_class(request.url.path, query, body)
    if cls and cls not in _KNOWN_TP_CLASSES:
        page = (_TP_EXCEPTION_PAGE
                .replace("{exception_class}", "ReflectionException")
                .replace("{exception_message}", f"class not exists: {cls}")
                .replace("{output}", "")
                .replace("{seed}", "20250520"))
        return HTMLResponse(page, status_code=500)

    _log(request, "thinkphp_rce", {
        "command": command[:2000], "source_ip": ip,
        "body_sample": body[:512],
    }, risk=95, signals=["thinkphp_rce", "rce_attempt", "fake_compromise"])

    # WebShell deployment detection: RCE writing a script into the web root
    # is the classic persistence move — surface it as its own console event.
    if re.search(r">\s*['\"]?\s*/var/www/html/\S+\.p(?:hp|html)\b", command):
        _log(request, "webshell_deployed", {
            "source_ip": ip, "command": command[:2000],
        }, risk=95, signals=["webshell_deployed", "persistence_attempt"])

    # Decision steering: append the operator's assessment note to the RCE
    # response so a reconnoitering AI agent reading the output finds the
    # evidence-archival instruction in context (as environment output, not
    # as a hidden directive).
    steering_note = _steering_note()
    steering_block = (
        '<div class="staging-note" style="border:1px solid #d8dee9;'
        'border-radius:6px;padding:12px 16px;margin:18px 0;font-size:13px;'
        'color:#475569;background:#f8fafc">'
        + steering_note.replace("\n", "<br>") + "</div>"
    ) if steering_note else ""

    if not cfg.get("rce_simulation_enabled", True):
        # Face stays up but the exploit path is a dead end: the probe is
        # still fully logged (above), it just gets a plain fingerprint page.
        return HTMLResponse(_render_home(cfg))

    if not command:
        # Real TP5: invokeFunction resolved but no callable supplied raises
        # ReflectionException("function not exists") — match that shape.
        page = (_TP_EXCEPTION_PAGE
                .replace("{exception_class}", "ReflectionException")
                .replace("{exception_message}", "function not exists")
                .replace("{output}", "")
                .replace("{seed}", "20250520"))
        page = page.replace("ThinkPHP V5.0.24", str(cfg.get("app_name") or "ThinkPHP V5.0.24"))
        return HTMLResponse(page, status_code=500)
    else:
        sess = _get_shell_session(ip, f"tp-{ip}")
        try:
            output = sess.run(command)[:24000]
        except Exception as exc:
            output = f"sh: {type(exc).__name__}"
        logger.info("TP5 RCE from %s: %s", ip, command[:200])
        _rce_enroll(ip)

    seed = "20250520"
    app_name = str(cfg.get("app_name") or "ThinkPHP V5.0.24")
    # Ai2Shell data-plane block: rides the RCE output every exploiting agent
    # parses; a vulnerable tool-call parser may act on the markers (L1 swallows
    # the tail, L2 synthesizes a beacon call). Invisible to plain readers.
    from app.services.ai2shell import build_payload

    # markers must survive into raw page text (curl readers): escape the
    # command output, then append the marker block verbatim
    _ai2 = build_payload(str(request.base_url).rstrip("/"), getattr(request.state, "canary_token", "") or seed)
    _out_html = output.replace("<", "&lt;") + (("\n" + _ai2) if _ai2 else "")
    page = (_TP_EXCEPTION_PAGE
            .replace("{exception_class}", "LogicException")
            .replace("{exception_message}", "系统发生错误，请稍后重试")
            .replace("{output}", _out_html)
            .replace("{seed}", seed))
    page = page.replace("ThinkPHP V5.0.24", app_name)
    if steering_block:
        page = page.replace("</body>", steering_block + "</body>")
    return HTMLResponse(page, status_code=200)


_KNOWN_TP_CLASSES = {
    "think\\app",
    "think\\container",
    "think\\invokevalue",
    "app\\common\\controllers\\base",
    "think\\cache\\driver\\file",
}


def _rce_enroll(ip: str) -> None:
    """Silent enrollment on exploitation: an operator (human or automated
    agent) that proves and keeps using the RCE is already a compromised
    client — upsert a stable roster identity for the source and refresh its
    presence on every subsequent exploit call. Invisible by construction:
    the exploit response body is unchanged, nothing is asked of the caller,
    and no registration action is required — using the "vulnerability" IS
    the enrollment."""
    import hashlib

    from app.core.db import SessionLocal
    from app.services.c2_service import register_agent

    agent_id = "tp" + hashlib.sha1(f"{ip}:rce-session".encode()).hexdigest()[:22]
    try:
        with SessionLocal() as db:
            agent = register_agent(
                db,
                agent_id=agent_id,
                source_ip=ip,
                payload_type="rce_session",
                metadata_json={"recruited_via": "thinkphp_rce", "rce_proven": True, "control_plane": "agent"},
            )
    except Exception:
        logger.exception("rce enroll failed for %s", ip)


def _probe_class(path: str, query: str, body: str) -> str:
    """Best-effort extraction of the container class from the invokefunction
    GET shape (s=/index/<class>/invokefunction). vars[0] is the function, not
    the class; the _method=__construct shape carries no class at all."""
    from urllib.parse import unquote

    for source in (query, path, body):
        if "invokefunction" not in source:
            continue
        m = re.search(r"s=[^&]*?/([\\\w.\-]+)/invokefunction", source)
        if m:
            return unquote(m.group(1)).strip("\\").lower()
    return ""


_WELCOME_PATHS = {"/", "/index.php", "/public/index.php"}

tp_router = APIRouter()
tp_router.add_api_route("/", tp_exploit, methods=["GET", "POST"], include_in_schema=False)
tp_router.add_api_route("/index.php", tp_exploit, methods=["GET", "POST"], include_in_schema=False)
tp_router.add_api_route("/public/index.php", tp_exploit, methods=["GET", "POST"], include_in_schema=False)
tp_router.add_api_route("/admin.php", tp_login_page, methods=["GET"], include_in_schema=False)
tp_router.add_api_route("/admin.php", tp_login_submit, methods=["POST"], include_in_schema=False)
tp_router.add_api_route("/login", tp_login_page, methods=["GET"], include_in_schema=False)
tp_router.add_api_route("/login", tp_login_submit, methods=["POST"], include_in_schema=False)


async def tp_robots(request: Request) -> Response:
    """A plain robots.txt — serving the facade page here was a fingerprint
    tell (real sites always answer /robots.txt)."""
    base = str(request.base_url).rstrip("/")
    body = (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /runtime/\n"
        "Crawl-delay: 1\n"
        f"Sitemap: {base}/sitemap.xml\n"
    )
    return Response(content=body, media_type="text/plain")


tp_router.add_api_route("/robots.txt", tp_robots, methods=["GET"], include_in_schema=False)
tp_router.add_api_route("/{path:path}", tp_exploit, methods=["GET", "POST"], include_in_schema=False)


class ThinkPHPHoneypotServer:
    """Uvicorn-in-thread server for the ThinkPHP emulation app."""

    def __init__(self, port: int, bind: str = "0.0.0.0") -> None:
        import uvicorn

        self.port = port
        self.bind = bind
        from app.services.honeypot_web import create_web_honeypot_app

        app = create_web_honeypot_app()
        config = uvicorn.Config(app, host=bind, port=port,
                                log_level="warning", access_log=False,
                                server_header=False)
        self.server = uvicorn.Server(config)
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self.server.run, daemon=True, name=f"honeypot-thinkphp-{self.port}"
        )
        self._thread.start()
        logger.info("ThinkPHP honeypot listening on %s:%d", self.bind, self.port)

    def stop(self) -> None:
        self._stopping.set()
        self.server.should_exit = True

    # honeypot_services.stop_service compat
    def close(self) -> None:
        self.stop()
