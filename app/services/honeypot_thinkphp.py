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
<style>body{font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;background:#fff;color:#333;margin:0;padding:24px}
.exception{background:#f8f8f8;border-left:4px solid #e1755c;padding:12px 16px;margin-bottom:16px}
.exception pre{margin:0;white-space:pre-wrap;word-break:break-all;font:12px/1.6 Consolas,monospace}
.copyright{color:#aaa;font-size:12px;margin-top:24px}</style></head>
<body>
<div class="exception">
<div class="message">ThinkPHP V5.0.24 — [ LogicException ]</div>
<pre>{output}</pre>
</div>
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
    if "invokefunction" in blob and "call_user_func_array" in blob:
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
    """Attackers wrap output in echo markers; unwrap so the fake shell runs
    the real command (marker still echoes back inside the output)."""
    low = command.lower().lstrip()
    if low.startswith("echo"):
        rest = command[4:].lstrip()
        # windows-style `echo ^ cmd` / `echo _marker_ && cmd`
        for sep in ("&&", "&", "|", ";"):
            if sep in rest:
                rest = rest.split(sep, 1)[1].strip()
                if rest:
                    return rest
        return rest or command
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


def _client_ip(request: Request) -> str:
    if request.client:
        return request.client.host
    return "unknown"


_NOT_FOUND_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>404 Not Found</title></head>
<body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>"""


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
        return HTMLResponse(_render_home(cfg))

    command = extract_tp_command(query, body)
    command = strip_echo_wrapper(command) if command else ""
    ip = _client_ip(request)

    _log(request, "thinkphp_rce", {
        "command": command[:2000], "source_ip": ip,
        "body_sample": body[:512],
    }, risk=95, signals=["thinkphp_rce", "rce_attempt", "fake_compromise"])

    if not cfg.get("rce_simulation_enabled", True):
        # Face stays up but the exploit path is a dead end: the probe is
        # still fully logged (above), it just gets a plain fingerprint page.
        return HTMLResponse(_render_home(cfg))

    if not command:
        output = "ThinkPHP V5.0.24 #exploit-accepted"
    else:
        sess = _get_shell_session(ip, f"tp-{ip}")
        try:
            output = sess.run(command)[:24000]
        except Exception as exc:
            output = f"sh: {type(exc).__name__}"
        logger.info("TP5 RCE from %s: %s", ip, command[:200])

    seed = ip.replace(".", "")
    app_name = str(cfg.get("app_name") or "ThinkPHP V5.0.24")
    page = (_TP_EXCEPTION_PAGE
            .replace("ThinkPHP V5.0.24", app_name)
            .replace("{output}", output.replace("<", "&lt;"))
            .replace("{seed}", seed))
    return HTMLResponse(page, status_code=200)


tp_router = APIRouter()
tp_router.add_api_route("/", tp_exploit, methods=["GET", "POST"], include_in_schema=False)
tp_router.add_api_route("/index.php", tp_exploit, methods=["GET", "POST"], include_in_schema=False)
tp_router.add_api_route("/public/index.php", tp_exploit, methods=["GET", "POST"], include_in_schema=False)
tp_router.add_api_route("/admin.php", tp_login_page, methods=["GET"], include_in_schema=False)
tp_router.add_api_route("/admin.php", tp_login_submit, methods=["POST"], include_in_schema=False)
tp_router.add_api_route("/login", tp_login_page, methods=["GET"], include_in_schema=False)
tp_router.add_api_route("/login", tp_login_submit, methods=["POST"], include_in_schema=False)
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
                                log_level="warning", access_log=False)
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
