"""Manage background web servers for deployed web-app honeypot templates.

When a template is deployed on a port other than the main application port,
a lightweight Uvicorn server is started in a background thread to serve it.
"""

from __future__ import annotations

import asyncio
import ssl
import threading
import urllib.parse
import urllib.request
from pathlib import Path

from fastapi import APIRouter, Request, Response
from fastapi.responses import HTMLResponse

router = APIRouter()

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# { (port, route_prefix): { "html_path": Path, "dir_path": Path|None,
#                              "template_id": int|None, "node_id": int|None,
#                              "template_name": str } }
_deployed: dict[tuple[int, str], dict] = {}

# { port: (uvicorn.Server, thread) }
_bg_servers: dict[int, tuple[object, threading.Thread]] = {}
_bg_lock = threading.Lock()

MAIN_PORT = 4877  # will be set from config at startup


def _url_encode_ascii(value: str) -> str:
    """Percent-encode non-ASCII characters in *value* so it can be used as a
    safe HTTP header value (the HTTP spec only guarantees 7-bit ASCII)."""
    return "".join(
        ch if 32 <= ord(ch) <= 126 else urllib.parse.quote(ch, safe="")
        for ch in value
    )


def _normalize_port(value) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return MAIN_PORT
    return max(1, min(65535, port))


def _normalize_route(route: str | None) -> str:
    raw = (route or "/").strip() or "/"
    if not raw.startswith("/"):
        raw = f"/{raw}"
    return raw.rstrip("/") or "/"


def _build_app(port: int):
    """Create a lightweight FastAPI app serving all templates for *port*."""
    from fastapi import FastAPI

    app = FastAPI()

    # ---- Proxy honeypot endpoints to the main application ----
    # Cloned pages inject JS that calls /_clone/credential and /_clone/payload/*
    # which live on the main app (MAIN_PORT).  Forward them transparently.
    @app.api_route("/_clone/{tail:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def _proxy_clone(request: Request, tail: str):
        target = f"http://127.0.0.1:{MAIN_PORT}/_clone/{tail}"
        body = await request.body()
        fwd_headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")}
        if body:
            fwd_headers["Content-Length"] = str(len(body))
        # Stamp deployment context so the main app can record template_id
        # on the resulting Event row.
        ctx = get_deployment_context(port, request.url.path)
        if ctx:
            if ctx.get("template_id") is not None:
                fwd_headers["X-Template-Id"] = str(ctx["template_id"])
            if ctx.get("node_id") is not None:
                fwd_headers["X-Node-Id"] = str(ctx["node_id"])
            if ctx.get("template_name"):
                # Template name may contain non-ASCII (Chinese), which
                # urllib's HTTP header layer rejects with a Latin-1
                # encoding error.  URL-encode the value so it survives
                # as a valid HTTP header.
                try:
                    raw_name: str = str(ctx["template_name"])
                    if all(32 <= ord(c) <= 126 for c in raw_name):
                        fwd_headers["X-Template-Name"] = raw_name
                    else:
                        fwd_headers["X-Template-Name"] = _url_encode_ascii(raw_name)
                except Exception:
                    pass
        fwd_headers["X-Deploy-Port"] = str(port)
        # ``X-Deploy-Route`` is the route prefix that served the page.
        # For static asset / page requests, the longest matching prefix on
        # the port is the answer.  For ``/_clone/*`` capture endpoints
        # (which the cloned JS fires AFTER loading the page) the prefix is
        # whatever template is currently registered on this port — use
        # any prefix that was registered for this port.
        match_prefix = ""
        for (p, prefix), info in _deployed.items():
            if p != port:
                continue
            req_path = request.url.path or "/"
            # Direct prefix match (page/asset requests)
            if req_path == prefix or req_path.startswith(prefix + "/"):
                if len(prefix) > len(match_prefix):
                    match_prefix = prefix
            # Capture-endpoint requests: pick the deepest registered prefix.
            elif req_path.startswith("/_clone/"):
                if len(prefix) > len(match_prefix):
                    match_prefix = prefix
        if match_prefix:
            fwd_headers["X-Deploy-Route"] = match_prefix
        # Run blocking urllib call in a threadpool so we don't block the event loop.
        import asyncio as _aio

        def _do_forward():
            req = urllib.request.Request(target, data=body or None, headers=fwd_headers, method=request.method)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                    resp_body = resp.read()
                    resp_headers = dict(resp.headers)
                    return resp_body, resp.status, resp_headers.get("Content-Type", "application/octet-stream"), resp_headers.get("Content-Disposition")
            except urllib.error.HTTPError as exc:
                try:
                    err_body = exc.read()
                except Exception:
                    err_body = b""
                return err_body, exc.code, "application/json", None
            except Exception as exc:
                import logging
                logging.getLogger("deployed_server").warning(
                    "Forward %s %s -> %s failed: %s", request.method, request.url.path, target, exc
                )
                return b'{"status":"error"}', 502, "application/json", None

        resp_body, status, ct, cd = await _aio.get_event_loop().run_in_executor(None, _do_forward)
        out = Response(content=resp_body, status_code=status, media_type=ct)
        if cd:
            out.headers["Content-Disposition"] = cd
        return out

    @app.get("/{path:path}")
    async def _catch_all(path: str):
        # Find the matching template
        for (p, prefix), info in _deployed.items():
            if p != port:
                continue
            request_path = f"/{path}" if path else "/"
            if request_path == prefix or request_path.startswith(prefix + "/"):
                return _serve(info, request_path, prefix)
        # Fallback: serve static assets from any deployed directory on this port
        # This handles the case where HTML references assets at the root (/asset-xxx.js)
        # while the template is deployed at a sub-route (e.g. /login).
        fallback = _serve_from_any_dir(port, f"/{path}")
        if fallback:
            return fallback
        return HTMLResponse(content="Not Found", status_code=404)

    @app.get("/")
    async def _root():
        for (p, prefix), info in _deployed.items():
            if p != port and prefix != "/":
                continue
            if p == port and prefix == "/":
                return _serve(info, "/", "/")
        return HTMLResponse(content="Not Found", status_code=404)

    return app


def _serve(info: dict, request_path: str, prefix: str) -> Response:
    dir_path: Path | None = info.get("dir_path")
    html_path: Path = info["html_path"]

    if dir_path:
        rel = request_path[len(prefix):].lstrip("/")
        if not rel or rel == "/":
            rel = "index.html"
        target = (dir_path / rel).resolve()
        if target.is_file() and str(dir_path.resolve()) in str(target):
            content_type = _guess_type(target.name)
            return Response(content=target.read_bytes(), media_type=content_type)
        # fallback to index.html
        return HTMLResponse(content=html_path.read_text(encoding="utf-8", errors="replace"))
    else:
        return HTMLResponse(content=html_path.read_text(encoding="utf-8", errors="replace"))


def _serve_from_any_dir(port: int, request_path: str) -> Response | None:
    """Try to serve *request_path* from any deployed template directory on *port*.

    This handles the case where a template is deployed at a sub-route (e.g. /login)
    but its HTML references assets at the root (e.g. /asset-0000-xxx.css).
    """
    for (p, _prefix), info in _deployed.items():
        if p != port:
            continue
        dir_path: Path | None = info.get("dir_path")
        if not dir_path:
            continue
        rel = request_path.lstrip("/")
        if not rel:
            continue
        target = (dir_path / rel).resolve()
        if target.is_file() and str(dir_path.resolve()) in str(target):
            content_type = _guess_type(target.name)
            return Response(content=target.read_bytes(), media_type=content_type)
    return None


def _guess_type(name: str) -> str:
    ext = Path(name).suffix.lower()
    return {
        ".css": "text/css",
        ".js": "application/javascript",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".svg": "image/svg+xml",
        ".webp": "image/webp",
        ".ico": "image/x-icon",
        ".woff": "font/woff",
        ".woff2": "font/woff2",
        ".json": "application/json",
        ".html": "text/html",
        ".htm": "text/html",
    }.get(ext, "application/octet-stream")


def _wait_port(port: int, timeout: float = 5.0) -> bool:
    """Probe the freshly started background server until it accepts TCP."""
    import socket
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _start_bg_server(port: int) -> bool:
    """Start a Uvicorn server on *port* in a daemon thread (if not already running).

    Returns True when the port actually accepts connections afterwards — a
    silent bind failure used to leave the deployment registered (and the UI
    reporting success) while nothing was listening.
    """
    port = _normalize_port(port)
    if port == MAIN_PORT:
        return False
    with _bg_lock:
        if port in _bg_servers:
            return True
        import uvicorn

        app = _build_app(port)
        config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="warning")
        server = uvicorn.Server(config)

        def _run():
            asyncio.run(server.serve())

        t = threading.Thread(target=_run, daemon=True, name=f"honeypot-port-{port}")
        t.start()
        _bg_servers[port] = (server, t)
    return _wait_port(port)


def _stop_bg_server(port: int) -> None:
    """Stop the background server on *port* if no templates remain."""
    port = _normalize_port(port)
    if port == MAIN_PORT:
        return
    remaining = sum(1 for (p, _) in _deployed if p == port)
    if remaining > 0:
        return
    with _bg_lock:
        entry = _bg_servers.pop(port, None)
        if entry:
            server, _ = entry
            server.should_exit = True


def register_deployed(
    port: int,
    route: str,
    artifact_path: str,
    *,
    template_id: int | None = None,
    node_id: int | None = None,
    template_name: str = "",
) -> bool:
    """Register a deployed template for serving.

    The optional ``template_id`` / ``node_id`` / ``template_name`` arguments are
    propagated into the in-memory registry so the per-port proxy can tag
    forwarded ``/_clone/*`` requests with deployment context (which lets the
    main app record ``template_id`` on the resulting ``Event`` row).

    Returns True when the artifact exists and the background server actually
    started accepting connections.
    """
    port = _normalize_port(port)
    route = _normalize_route(route)
    abs_path = (PROJECT_ROOT / artifact_path).resolve()
    if not abs_path.exists():
        return False

    if abs_path.is_dir():
        index = abs_path / "index.html"
        _deployed[(port, route)] = {
            "html_path": index if index.is_file() else abs_path,
            "dir_path": abs_path,
            "template_id": template_id,
            "node_id": node_id,
            "template_name": template_name,
        }
    elif abs_path.is_file():
        # If the file lives inside the cloned directory, serve the whole
        # directory so relative asset paths (CSS/JS/images) resolve correctly.
        parent = abs_path.parent
        if parent.name and (parent / "index.html").is_file():
            _deployed[(port, route)] = {
                "html_path": abs_path,
                "dir_path": parent,
                "template_id": template_id,
                "node_id": node_id,
                "template_name": template_name,
            }
        else:
            _deployed[(port, route)] = {
                "html_path": abs_path,
                "dir_path": None,
                "template_id": template_id,
                "node_id": node_id,
                "template_name": template_name,
            }
    else:
        return False

    return _start_bg_server(port)


def unregister_deployed(port: int, route: str) -> None:
    """Remove a deployed template."""
    port = _normalize_port(port)
    route = _normalize_route(route)
    _deployed.pop((port, route), None)
    _stop_bg_server(port)


def get_deployment_context(port: int, request_path: str = "/") -> dict | None:
    """Return deployment metadata for *port* + *request_path*.

    Used by the ``_proxy_clone`` handler so it can stamp ``X-Template-Id``
    and ``X-Node-Id`` on the forwarded request.  Falls back to the first
    deployment on the port if no prefix matches (sub-routes still register
    their template_id).
    """
    candidates: list[dict] = []
    for (p, _prefix), info in _deployed.items():
        if p != port:
            continue
        candidates.append(info)
    if not candidates:
        return None
    # Prefer the entry whose path actually matches, but always return
    # *some* context when the port has any deployment.
    return candidates[0]


def load_from_db() -> None:
    """Load all deployed web-app templates from the database at startup."""
    from app.core.db import SessionLocal
    from app.models.node import Node
    from sqlalchemy import select

    with SessionLocal() as db:
        nodes = db.scalars(select(Node)).all()
        for node in nodes:
            for entry in (node.deployed_services_json or []):
                if not isinstance(entry, dict):
                    continue
                if entry.get("type") != "web-app-honeypot":
                    continue
                artifact = entry.get("artifact_path", "")
                if not artifact:
                    continue
                port = _normalize_port(entry.get("deploy_port", MAIN_PORT))
                route = _normalize_route(entry.get("deploy_route", entry.get("entry_path", "/")))
                template_id = node.template_id
                node_id = node.id
                template_name = node.name
                register_deployed(
                    port,
                    route,
                    artifact,
                    template_id=template_id,
                    node_id=node_id,
                    template_name=template_name,
                )
