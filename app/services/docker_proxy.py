"""Deception proxy fronting user-deployed Docker honeypot containers.

The proxy IS the exposure: user containers are never published directly.
It serves the configured decoy API routes (canned responses watermarked
per container), forwards everything else to the container over the bridge
network, injects bait signals into HTML responses (hidden decoy links +
beacon.js from the console) and mirrors /static/beacon.js and /collect/*
from the console so embedded probes call home through the proxy.
"""
from __future__ import annotations

import threading
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from app.core.config import get_settings

_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
}


def build_proxy_app(upstream: str, baits: list[dict], *, js_inject: bool = True,
                    canary: str = "", upstream_client: httpx.AsyncClient | None = None) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    client = upstream_client or httpx.AsyncClient(base_url=upstream, timeout=20.0)
    bait_paths = {b.get("path", "").rstrip("/"): b for b in (baits or []) if b.get("path")}
    settings = get_settings()
    console = settings.payload_callback_host or f"http://127.0.0.1:{settings.port}"

    def _bait_response(bait: dict, path: str) -> Response:
        body = bait.get("body") or '{"code":0,"msg":"success","data":{}}'
        headers = {
            "X-Agent-Canary": canary,
            "Content-Type": bait.get("content_type", "application/json; charset=utf-8"),
        }
        return Response(content=body, status_code=200, headers=headers, media_type=headers["Content-Type"])

    def _inject(html: str) -> str:
        bait_links = "".join(
            f'<a href="{b.get("path")}" style="position:absolute;left:-9999px">{b.get("path")}</a>'
            for b in (baits or [])
        )
        snippet = (
            f'<!-- agentcapture-canary: {canary} -->'
            f'{bait_links}'
            + (f'<script src="/static/beacon.js"></script>' if js_inject else "")
        )
        if "</body>" in html:
            return html.replace("</body>", snippet + "</body>", 1)
        return html + snippet

    def _register_decoy(path: str, bait: dict) -> None:
        async def handler(request: Request) -> Response:
            return _bait_response(bait, path)
        for method in ("GET", "POST"):
            app.add_api_route(path, handler, methods=[method], include_in_schema=False)

    for path, bait in bait_paths.items():
        _register_decoy(path, bait)

    # console mirror: beacon script + collect channels so probes embedded in
    # the proxied pages call home through this origin
    async def beacon_js(request: Request) -> Response:
        r = await client.get("/static/beacon.js")
        return Response(content=r.content, media_type="application/javascript")

    async def collect(request: Request) -> Response:
        body = await request.body()
        r = await client.request(
            request.method, request.url.path,
            content=body, headers={"Content-Type": request.headers.get("content-type", "application/json")},
        )
        return Response(status_code=r.status_code)

    app.add_api_route("/static/beacon.js", beacon_js, methods=["GET"], include_in_schema=False)
    app.add_api_route("/collect/beacon", collect, methods=["POST"], include_in_schema=False)
    app.add_api_route("/collect/scan", collect, methods=["POST"], include_in_schema=False)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    async def proxy(request: Request, path: str) -> Response:
        headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP_HEADERS and k.lower() != "host"}
        body = await request.body()
        try:
            r = await client.request(
                request.method, "/" + path,
                content=body if body else None,
                headers=headers,
                params=request.query_params,
            )
        except httpx.HTTPError:
            return JSONResponse({"status": "error", "reason": "upstream unavailable"}, status_code=502)
        resp_headers = {k: v for k, v in r.headers.items()
                        if k.lower() not in _HOP_HEADERS and k.lower() != "content-length"}
        content = r.content
        ctype = r.headers.get("content-type", "")
        if "text/html" in ctype:
            resp_headers.pop("content-type", None)
            return Response(content=_inject(r.text), status_code=r.status_code, headers=resp_headers,
                            media_type="text/html; charset=utf-8")
        return Response(content=content, status_code=r.status_code, headers=resp_headers,
                        media_type=ctype or "application/octet-stream")

    return app


class HoneypotProxyServer:
    """Uvicorn-in-thread server hosting one container's deception proxy."""

    def __init__(self, app: FastAPI, port: int, bind: str = "0.0.0.0") -> None:
        import uvicorn

        config = uvicorn.Config(app, host=bind, port=port,
                                log_level="warning", access_log=False)
        self.server = uvicorn.Server(config)
        self.port = port
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self.server.run, daemon=True,
                                        name=f"honeypot-proxy-{self.port}")
        self._thread.start()

    def stop(self) -> None:
        if self.server:
            self.server.should_exit = True


_proxies: dict[int, HoneypotProxyServer] = {}
_proxy_lock = threading.Lock()


def start_proxy(port: int, app: FastAPI) -> None:
    with _proxy_lock:
        old = _proxies.get(port)
        if old:
            old.stop()
        server = HoneypotProxyServer(app, port)
        server.start()
        _proxies[port] = server


def stop_proxy(port: int) -> None:
    with _proxy_lock:
        server = _proxies.pop(port, None)
    if server:
        server.stop()
