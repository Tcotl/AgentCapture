"""Web honeypot application factory.

Assembles the complete deception plane served on the dedicated honeypot
port (default 48777):

- the ThinkPHP 5.x emulation face (default landing page)
- every bait router: portal/poison-dataset/MCP/metadata/intranet/agent-file
  counter-offense faces, decoy traps, recon/collect channels
- the capture-and-inject middleware (full deception stack: session canary
  issuance, risk decisions, prompt injection, event persistence)
- the shared static assets (beacon.js / recon.js)

The console (4877) keeps only the management plane: admin console, open
API, C2 listener API and health. Bait faces referenced from console pages
should link to this honeypot origin instead.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.middleware.injector import CaptureAndInjectMiddleware

WEB_HONEYPOT_APP_TITLE = "AgentCapture Web Honeypot"


def create_web_honeypot_app() -> FastAPI:
    from app.routes.collect import router as collect_router
    from app.routes.counter_offense import router as counter_offense_router
    from app.routes.counter_recon import router as counter_recon_router
    from app.routes.traps import router as traps_router
    from app.services.honeypot_thinkphp import tp_router

    app = FastAPI(
        title=WEB_HONEYPOT_APP_TITLE,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    app.add_middleware(CaptureAndInjectMiddleware, observe_only_all=True)

    class FacadeHeadersMiddleware:
        """Pure-ASGI facade polish: hardened headers (no Server — uvicorn lowercases names, contradicting any claimed origin; security
        headers, Title-Case names — Starlette lowercases everything), and
        proper HEAD semantics (a 405 + `allow:` header is a framework tell)."""

        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope["type"] != "http":
                await self.app(scope, receive, send)
                return
            is_head = scope["method"] == "HEAD"
            if is_head:
                scope["method"] = "GET"

            async def send_wrapper(message):
                if message["type"] == "http.response.start":
                    hdrs = message["headers"]

                    def _set(name: bytes, value: bytes) -> None:
                        for i, (k, _) in enumerate(hdrs):
                            if k.lower() == name.lower():
                                hdrs[i] = (name, value)
                                return
                        hdrs.append((name, value))

                    def _has(name: bytes) -> bool:
                        return any(k.lower() == name.lower() for k, _ in hdrs)

                    if not _has(b"X-Content-Type-Options"):
                        hdrs.append((b"x-content-type-options", b"nosniff"))
                    if not _has(b"X-Frame-Options"):
                        hdrs.append((b"x-frame-options", b"SAMEORIGIN"))
                    if not _has(b"Referrer-Policy"):
                        hdrs.append((b"referrer-policy", b"strict-origin-when-cross-origin"))
                    if not _has(b"Content-Security-Policy"):
                        hdrs.append(
                            (b"content-security-policy",
                             b"default-src 'self'; script-src 'self' 'unsafe-inline'; "
                             b"style-src 'self' 'unsafe-inline'; img-src 'self' data:")
                        )
                    # nginx emits Title-Case names; Starlette lowercases — recase
                    hdrs[:] = [
                        (b"-".join(w.capitalize() for w in k.split(b"-")), v)
                        for (k, v) in hdrs
                    ]
                if is_head and message["type"] == "http.response.body":
                    message["body"] = b""
                await send(message)

            await self.app(scope, receive, send_wrapper)

    app.add_middleware(FacadeHeadersMiddleware)

    @app.exception_handler(RequestValidationError)
    async def _neutral_validation_error(request, exc):
        # FastAPI/Pydantic 422 bodies name the framework — a fingerprint tell
        # on a plane pretending to be ThinkPHP behind nginx.
        return JSONResponse({"error": "bad request"}, status_code=400)

    @app.get("/healthz")
    def healthz():
        # Deliberately generic — naming the face here fingerprinted the whole
        # plane in a single request.
        return {"status": "ok"}

    static_dir = Path(__file__).resolve().parents[1] / "static"
    # Mount /static BEFORE the routers: the ThinkPHP face registers a
    # catch-all /{path:path} and would otherwise shadow beacon.js/recon.js,
    # breaking browser-side telemetry on this plane.
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Bait routers first — the ThinkPHP face registers a catch-all
    # /{path:path} and must come LAST so it only serves paths no bait
    # router claimed (FastAPI matches routes in registration order).
    app.include_router(counter_recon_router)
    app.include_router(counter_offense_router)
    app.include_router(traps_router)
    app.include_router(collect_router)
    app.include_router(tp_router)

    return app
