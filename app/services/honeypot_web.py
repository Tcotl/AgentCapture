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

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "face": "honeypot"}

    # Bait routers first — the ThinkPHP face registers a catch-all
    # /{path:path} and must come LAST so it only serves paths no bait
    # router claimed (FastAPI matches routes in registration order).
    app.include_router(counter_recon_router)
    app.include_router(counter_offense_router)
    app.include_router(traps_router)
    app.include_router(collect_router)
    app.include_router(tp_router)

    static_dir = Path(__file__).resolve().parents[1] / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    return app
