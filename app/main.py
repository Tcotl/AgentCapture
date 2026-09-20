import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.core.config import get_settings
from app.core.db import SessionLocal, init_db
from app.routes.admin import router as admin_router
from app.routes.agent_control import router as agent_control_router
from app.routes.c2 import router as c2_router
from app.routes.collect import router as collect_router
from app.routes.console import router as console_router
from app.routes.counter_recon import embedded_router as embedded_router
from app.routes.demo import router as demo_router
from app.routes.health import router as health_router
from app.routes.node_agent import router as node_agent_router
from app.routes.public_api import router as public_api_router
from app.services.seeds import seed_defaults
from app.services import deployed_server


# ---------------------------------------------------------------------------
# Fix Starlette's form parser default charset
# ---------------------------------------------------------------------------
# Starlette's FormParser hardcodes `latin-1` when decoding
# application/x-www-form-urlencoded bodies (see starlette/formparsers.py:113).
# Real browsers and CLI tools send UTF-8 without an explicit charset, so
# fields like Chinese web_stack ("OA 登录") get decoded as mojibake and
# stored as e.g. "OAç»å½".
# We monkey-patch the parser so the default charset is UTF-8 — both the
# default and any Content-Type-specified charset — while still respecting the
# charset declared by the request itself (e.g. "; charset=utf-8").
def _patch_starlette_form_parser_default_charset() -> None:
    from urllib.parse import unquote_plus

    from starlette import formparsers

    async def _patched_parse(self):  # type: ignore[no-untyped-def]
        from multipart.multipart import QuerystringParser

        callbacks = {
            "on_field_start": self.on_field_start,
            "on_field_name": self.on_field_name,
            "on_field_data": self.on_field_data,
            "on_field_end": self.on_field_end,
            "on_end": self.on_end,
        }
        parser = QuerystringParser(callbacks)
        field_name = bytearray()
        field_value = bytearray()
        items: list = []

        # Pick charset: prefer Content-Type charset, otherwise UTF-8 (was latin-1).
        charset = "utf-8"
        content_type = (self.headers.get("content-type") or "").lower()
        if "charset=" in content_type:
            try:
                charset = content_type.split("charset=", 1)[1].split(";", 1)[0].strip() or "utf-8"
            except Exception:
                charset = "utf-8"

        async for chunk in self.stream:
            if chunk:
                parser.write(chunk)
            else:
                parser.finalize()
            messages = list(self.messages)
            self.messages.clear()
            for message_type, message_bytes in messages:
                if message_type == formparsers.FormMessage.FIELD_START:
                    field_name = bytearray()
                    field_value = bytearray()
                elif message_type == formparsers.FormMessage.FIELD_NAME:
                    field_name.extend(message_bytes)
                elif message_type == formparsers.FormMessage.FIELD_DATA:
                    field_value.extend(message_bytes)
                elif message_type == formparsers.FormMessage.FIELD_END:
                    name = unquote_plus(field_name.decode(charset))
                    value = unquote_plus(field_value.decode(charset))
                    items.append((name, value))

        return formparsers.FormData(items)

    formparsers.FormParser.parse = _patched_parse


_patch_starlette_form_parser_default_charset()


settings = get_settings()
app = FastAPI(title=settings.app_name)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    session_cookie=settings.admin_session_cookie_name,
    same_site="lax",
    https_only=False,
)
# Console security path: serves /admin routes under the configured prefix
# (default /agentcapture/) and 404s the well-known /admin. Must sit inside
# SessionMiddleware (sessions are path-independent) but outside the routers.
from app.middleware.admin_path import AdminAccessPathMiddleware  # noqa: E402

app.add_middleware(AdminAccessPathMiddleware)
app.mount("/static", StaticFiles(directory=str(Path(__file__).resolve().parent / "static")), name="static")

# Serve cloned/uploaded web template assets so preview can resolve relative paths.
_cloned_root = Path(__file__).resolve().parents[1] / "data" / "web_app_templates" / "cloned"
_cloned_root.mkdir(parents=True, exist_ok=True)
app.mount("/_preview/cloned", StaticFiles(directory=str(_cloned_root)), name="preview-cloned")

app.include_router(health_router)
app.include_router(agent_control_router)
app.include_router(node_agent_router)
app.include_router(c2_router)
app.include_router(console_router)
# 嵌入式蜜罐 channels (collect beacon/scan, recon, agent echo, payload
# distribution): handlers gate on the embedded master switch — with the
# embedded honeypot disabled (deployment default) they answer 404.
app.include_router(embedded_router)
app.include_router(collect_router)
app.include_router(public_api_router)
app.include_router(admin_router)
app.include_router(demo_router)


@app.on_event("startup")
def on_startup() -> None:
    # Serverless targets (Vercel etc.): no long-running processes, no TCP
    # listeners, ephemeral filesystem — skip everything that needs a daemon
    # and keep only the web deception layer + console + APIs.
    serverless = (
        os.environ.get("VERCEL") == "1" or os.environ.get("SERVERLESS_MODE") == "1"
    )
    init_db()
    with SessionLocal() as db:
        seed_defaults(db)
    if serverless:
        import logging

        logging.getLogger("honeypot_services").info(
            "serverless mode: skipping deployed-server autoload, retention "
            "scheduler and protocol honeypot autostart"
        )
        return
    deployed_server.MAIN_PORT = settings.port
    deployed_server.load_from_db()
    # Retention: one startup pass + hourly daemon (see services/retention.py)
    from app.services.retention import run_retention, start_retention_scheduler

    try:
        with SessionLocal() as db:
            run_retention(db)
        if not serverless:
            start_retention_scheduler()
    except Exception:
        import logging

        logging.getLogger("retention").warning("startup retention pass failed", exc_info=True)
    # Start running honeypot services
    from app.services import honeypot_services
    from sqlalchemy import select
    from app.models.service import ServiceCatalog
    with SessionLocal() as db:
        services = db.scalars(
            select(ServiceCatalog).where(ServiceCatalog.status == "running")
        ).all()
        for svc in services:
            try:
                honeypot_services.start_service(svc.service_key, svc.default_port)
            except OSError as exc:
                import logging
                logging.getLogger("honeypot_services").warning(
                    "Skipped auto-start %s on :%d — %s", svc.service_key, svc.default_port, exc
                )
        # Reconcile DB status with the actual in-memory runtime after the
        # auto-start pass: anything still flagged running that did not bind,
        # and anything we managed to start that wasn't flagged, will be fixed.
        changed = honeypot_services.sync_services_status(db)
        if changed:
            logging.getLogger("honeypot_services").info(
                "Reconciled %d honeypot service status row(s) on startup", changed
            )
