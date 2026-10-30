"""Vercel entrypoint for the AgentCapture web deception layer.

Serverless scope: capture/inject middleware, all bait surfaces (portal,
counter-offense faces, cloned-template serving), the admin console and the
open API. Protocol honeypots (SSH/MySQL/Redis/FTP/ES listeners) and cloned
web-app instances need long-running processes/TCP binds and belong on a
self-hosted node — see docs/integration.md §5.4-5.5.
"""
import os

# Vercel marker consumed by app.main startup guards (skips daemon threads,
# honeypot TCP autostart and deployed-server autoload).
os.environ["VERCEL"] = "1"

# Lambda filesystem is read-only except /tmp — default the SQLite database
# there unless the operator points DATABASE_URL at an external server.
os.environ.setdefault(
    "DATABASE_URL",
    "sqlite:////tmp/agent_capture.db",
)
# Demo environment default (vercel.com deployment): bootstrap admin uses
# Admin@123 unless the operator overrides it in project env vars.
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "Admin@123")
os.environ.setdefault("KNOWLEDGE_BASE_ROOT", "/tmp/knowledge_base")

import sys  # noqa: E402

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from starlette.requests import Request  # noqa: E402

from app.main import app  # noqa: E402

# ── TEMP diagnostics for the demo form-parse 400 (remove after fix) ──
import traceback  # noqa: E402

@app.get("/api/__diag")
def _diag():
    import importlib.util
    import sys
    def has(mod):
        try:
            return importlib.util.find_spec(mod) is not None
        except Exception as exc:
            return f"err:{exc}"
    def ver(mod):
        try:
            m = __import__(mod)
            return getattr(m, "__version__", "installed")
        except Exception as exc:
            return f"missing/{exc}"
    def real_form_parse():
        try:
            from multipart.multipart import parse_options_header
            result = parse_options_header(b"application/x-www-form-urlencoded")
            return "ok:" + repr(result)[:80]
        except Exception as exc:
            return "IMPORT/PARSE-ERR: " + repr(exc)
    return {
        "python": sys.version.split()[0],
        "real_form_parse": real_form_parse(),
        "starlette_ver": ver("starlette"),
        "fastapi_ver": ver("fastapi"),
        "multipart": has("multipart"),
        "python_multipart": has("python_multipart"),
    }

@app.post("/api/__formdiag")
async def _formdiag(request: Request):
    try:
        form = await request.form()
        return {"ok": True, "fields": dict(form)}
    except Exception as exc:
        return {"ok": False, "err": repr(exc),
                "tb": traceback.format_exc()[-1800:]}

@app.middleware("http")
async def _log_body_parse_err(request, call_next):
    try:
        return await call_next(request)
    except Exception as exc:
        detail = str(getattr(exc, "detail", "") or "")
        if "parsing the body" in detail:
            cause = exc.__cause__ or exc
            print("BODY-PARSE-ERR:", "".join(
                traceback.format_exception(type(cause), cause, cause.__traceback__)), flush=True)
        raise

# TEMP body-parse diagnostics
import traceback  # noqa: E402

@app.middleware("http")
async def _log_body_parse_err(request, call_next):  # noqa: E402
    try:
        return await call_next(request)
    except Exception as exc:  # noqa: E402
        detail = str(getattr(exc, "detail", "") or "")
        if "parsing the body" in detail:
            cause = exc.__cause__ or exc
            print("BODY-PARSE-ERR:", "".join(
                traceback.format_exception(type(cause), cause, cause.__traceback__)), flush=True)
        raise

# TEMP diagnostics (remove after verifying): report importable form backend
from app.core.config import get_settings as _gs  # noqa: E402

@app.get("/api/__diag")
def _diag():  # noqa: E402
    import importlib.util
    import sys
    def real_form_parse():
        try:
            from multipart.multipart import parse_options_header
            result = parse_options_header(b"application/x-www-form-urlencoded")
            return "ok:" + repr(result)[:80]
        except Exception as exc:
            return "IMPORT/PARSE-ERR: " + repr(exc)
    def real_starlette_form():
        try:
            from starlette.formparsers import FormParser
            return "FormParser-ok:" + repr(FormParser)
        except Exception as exc:
            return "IMPORT-ERR: " + repr(exc)
    return {
        "python": sys.version.split()[0],
        "real_form_parse": real_form_parse(),
        "real_starlette_form": real_starlette_form(),
        "app_loaded": True,
    }

# Vercel's Python runtime picks up an ASGI callable named `app`.
