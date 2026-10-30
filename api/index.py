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

from app.main import app  # noqa: E402

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
    return {
        "python": sys.version.split()[0],
        "multipart_import": has("multipart"),
        "python_multipart_import": has("python_multipart"),
        "multipart_ver": ver("multipart"),
        "python_multipart_ver": ver("python_multipart"),
        "starlette_ver": ver("starlette"),
        "fastapi_ver": ver("fastapi"),
    }

# Vercel's Python runtime picks up an ASGI callable named `app`.
