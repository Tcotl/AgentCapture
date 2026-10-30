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
    return {
        "python": sys.version.split()[0],
        "multipart": has("multipart"),
        "uvicorn": has("uvicorn"),
        "paramiko": has("paramiko"),
        "app_loaded": True,
    }

# Vercel's Python runtime picks up an ASGI callable named `app`.
