"""Console security access path middleware.

Serves the admin console under a configurable URL prefix (default
``/agentcapture/``) while answering the well-known ``/admin`` with 404, so
the console is not discoverable by scanners or drive-by visitors:

- Inbound: ``/{prefix}/...`` requests are rewritten internally to the
  ``/admin/...`` routes (all handlers, templates and auth logic stay
  unchanged — they keep speaking ``/admin``).
- Outbound: ``Location`` headers and admin HTML bodies are rewritten back
  to the configured prefix, so redirects, nav links and inline JS fetches
  work from the browser's point of view.
- Guard: direct hits on ``/admin`` / ``/api/admin`` return a bare 404 when
  the configured prefix differs (no hint that a console exists).
"""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.services.system_settings import get_admin_access_path

_API_MARK = "\x00API\x00"
_ADMIN_MARK = "\x00ADMIN\x00"


def rewrite_admin_html(body: str, prefix: str) -> str:
    """Point admin page URL references at the configured access prefix.

    Quote-anchored ('"/admin' or "'/admin") so path strings that merely
    mention admin (decoy file previews, docs) stay untouched unless they are
    actual URL references. Placeholder markers avoid re-matching freshly
    written output (e.g. a custom prefix that itself starts with "admin").
    """
    if prefix == "admin":
        return body
    out = body
    for quote in ('"', "'"):
        out = out.replace(quote + "/api/admin", quote + _API_MARK)
        out = out.replace(quote + "/admin", quote + _ADMIN_MARK)
    return out.replace(_API_MARK, f"/{prefix}/api/admin").replace(
        _ADMIN_MARK, f"/{prefix}/admin"
    )


def _guard_path(path: str) -> bool:
    return path == "/admin" or path.startswith(("/admin/", "/api/admin"))


class AdminAccessPathMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        prefix = get_admin_access_path()
        path = request.scope.get("path", "") or ""

        if prefix != "admin" and _guard_path(path):
            return Response("Not Found", status_code=404, media_type="text/plain")

        admin_bound = False
        new_path: str | None = None
        if path == f"/{prefix}" or path == f"/{prefix}/":
            # dashboard route is registered as /admin (no trailing slash)
            new_path = "/admin"
        elif path.startswith(f"/{prefix}/"):
            # the remainder IS the admin route path ("admin/...")
            new_path = "/" + path[len(prefix) + 2:]
        if new_path is not None:
            request.scope["path"] = new_path
            request.scope["raw_path"] = new_path.encode()
            admin_bound = True
        elif path == "/admin" or path.startswith("/admin/"):
            admin_bound = True

        response = await call_next(request)

        # Re-read after the handler ran: a request that itself changed the
        # access path (系统设置 form) must emit redirects/links to the NEW prefix.
        out_prefix = get_admin_access_path()

        location = response.headers.get("location")
        if location and out_prefix != "admin":
            # handle both relative ("/admin/login") and absolute Locations
            # (Starlette's redirect_slashes builds absolute URLs)
            parts = urlsplit(location)
            p = parts.path
            if p == "/admin" or p.startswith(("/admin/", "/api/admin")):
                response.headers["location"] = urlunsplit(
                    parts._replace(path=f"/{out_prefix}{p}")
                )

        if admin_bound and out_prefix != "admin":
            ctype = response.headers.get("content-type", "")
            if ctype.startswith("text/html"):
                chunks = [chunk async for chunk in response.body_iterator]
                body = rewrite_admin_html(b"".join(chunks).decode("utf-8", errors="replace"), out_prefix)
                headers = dict(response.headers)
                headers["content-length"] = str(len(body.encode("utf-8")))
                return Response(
                    content=body,
                    status_code=response.status_code,
                    headers=headers,
                    media_type=ctype,
                )
        return response
