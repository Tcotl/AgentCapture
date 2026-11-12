"""Admin-plane MCP server (streamable-HTTP subset): POST /api/mcp.

Lets an operator's AI agent (Claude Code / ZCode / any MCP client) manage
the honeypot: initialize → tools/list → tools/call. Auth is the platform
API token (Authorization: Bearer or X-API-Key); read tools need
``mcp:read``, mutating tools ``mcp:write`` (or ``*``).

Responses are plain JSON-RPC over HTTP (no SSE stream) — a legal
streamable-HTTP mode that every mainstream client accepts."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.services.api_tokens import api_token_has_permission, resolve_api_token
from app.services.mcp_admin_tools import call_tool, tools_for_permission

router = APIRouter(prefix="/api/mcp", tags=["mcp-admin"])

PROTO = "2024-11-05"
SERVER_INFO = {"name": "agentcapture-admin", "version": "0.1.0"}


def _token_from(request: Request) -> str | None:
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.headers.get("x-api-key")


def _rpc(req_id, result) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": result})


def _rpc_err(req_id, code: int, message: str, http: int = 200) -> JSONResponse:
    return JSONResponse(
        {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}},
        status_code=http,
    )


@router.post("")
@router.post("/")
async def mcp_admin_entry(request: Request, db: Session = Depends(get_db)):
    try:
        body = await request.json()
    except Exception:
        return _rpc_err(None, -32700, "parse error", 400)
    if not isinstance(body, dict):
        return _rpc_err(None, -32600, "invalid request", 400)
    method = body.get("method") or ""
    req_id = body.get("id")

    # notifications (no id) — acknowledge silently
    if req_id is None:
        return Response(status_code=202)

    if method == "initialize":
        return _rpc(req_id, {
            "protocolVersion": PROTO,
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        })

    # everything below requires a token
    token = resolve_api_token(db, _token_from(request))
    if token is None:
        return _rpc_err(req_id, -32001, "unauthorized: supply a platform API token (Authorization: Bearer / X-API-Key)", 401)
    can_read = api_token_has_permission(token, "mcp:read")
    can_write = api_token_has_permission(token, "mcp:write")
    if not can_read and not can_write:
        return _rpc_err(req_id, -32001, "token lacks mcp:read / mcp:write permission", 403)

    if method == "tools/list":
        return _rpc(req_id, {"tools": tools_for_permission(can_write)})

    if method == "tools/call":
        params = body.get("params") or {}
        name = str(params.get("name") or "")
        args = params.get("arguments") or {}
        from app.services.mcp_admin_tools import WRITE_TOOLS

        if name in WRITE_TOOLS and not can_write:
            return _rpc(req_id, {"content": [{"type": "text", "text": "token lacks mcp:write permission"}], "isError": True})
        try:
            result = call_tool(db, name, args if isinstance(args, dict) else {}, actor=f"mcp:{token.name}")
        except Exception as exc:  # one bad call never kills the server
            return _rpc(req_id, {"content": [{"type": "text", "text": f"error: {type(exc).__name__}: {exc}"}], "isError": True})
        return _rpc(req_id, {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, default=str)}], "isError": False})

    return _rpc_err(req_id, -32601, f"method not found: {method}")
