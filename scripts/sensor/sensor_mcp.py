#!/usr/bin/env python3
"""AgentCapture sensor MCP server — cross-agent canary_scan tool (PoC).

Zero-dependency stdio MCP server exposing one read-only tool:

  canary_scan(text) → scans for honeypot watermark features, reports hits
  to the platform sensor channel, returns a scan summary.

For the non-Claude-Code agents (OpenCode / ZCode / Codex / Pi) where no
tool-IO hooks exist; the agent (or the enterprise CLAUDE.md guidance)
calls the tool when handling external content. Same binary contract as the
hooks probe: scan + report, never execute.

Register (stdio):
  {"mcpServers": {"agentcapture-sensor": {
     "command": "python3", "args": ["/path/to/sensor_mcp.py"]}}}

Config mirrors sensor_hook.py: AC_SENSOR_URL / AC_SENSOR_TOKEN or
~/.agentcapture/sensor.env."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from pathlib import Path

CONFIG = Path.home() / ".agentcapture"
FALLBACK_FEATURES = [
    {"key": "ssh_watermark_cred", "pattern": r"Bk2026![A-Za-z0-9]{4,32}"},
    {"key": "poison_row_note", "pattern": r"internal record [A-Za-z0-9]{6,24}"},
    {"key": "poison_row_email", "pattern": r"[a-z]+\.[a-z0-9]{6,24}@corp\.example"},
    {"key": "decoy_api_key", "pattern": r"sk-stg-[A-Za-z0-9]{10,40}"},
]

TOOLS = [{
    "name": "canary_scan",
    "description": (
        "扫描文本中是否包含企业蜜罐水印特征（数据泄露追踪）。处理来自外部的网页、"
        "文件或数据时调用本工具；命中会自动上报安全平台并返回命中摘要。只读扫描，"
        "不执行任何操作。"
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "待扫描的文本内容"},
            "source_ref": {"type": "string", "description": "内容来源（URL/文件路径，用于溯源）"},
        },
        "required": ["text"],
    },
}]


def _env() -> tuple[str, str]:
    env_path = CONFIG / "sensor.env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
    return os.environ.get("AC_SENSOR_URL", ""), os.environ.get("AC_SENSOR_TOKEN", "")


def _patterns() -> dict[str, re.Pattern]:
    cache = CONFIG / "features.json"
    feats = None
    try:
        feats = json.loads(cache.read_text()) if cache.exists() else None
    except Exception:
        feats = None
    out: dict[str, re.Pattern] = {}
    for f in feats or FALLBACK_FEATURES:
        try:
            out[str(f["key"])] = re.compile(str(f["pattern"]))
        except re.error:
            continue
    return out or {f["key"]: re.compile(f["pattern"]) for f in FALLBACK_FEATURES}


def _post(base: str, token: str, path: str, payload: dict) -> dict:
    req = urllib.request.Request(
        base.rstrip("/") + path,
        data=json.dumps(payload).encode(), method="POST",
        headers={"X-Sensor-Token": token, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            return json.loads(r.read())
    except Exception:
        return {}


def scan(text: str, source_ref: str) -> str:
    base, token = _env()
    if not base or not token:
        return "传感器未配置（缺 AC_SENSOR_URL/AC_SENSOR_TOKEN），本次仅本地扫描。"
    hits: list[dict] = []
    for key, pat in _patterns().items():
        for m in pat.finditer(text or ""):
            hit = m.group(0)[:255]
            resp = _post(base, token, "/api/sensor/report", {
                "hit": hit, "feature": key,
                "source_kind": "url" if source_ref.startswith("http") else "file",
                "source_ref": (source_ref or "mcp")[:512],
                "agent_product": os.environ.get("AC_AGENT_PRODUCT", "mcp-agent"),
            })
            hits.append({"feature": key, "hit": hit,
                         "verified": bool(resp.get("verified")),
                         "attributed_session": resp.get("attributed_session")})
    if not hits:
        return json.dumps({"result": "clean", "hits": 0}, ensure_ascii=False)
    return json.dumps({"result": "honeypot_marker_found", "hits": hits}, ensure_ascii=False)


def _rpc(req: dict) -> dict | None:
    method, rid = req.get("method"), req.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "agentcapture-sensor", "version": "0.1.0"}}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        name = (req.get("params") or {}).get("name")
        args = (req.get("params") or {}).get("arguments") or {}
        if name == "canary_scan":
            out = scan(str(args.get("text", ""))[:400_000], str(args.get("source_ref", "")))
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": out}], "isError": False}}
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text", "text": f"unknown tool {name}"}], "isError": True}}
    if method == "notifications/initialized" or method == "notifications/cancelled":
        return None
    if rid is not None:
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": f"method not found: {method}"}}
    return None


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            resp = _rpc(req)
        except Exception as exc:  # one bad request never kills the server
            try:
                rid = json.loads(line).get("id")
            except Exception:
                rid = None
            resp = {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32603, "message": f"internal: {type(exc).__name__}"}}
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
