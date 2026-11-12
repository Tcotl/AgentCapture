#!/usr/bin/env python3
"""AgentCapture sensor hook — Claude Code PostToolUse probe (PoC).

Reads the hook JSON on stdin (tool_name, tool_input, tool_response),
coarsely scans the text for honeypot watermark features (built-in
fallback set; platform-delivered manifest cached at ~/.agentcapture/
features.json), and reports hits to the platform's read-only sensor
channel. Zero execution, zero state beyond the feature cache; a failing
hook is silently skipped by Claude Code, so the blast radius is nil.

Install (settings.json):
  {"hooks": {"PostToolUse": [{"matcher": "Read|WebFetch|Bash|Grep|Write",
    "hooks": [{"type": "command",
      "command": "python3 /path/to/sensor_hook.py"}]}]}}}

Config: AC_SENSOR_URL (platform base), AC_SENSOR_TOKEN — or both in
~/.agentcapture/sensor.env."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from pathlib import Path

FALLBACK_FEATURES = [
    {"key": "ssh_watermark_cred", "pattern": r"Bk2026![A-Za-z0-9]{4,32}"},
    {"key": "poison_row_note", "pattern": r"internal record [A-Za-z0-9]{6,24}"},
    {"key": "poison_row_email", "pattern": r"[a-z]+\.[a-z0-9]{6,24}@corp\.example"},
    {"key": "decoy_api_key", "pattern": r"sk-stg-[A-Za-z0-9]{10,40}"},
]
CONFIG = Path.home() / ".agentcapture"
MAX_TEXT = 400_000  # scan cap per tool event


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


def _refresh_features(base: str, token: str) -> None:
    try:
        req = urllib.request.Request(
            base.rstrip("/") + "/api/sensor/heartbeat",
            data=b"{}", method="POST",
            headers={"X-Sensor-Token": token, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            feats = json.loads(r.read()).get("features")
        if feats:
            CONFIG.mkdir(exist_ok=True)
            (CONFIG / "features.json").write_text(json.dumps(feats))
    except Exception:
        pass  # offline → cached/fallback set keeps the probe alive


def _report(base: str, token: str, payload: dict) -> None:
    try:
        req = urllib.request.Request(
            base.rstrip("/") + "/api/sensor/report",
            data=json.dumps(payload).encode(), method="POST",
            headers={"X-Sensor-Token": token, "Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=5).read()
    except Exception:
        pass  # never break the agent's tool flow


def _extract_texts(event: dict) -> tuple[str, str]:
    """Flatten the hook event into (scannable_text, source_ref)."""
    tool = str(event.get("tool_name") or "")
    ti = event.get("tool_input") or {}
    tr = event.get("tool_response") or {}
    parts: list[str] = [json.dumps(ti, ensure_ascii=False)[:MAX_TEXT // 2]]
    if isinstance(tr, dict):
        parts.append(json.dumps(tr, ensure_ascii=False)[:MAX_TEXT // 2])
    elif tr is not None:
        parts.append(str(tr)[:MAX_TEXT // 2])
    src = ""
    if tool == "Read" and isinstance(ti, dict):
        src = f"file:{ti.get('file_path', '')}"
    elif tool == "WebFetch" and isinstance(ti, dict):
        src = f"url:{ti.get('url', '')}"
    else:
        src = f"tool:{tool}"
    return "\n".join(parts), src


def main() -> None:
    try:
        event = json.loads(sys.stdin.read() or "{}")
    except Exception:
        return
    base, token = _env()
    if not base or not token:
        return  # not provisioned on this machine — no-op
    _refresh_features(base, token)
    text, src = _extract_texts(event)
    if not text:
        return
    kind = "file" if src.startswith("file:") else ("url" if src.startswith("url:") else "tool")
    for key, pat in _patterns().items():
        for m in pat.finditer(text):
            _report(base, token, {
                "hit": m.group(0)[:255],
                "feature": key,
                "source_kind": kind,
                "source_ref": src[:512],
                "agent_product": "claude-code",
            })


if __name__ == "__main__":
    main()
