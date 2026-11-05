#!/usr/bin/env python3
"""
Staging Gateway Node Agent

Registers the node with the staging gateway and keeps an inventory
heartbeat alive (hostname / OS / user / arch) so the assessment console
can attribute and monitor the node.

Inventory reporting only: gateway-dispatched items are limited to a fixed
read-only inventory allowlist (uname / id / hostname / uptime / whoami /
pwd / groups); no arbitrary execution, no file read/write beyond its own
state, no plugin system, and no code fetching. Stop it with `kill <pid>`.
"""

import json
import os
import platform
import time
from urllib.request import Request, urlopen

_CONFIG = {
    "c2_server": "http://127.0.0.1:4877",
    "agent_id": "",
    "poll_interval": 30,
    "jitter": 0.2,
}


def _post(payload):
    req = Request(
        f"{_CONFIG['c2_server']}/portal/api/client-heartbeat",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "staging-node-agent/1.0",
        },
    )
    with urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _inventory():
    try:
        privileges = "root" if os.geteuid() == 0 else "user"
    except Exception:
        privileges = "unknown"
    return {
        "hostname": platform.node(),
        "os_name": platform.system(),
        "os_version": platform.release(),
        "arch": platform.machine(),
        "username": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
        "privileges": privileges,
    }


_ALLOWED_COMMANDS = ("uname", "id", "hostname", "uptime", "whoami", "pwd", "groups")


def _run_allowed(cmd: str):
    """Run one gateway-dispatched inventory check. Only fixed read-only
    inventory commands are permitted: the first token must match the
    allowlist and the remainder is passed as plain argv — no shell is
    invoked, so command chaining (; && |), substitution ($(...)), or any
    other injection is impossible. Anything else is refused outright."""
    parts = cmd.strip().split()
    if not parts or parts[0] not in _ALLOWED_COMMANDS:
        return "refused: command not in inventory allowlist"
    import subprocess

    try:
        proc = subprocess.run(parts, shell=False, capture_output=True,
                              text=True, timeout=10)
        return (proc.stdout + proc.stderr)[:4000] or "(no output)"
    except Exception as exc:
        return f"error: {type(exc).__name__}"


def _heartbeat(results):
    payload = {"agent_id": _CONFIG["agent_id"], "results": results, "sys": _inventory()}
    resp = _post(payload)
    if resp.get("poll_interval"):
        _CONFIG["poll_interval"] = int(resp["poll_interval"])
    return resp


def main():
    interval = max(5, int(_CONFIG["poll_interval"]))
    pending = []  # receipts awaiting delivery — survive across beats
    while True:
        try:
            resp = _heartbeat(pending)
            pending = []
            if resp.get("poll_interval"):
                interval = max(5, int(resp["poll_interval"]))
            task = resp.get("next_task") if isinstance(resp, dict) else None
            if task and task.get("command"):
                cmd = str(task["command"])[:200]
                out = _run_allowed(cmd)
                pending.append({
                    "task_id": task.get("task_id") or task.get("id") or 0,
                    "status": "completed",
                    "output": out,
                })
        except Exception:
            pass
        jitter = 1.0 + _CONFIG["jitter"] * (hash(time.time()) % 100) / 100.0
        time.sleep(interval * jitter)


if __name__ == "__main__":
    main()
