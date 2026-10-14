"""Reference distributed node agent for AgentCapture (method 5 onboarding).

Talks the HTTP contract from docs/integration.md §5.5/§6.3 using only the
Python standard library — download to any node with Python 3.9+ and run:

    python3 node_agent.py --server http://ac.your.site:4877 \
        --name dc1-edge --token <NODE_AUTH_TOKEN>

The node must be registered first in the console (Node Management → add
node with the same name), otherwise heartbeats return 404.

Pulled tasks are printed and acknowledged as completed with a stub result —
replace the handle_task() body with real execution logic for your fleet.
"""
import argparse
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.request

VERSION = "1.0-reference"


def _post(base: str, path: str, token: str, payload: dict) -> dict:
    req = urllib.request.Request(
        base.rstrip("/") + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Node-Token": token},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8") or "{}")


def _metrics() -> dict:
    try:
        load1, load5, load15 = os.getloadavg()
        return {"load1": round(load1, 2), "load5": round(load5, 2)}
    except (OSError, AttributeError):
        return {}


def handle_task(task: dict) -> dict:
    """Replace with real execution. Return the task result payload."""
    print(f"[task #{task.get('id')}] {task.get('task_type')} -> stub execution")
    return {"executed_by": "reference-agent", "detail": "stub result"}


def run(args: argparse.Namespace) -> None:
    stop = {"flag": False}

    def _stop(_sig, _frm):
        stop["flag"] = True

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    print(f"node agent '{args.name}' -> {args.server} every {args.interval}s (Ctrl-C to stop)")
    while not stop["flag"]:
        try:
            hb = _post(args.server, "/api/node/heartbeat", args.token, {
                "node_name": args.name,
                "status": "online",
                "version": VERSION,
                "metrics": _metrics(),
            })
            print(f"[heartbeat] ok server_time={hb.get('server_time')}")

            pulled = _post(args.server, "/api/node/tasks/pull", args.token, {
                "node_name": args.name,
            })
            for task in pulled.get("tasks") or []:
                result = handle_task(task)
                ack = _post(args.server, "/api/node/tasks/ack", args.token, {
                    "node_name": args.name,
                    "task_id": task.get("id"),
                    "status": "completed",
                    "result": result,
                })
                print(f"[task #{task.get('id')}] ack -> {ack.get('task_status')}")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")[:200]
            print(f"[error] HTTP {exc.code}: {body}", file=sys.stderr)
            if exc.code == 404:
                print("node not registered — create it in the console first", file=sys.stderr)
        except Exception as exc:  # network blips: keep the loop alive
            print(f"[error] {exc}", file=sys.stderr)
        for _ in range(args.interval):
            if stop["flag"]:
                break
            time.sleep(1)
    print("node agent stopped")


def main() -> None:
    ap = argparse.ArgumentParser(description="AgentCapture reference node agent")
    ap.add_argument("--server", required=True, help="platform base URL, e.g. http://10.0.0.5:4877")
    ap.add_argument("--name", required=True, help="node name, must match the console registry")
    ap.add_argument("--token", required=True, help="NODE_AUTH_TOKEN configured on the platform")
    ap.add_argument("--interval", type=int, default=30, help="heartbeat interval seconds (default 30)")
    run(ap.parse_args())


if __name__ == "__main__":
    main()
