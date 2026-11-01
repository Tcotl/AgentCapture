"""Reference distributed node agent for AgentCapture (method 5 onboarding).

Talks the HTTP contract from docs/integration.md §5.5/§6.3 using only the
Python standard library — download to any gateway/jump host in an intranet
segment with Python 3.9+ and run:

    sudo python3 node_agent.py --server http://ac.intra:4877 \\
        --name dc1-edge --token <NODE_AUTH_TOKEN> --apply

The node must be registered first in the console (节点管理 → 新增, same
name), otherwise heartbeats return 404.

Executed task types:
  honeypot-publish   apply iptables DNAT rules from payload.rules — forward
                     the segment's standard-port scan traffic (22/3306/6379/
                     21/9200…) to the AC honeypot ports. Queue tasks from the
                     console: 节点详情 → 蜜罐发布（多网段集中运营）.
  honeypot-retract   remove every DNAT rule carrying this agent's comment
                     marker from the segment gateway.
  sync-template / restart-services / rotate-decoys / collect-snapshot
                     platform placeholder types: acknowledged as done with a
                     note (no local action).

Safety rails: iptables changes are DRY-RUN by default — pass --apply to
enforce them; --allow-ports 22,3306 restricts which local ports may be
forwarded; every rule carries a comment marker so retraction only ever
touches this agent's own rules.
"""
import argparse
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

VERSION = "1.1-reference"

MARK = "agentcapture-node"  # iptables comment marker identifying our rules


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
        load1, load5, _load15 = os.getloadavg()
        return {"load1": round(load1, 2), "load5": round(load5, 2)}
    except (OSError, AttributeError):
        return {}


def _iptables(args: list[str], apply: bool) -> tuple[bool, str]:
    """Run an iptables -t nat command; dry-run just echoes it."""
    cmd = ["iptables", "-t", "nat", *args, "-m", "comment", "--comment", MARK]
    printable = " ".join(cmd)
    if not apply:
        print(f"[dry-run] {printable}")
        return True, printable
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
        ok = proc.returncode == 0
        detail = (proc.stdout or proc.stderr or "").strip()[:300]
        print(("ok  " if ok else "FAIL") + " " + printable + (" :: " + detail if detail else ""))
        return ok, detail or printable
    except Exception as exc:  # noqa: BLE001 — the agent must stay alive
        print(f"FAIL {printable} :: {exc}")
        return False, str(exc)[:300]

def _publish(payload: dict, fallback_host: str, allowed: set[int], apply: bool) -> tuple[bool, str]:
    import socket

    rules = payload.get("rules") or []
    target = payload.get("target_host") or fallback_host
    if not rules:
        return False, "no rules in payload"
    if target.startswith("<") and apply:
        # dry-run may print the placeholder so operators see the shape;
        # --apply must never run DNAT against a placeholder
        return False, "target_host placeholder not replaced (set AC intranet IP)"
    # iptables rejects hostnames ("Bad IP address") — resolve to an IP first
    try:
        target_ip = socket.gethostbyname(target)
    except OSError:
        target_ip = target
    ok_all, details = True, []
    for rule in rules:
        port = int(rule.get("node_port") or 0)
        if allowed and port not in allowed:
            ok_all = False
            details.append(f"port {port} not in --allow-ports, skipped")
            continue
        ok, detail = _iptables(
            ["-A", "PREROUTING", "-p", str(rule.get("proto") or "tcp"),
             "--dport", str(port), "-j", "DNAT",
             "--to-destination", f"{target_ip}:{rule.get('target_port')}"],
            apply=apply,
        )
        ok_all = ok_all and ok
        details.append(detail)
    return ok_all, " | ".join(details)


def _retract(apply: bool) -> tuple[bool, str]:
    # listing is read-only: plain -S without the comment matcher (_iptables
    # always appends -m comment, which -S rejects)
    proc = subprocess.run(
        ["iptables", "-t", "nat", "-S", "PREROUTING"],
        capture_output=True, text=True, timeout=15, check=False,
    )
    listing = (proc.stdout or proc.stderr or "").strip()
    all_rules = [ln for ln in listing.splitlines() if ln.startswith("-A ")]
    ours = [i + 1 for i, ln in enumerate(all_rules) if MARK in ln]
    if not ours:
        return True, "no agentcapture rules present"
    # delete by rule number, highest first so earlier indices stay valid
    # (nf_tables backends are picky about -D with a full rule spec)
    ok_all, details = True, []
    for num in sorted(ours, reverse=True):
        ok, detail = _iptables(["-D", "PREROUTING", str(num)], apply=apply)
        ok_all = ok_all and ok
        details.append(detail)
    return ok_all, " | ".join(details)


def handle_task(task: dict, opts: argparse.Namespace) -> tuple[str, dict]:
    """Execute one pulled task. Returns (status, result payload)."""
    ttype = task.get("task_type") or ""
    payload = task.get("payload") or {}
    allowed = opts.allowed_ports
    if ttype == "honeypot-publish":
        ok, detail = _publish(payload, opts.target_host, allowed, opts.apply)
        return ("done" if ok else "failed"), {"executed_by": "reference-agent", "detail": detail}
    if ttype == "honeypot-retract":
        ok, detail = _retract(opts.apply)
        return ("done" if ok else "failed"), {"executed_by": "reference-agent", "detail": detail}
    # platform placeholder types: no local action, acknowledge and move on
    return "done", {"executed_by": "reference-agent", "detail": f"{ttype}: no local action"}


def run(args: argparse.Namespace) -> None:
    stop = {"flag": False}

    def _stop(_sig, _frm):
        stop["flag"] = True

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    if not args.apply:
        print("dry-run mode: iptables commands are printed, not applied (pass --apply)")
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
            tasks = pulled.get("tasks") or ([pulled["task"]] if pulled.get("task") else [])
            for task in tasks:
                status, result = handle_task(task, args)
                ack = _post(args.server, "/api/node/tasks/ack", args.token, {
                    "node_name": args.name,
                    "task_id": task.get("id"),
                    "status": status,
                    "result": result,
                })
                print(f"[task #{task.get('id')}] {task.get('task_type')} -> {status} (ack {ack.get('task_status', 'ok')})")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")[:200]
            print(f"[error] HTTP {exc.code}: {body}", file=sys.stderr)
            if exc.code == 404:
                print("node not registered — create it in the console first", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001 — network blips: keep the loop alive
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
    ap.add_argument("--apply", action="store_true", help="really run iptables (default: dry-run)")
    ap.add_argument("--target-host", default="", help="AC intranet IP for DNAT targets (falls back to the task payload)")
    ap.add_argument("--allow-ports", default="", help="comma-separated local ports that may be forwarded, e.g. 22,3306")
    args = ap.parse_args()
    args.allowed_ports = {int(p) for p in args.allow_ports.split(",") if p.strip().isdigit()}
    run(args)


if __name__ == "__main__":
    main()
