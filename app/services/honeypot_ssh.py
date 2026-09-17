"""Paramiko-based interactive SSH honeypot.

Full SSH-2.0 transport: real key exchange, password authentication (accept-all
so attackers are never locked out), an interactive PTY shell backed by the
deceptive filesystem (:mod:`app.services.honeypot_shell`), single-shot exec
channels, and a read-only SFTP subsystem.

Everything the attacker does is captured:
- every auth attempt → ``ssh_auth`` Event + CredentialObservation
- session establish/close → ``honeypot_sessions`` row (HoneypotSession)
- every typed command + its output → session transcript + ``ssh_command`` Event

Requires ``paramiko``; when it is missing the ssh service falls back to the
legacy banner-level handler in :mod:`app.services.honeypot_services`.
"""

from __future__ import annotations

import logging
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import get_settings

logger = logging.getLogger("honeypot_ssh")

try:
    import paramiko

    class _ScannerNoiseFilter(logging.Filter):
        """Drop paramiko's ERROR-level tracebacks for pre-banner probe noise.

        Port scanners and low-quality clients constantly open connections and
        disappear before the SSH banner exchange; paramiko's transport thread
        logs a full traceback for each. That is expected background noise for
        a honeypot, not a fault — keep everything else.
        """

        _NOISE = (
            "Error reading SSH protocol banner",
            "EOF when attempting to read the banner",
            "Connection reset by peer",
            "Socket exception",
        )

        def filter(self, record: logging.LogRecord) -> bool:
            try:
                return not any(n in record.getMessage() for n in self._NOISE)
            except Exception:
                return True

    logging.getLogger("paramiko").addFilter(_ScannerNoiseFilter())
except ImportError:  # pragma: no cover - exercised only without the extra
    paramiko = None

SSH_AVAILABLE = paramiko is not None

# Transcript protection: cap entries and per-entry size so a session cannot
# inflate the database (the retention service bounds lifetime, this bounds
# size per row).
MAX_TRANSCRIPT_ENTRIES = 600
MAX_ENTRY_CHARS = 8000
WELCOME_BANNER = "Ubuntu 22.04.4 LTS"


def host_key_path() -> Path:
    settings = get_settings()
    return Path(settings.knowledge_base_root).resolve().parent / "ssh_host_key"


def load_or_generate_host_key():
    """RSA host key persisted next to the knowledge base so the server
    fingerprint stays stable across restarts (avoid the tell-tale
    'host key changed' warning for repeat visitors)."""
    if paramiko is None:
        return None
    path = host_key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            return paramiko.RSAKey(filename=str(path))
        except Exception:
            logger.warning("could not load ssh host key, regenerating", exc_info=True)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(path))
    logger.info("generated new SSH host key at %s", path)
    return key


def _append_transcript(entries: list[dict], entry: dict) -> list[dict]:
    """Pure helper: append an entry honouring the transcript caps."""
    entry = dict(entry)
    for field_name in ("cmd", "out"):
        value = entry.get(field_name)
        if isinstance(value, str) and len(value) > MAX_ENTRY_CHARS:
            entry[field_name] = value[:MAX_ENTRY_CHARS] + f"\n… [truncated {len(value)} chars]"
    entries.append(entry)
    excess = len(entries) - MAX_TRANSCRIPT_ENTRIES
    if excess > 0:
        entries = entries[excess:]
        entry["note"] = "transcript head truncated"
    return entries


# ---------------------------------------------------------------------------
# persistence helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _session_create(session_id: str, source_ip: str, port: int, *,
                    username: str = "", password: str = "",
                    auth_attempts: int = 0,
                    transcript_entries: list[dict] | None = None) -> int:
    from app.models.honeypot_session import HoneypotSession
    from app.core.db import SessionLocal

    with SessionLocal() as db:
        row = HoneypotSession(
            session_id=session_id[:64],
            service="ssh",
            source_ip=source_ip,
            port=port,
            status="active",
            username=(username or "")[:64],
            password=(password or "")[:256],
            auth_attempts=auth_attempts,
            command_count=0,
            started_at=_now(),
            transcript_json=_append_transcript(list(transcript_entries or []), {"ts": _now().isoformat(), "kind": "session_open"}),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row.id


def _session_update(session_pk: int, *, username: str | None = None,
                    password: str | None = None, auth_attempt: bool = False,
                    command_count_delta: int = 0, transcript_entry: dict | None = None,
                    ended: bool = False) -> None:
    from app.models.honeypot_session import HoneypotSession
    from app.core.db import SessionLocal

    with SessionLocal() as db:
        row = db.get(HoneypotSession, session_pk)
        if row is None:
            return
        if username is not None:
            row.username = username[:64]
        if password is not None:
            row.password = password[:256]
        if auth_attempt:
            row.auth_attempts = (row.auth_attempts or 0) + 1
        row.command_count = (row.command_count or 0) + command_count_delta
        if transcript_entry is not None:
            row.transcript_json = _append_transcript(list(row.transcript_json or []), transcript_entry)
        if ended:
            row.status = "closed"
            row.ended_at = _now()
        db.add(row)
        db.commit()


def _log_event(event_type: str, source_ip: str, session_id: str, payload: dict,
               risk_score: int, *, credential: dict | None = None, alert: bool = False) -> None:
    from app.core.db import SessionLocal
    from app.services.events import create_credential_observation, create_event

    try:
        with SessionLocal() as db:
            create_event(
                db,
                site_id="honeypot",
                session_id=session_id[:64],
                source_ip=source_ip,
                method="SSH",
                path="/ssh:22",
                status_code=0,
                event_type=event_type,
                user_agent="",
                headers_json={},
                payload_json=payload,
                signals_json=["honeypot-service", event_type],
                risk_score=risk_score,
                decision="observe",
            )
            if credential and (credential.get("username") or credential.get("password")):
                create_credential_observation(
                    db,
                    source_ip=source_ip,
                    node_name="honeypot-node",
                    service_name="ssh",
                    username=str(credential.get("username", ""))[:128],
                    password=str(credential.get("password", ""))[:256],
                    path="/ssh:22",
                    session_id=session_id[:64],
                    source_label="protocol-honeypot",
                )
            if alert:
                from app.services.alert_dispatcher import AlertPayload, get_alert_dispatcher

                get_alert_dispatcher().start_event(AlertPayload(
                    event_type=event_type,
                    source_ip=source_ip,
                    decision="observe",
                    risk_score=risk_score,
                    signals=["honeypot-service"],
                    path="/ssh:22",
                    method="SSH",
                    summary=f"honeypot {event_type}: ssh session from {source_ip}",
                    timestamp=_now(),
                ))
    except Exception as exc:
        logger.warning("ssh honeypot event log failed (%s): %s", event_type, exc)


# ---------------------------------------------------------------------------
# paramiko server interface
# ---------------------------------------------------------------------------

if SSH_AVAILABLE:

    class _ServerInterface(paramiko.ServerInterface):
        def __init__(self, conn: "_ConnectionState"):
            self.conn = conn

        # -- auth ------------------------------------------------------
        def get_allowed_auths(self, username):
            return "password,publickey"

        def check_auth_none(self, username):
            self.conn.record_auth(username, "", method="none", accepted=False)
            return paramiko.AUTH_FAILED

        def check_auth_publickey(self, username, key):
            fingerprint = key.get_fingerprint().hex() if key else ""
            self.conn.record_auth(username, f"pubkey:{fingerprint[:32]}", method="publickey", accepted=False)
            return paramiko.AUTH_FAILED

        def check_auth_password(self, username, password):
            settings = get_settings()
            accepted = bool(settings.ssh_accept_all) and bool(username)
            self.conn.record_auth(username, password or "", method="password", accepted=accepted)
            if accepted:
                self.conn.username = username
                self.conn.authenticated.set()
                return paramiko.AUTH_SUCCESSFUL
            return paramiko.AUTH_FAILED

        # -- channels ---------------------------------------------------
        def check_channel_request(self, kind, chanid):
            if kind == "session":
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_channel_pty_request(self, channel, term, width, height,
                                      pixelwidth, pixelheight, modes):
            self.conn.term = term or "xterm"
            return True

        def check_channel_shell_request(self, channel):
            self.conn.set_channel_intent(channel, "shell")
            return True

        def check_channel_exec_request(self, channel, command):
            # Only record the intent here; the per-channel service thread
            # (which owns the channel reference) performs the work.
            if isinstance(command, (list, tuple)):
                command = " ".join(command)
            command = (
                command.decode("utf-8", errors="replace")
                if isinstance(command, bytes) else str(command)
            )
            self.conn.set_channel_intent(channel, "exec", command)
            return True

        # NOTE: SFTP is wired via transport.set_subsystem_handler (see
        # _handle_connection) — the paramiko-5-recommended mechanism.


if SSH_AVAILABLE:

    class _HoneypotSftpServer(paramiko.SFTPServer):
        """SFTP subsystem wrapper: records the channel intent so the per-
        channel service thread knows to simply hold the channel open."""

        def __init__(self, channel, name, server, *args, **kwargs):
            server.conn.set_channel_intent(channel, "subsystem")
            super().__init__(channel, name, server, sftp_si=_SftpInterface)


class _ConnectionState:
    """Per-connection state shared between paramiko callbacks and handlers."""

    def __init__(self, server: "SshHoneypotServer", addr):
        self.server = server
        self.addr = addr
        self.source_ip = addr[0] if addr else "unknown"
        self.username = ""
        self.session_id = f"ssh:{self.source_ip}:{datetime.now(timezone.utc).strftime('%H%M%S')}"
        self.session_pk: int | None = None
        self.term = "xterm"
        # pre-auth bookkeeping: flushed into the row once auth succeeds and
        # the session row exists
        self.pending_transcript: list[dict] = []
        self.last_username = ""
        self.last_password = ""
        self.auth_count = 0
        self._sftp_shell = None
        # per-channel intents: chanid -> "shell" | "exec" | "subsystem"
        # (registered by paramiko callback threads, consumed by the
        # per-channel service threads)
        self._intents: dict[int, tuple[str, str]] = {}
        self._intents_lock = threading.Lock()
        self.authenticated = threading.Event()

    def set_channel_intent(self, channel, kind: str, command: str = "") -> None:
        with self._intents_lock:
            self._intents[channel.get_id()] = (kind, command)

    def get_channel_intent(self, channel, timeout: float = 10.0):
        """Wait for the client to announce what this channel is for."""
        import time

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not channel.closed:
            with self._intents_lock:
                intent = self._intents.pop(channel.get_id(), None)
            if intent:
                return intent
            time.sleep(0.05)
        return ("shell", "")

    # -- auth bookkeeping ------------------------------------------
    def record_auth(self, username: str, secret: str, *, method: str, accepted: bool) -> None:
        self.auth_count += 1
        if username:
            self.last_username = username
        if method == "password" and secret:
            self.last_password = secret
        self.server.auth_attempts += 1
        _log_event(
            "ssh_auth",
            self.source_ip,
            self.session_id,
            {"auth_method": method, "username": username, "accepted": accepted},
            risk_score=90,
            credential={"username": username, "password": secret} if method == "password" else None,
        )
        self.pending_transcript.append({
            "ts": _now().isoformat(),
            "kind": "auth",
            "method": method,
            "user": username,
            "accepted": accepted,
        })
        if len(self.pending_transcript) > MAX_TRANSCRIPT_ENTRIES:
            self.pending_transcript = self.pending_transcript[-MAX_TRANSCRIPT_ENTRIES:]

    def flush_session_row(self) -> int:
        """Create the HoneypotSession row after successful auth."""
        self.session_pk = _session_create(
            self.session_id,
            self.source_ip,
            self.server.port,
            username=self.last_username,
            password=self.last_password,
            auth_attempts=self.auth_count,
            transcript_entries=self.pending_transcript,
        )
        self.pending_transcript = []
        return self.session_pk

    # -- exec channel ----------------------------------------------
    def run_exec(self, channel, command) -> None:
        if isinstance(command, (list, tuple)):
            command = " ".join(command)
        command = command.decode("utf-8", errors="replace") if isinstance(command, bytes) else command
        shell = self.shared_shell()
        output = ""
        try:
            output = shell.run(command) or ""
            channel.sendall(output.encode("utf-8") + b"\n")
            channel.send_exit_status(0)
        except Exception as exc:
            logger.debug("exec handler failed: %s", exc)
            channel.send_exit_status(1)
        finally:
            try:
                channel.close()
            except Exception:
                pass
            self.record_command(command, output)


    def record_command(self, command: str, output: str) -> None:
        _log_event(
            "ssh_command",
            self.source_ip,
            self.session_id,
            {"command": command[:500], "output_len": len(output or "")},
            risk_score=85,
        )
        _session_update(
            self.session_pk or 0,
            command_count_delta=1,
            transcript_entry={
                "ts": _now().isoformat(),
                "kind": "command",
                "user": self.username or "root",
                "cmd": command,
                "out": output or "",
            },
        )

    # -- shared fake-machine state ---------------------------------
    def shared_shell(self):
        """One ShellSession per connection so all channels (shell, exec,
        SFTP) see the same fake machine: a file written in the interactive
        shell is visible to a later exec/SFTP, exactly like a real host."""
        from app.services.honeypot_shell import ShellSession

        if self._sftp_shell is None:
            self._sftp_shell = ShellSession(
                self.session_id, self.source_ip, self.username or "root"
            )
        return self._sftp_shell


if SSH_AVAILABLE:

    class _SftpInterface(paramiko.SFTPServerInterface):
        """Read-only SFTP over the deceptive filesystem."""

        def __init__(self, server_interface):
            super().__init__(server_interface)
            self.conn: _ConnectionState = server_interface.conn

        def _node(self, path: str):
            from app.services import honeypot_fs

            shell = self.conn.shared_shell()
            return honeypot_fs.resolve_node(shell.fs, "/", path or "/", shell.home), shell

        def _attrs(self, node, ctx):
            from paramiko.sftp_attr import SFTPAttributes

            attrs = SFTPAttributes()
            attrs.st_size = node.current_size(ctx)
            attrs.st_mode = (0o040755 if node.kind == "dir" else 0o100644)
            attrs.st_uid = 0 if node.owner == "root" else 1000
            attrs.st_gid = attrs.st_uid
            attrs.st_atime = int(datetime.now(timezone.utc).timestamp())
            attrs.st_mtime = attrs.st_atime
            return attrs

        def stat(self, path):
            node, shell = self._node(path)
            if node is None:
                return paramiko.SFTP_NO_SUCH_FILE
            return self._attrs(node, shell.ctx)

        def lstat(self, path):
            return self.stat(path)

        def list_folder(self, path):
            node, shell = self._node(path)
            if node is None:
                return paramiko.SFTP_NO_SUCH_FILE
            if node.kind != "dir":
                return paramiko.SFTP_OP_UNSUPPORTED
            entries = []
            for name, child in sorted(node.children.items()):
                attr = self._attrs(child, shell.ctx)
                attr.filename = name
                entries.append(attr)
            return entries

        def open(self, path, flags, attr):
            # deny all write-ish modes (SFTP_FLAG_WRITE = 0x2, CREAT 0x8 etc.)
            if flags & (0x2 | 0x8 | 0x10 | 0x20):
                return paramiko.SFTP_PERMISSION_DENIED
            node, shell = self._node(path)
            if node is None or node.kind != "file":
                return paramiko.SFTP_NO_SUCH_FILE
            return _SftpFile(node, shell.ctx)


    class _SftpFile(paramiko.SFTPHandle):
        def __init__(self, node, ctx):
            super().__init__(flags=0)
            self.node = node
            self.ctx = ctx

        def read(self, offset, length):
            data = self.node.text(self.ctx).encode("utf-8", errors="replace")
            return data[offset:offset + length]

        def write(self, offset, data):
            return paramiko.SFTP_PERMISSION_DENIED

        def stat(self):
            from paramiko.sftp_attr import SFTPAttributes

            attrs = SFTPAttributes()
            attrs.st_size = len(self.node.text(self.ctx).encode("utf-8", errors="replace"))
            attrs.st_mode = 0o100644
            return attrs


# ---------------------------------------------------------------------------
# connection handling + server loop
# ---------------------------------------------------------------------------


def _handle_connection(server: "SshHoneypotServer", sock: socket.socket, addr) -> None:

    conn = _ConnectionState(server, addr)
    try:
        sock.settimeout(30)
        transport = paramiko.Transport(sock)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        transport.add_server_key(server.host_key)
        transport.set_subsystem_handler("sftp", _HoneypotSftpServer)
        transport.start_server(server=_ServerInterface(conn))
    except Exception as exc:
        logger.debug("ssh handshake failed from %s: %s", conn.source_ip, exc)
        try:
            sock.close()
        except Exception:
            pass
        return

    # Wait for the client to authenticate (the transport thread runs the auth
    # callbacks); without this gate we would close on still-anonymous clients.
    if not conn.authenticated.wait(30):
        try:
            transport.close()
        except Exception:
            pass
        return

    conn.flush_session_row()
    _log_event(
        "ssh_session",
        conn.source_ip,
        conn.session_id,
        {"username": conn.username, "authenticated": True},
        risk_score=95,
        alert=True,
    )

    import time as _time

    try:
        while transport.is_active() and not server._stopping.is_set():
            channel = transport.accept(2)
            if channel is None:
                continue
            if channel.closed:
                continue
            threading.Thread(
                target=_serve_channel, args=(conn, channel),
                daemon=True, name="ssh-honeypot-channel",
            ).start()
        # drain: wait briefly for channel threads to finish their writes
        _time.sleep(0.2)
    finally:
        _session_update(conn.session_pk, ended=True)
        try:
            transport.close()
        except Exception:
            pass


def _serve_channel(conn: _ConnectionState, channel) -> None:
    """Dispatch one opened channel according to the intent its client announced."""
    kind, command = conn.get_channel_intent(channel)
    try:
        if kind == "exec":
            conn.run_exec(channel, command)
        elif kind == "subsystem":
            # SFTP runs inside paramiko's own thread; just hold it open
            _wait_channel_close(channel, timeout=600)
        else:
            _interactive_shell(conn, conn.shared_shell(), channel)
    finally:
        try:
            channel.close()
        except Exception:
            pass


def _wait_channel_close(channel, timeout: float) -> None:
    import time

    deadline = time.monotonic() + timeout
    while not channel.closed and time.monotonic() < deadline:
        time.sleep(0.2)


def _interactive_shell(conn: _ConnectionState, shell_session, channel) -> None:
    """Minimal but believable interactive line shell.

    Handles: local line editing (backspace, Ctrl-C, Ctrl-D), up/down history
    recall, and a per-user prompt. The client does its own local echo (PTY
    mode), so the server only writes after a line is submitted.
    """
    prompt = shell_session.prompt
    try:
        channel.sendall(shell_session.motd().encode("utf-8"))
        channel.sendall(prompt.encode("utf-8"))
    except Exception:
        return

    buffer = ""
    history_idx: int | None = None
    while True:
        try:
            data = channel.recv(4096)
        except Exception:
            break
        if not data:
            break

        i = 0
        while i < len(data):
            byte = data[i:i + 1]
            i += 1
            if byte in (b"\r", b"\n"):
                line = buffer
                buffer = ""
                history_idx = None
                channel.sendall(b"\r\n")
                if line.strip():
                    output = shell_session.run(line)
                    conn.record_command(line, output)
                    if output:
                        channel.sendall(output.encode("utf-8") + b"\r\n")
                    if line.strip() in ("exit", "logout"):
                        channel.sendall(b"logout\r\n")
                        return
                else:
                    continue
                channel.sendall(shell_session.prompt.encode("utf-8"))
                continue
            if byte == b"\x7f" or byte == b"\x08":  # backspace
                if buffer:
                    buffer = buffer[:-1]
                    channel.sendall(b"\b \b")
                continue
            if byte == b"\x03":  # Ctrl-C
                buffer = ""
                history_idx = None
                channel.sendall(b"^C\r\n" + shell_session.prompt.encode("utf-8"))
                continue
            if byte == b"\x04":  # Ctrl-D
                if not buffer:
                    channel.sendall(b"\r\nlogout\r\n")
                    return
                continue
            if byte == b"\x1b":  # escape sequence (arrow keys)
                seq = data[i:i + 2]
                if seq in (b"[A", b"[B"):
                    i += 2
                    if seq == b"[A":
                        if shell_session.history:
                            history_idx = (
                                len(shell_session.history) - 1 if history_idx is None
                                else max(0, history_idx - 1)
                            )
                            buffer = shell_session.history[history_idx]
                    else:
                        if history_idx is not None:
                            history_idx = min(len(shell_session.history) - 1, history_idx + 1)
                            buffer = shell_session.history[history_idx]
                    channel.sendall(b"\r\x1b[K" + shell_session.prompt.encode("utf-8") + buffer.encode("utf-8"))
                else:
                    # swallow the rest of any other escape sequence ([C/[D, Home, F1…)
                    if i < len(data) and data[i:i + 1] in (b"[", b"O"):
                        i += 1
                        while i < len(data) and not (
                            0x40 <= data[i] <= 0x7E
                        ):
                            i += 1
                        i += 1
                continue
            if byte == b"\t":  # tab: no completion, keep it neutral
                continue
            buffer += byte.decode("utf-8", errors="replace")


class SshHoneypotServer:
    """TCP listener + thread-per-connection SSH honeypot."""

    def __init__(self, port: int, bind: str = "0.0.0.0") -> None:
        if not SSH_AVAILABLE:
            raise RuntimeError("paramiko is not installed — SSH honeypot unavailable")
        self.port = port
        self.bind = bind
        self.host_key = load_or_generate_host_key()
        self.auth_attempts = 0
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.bind, self.port))
        self._sock.listen(16)
        self._thread = threading.Thread(
            target=self._accept_loop, daemon=True, name=f"honeypot-ssh-{self.port}"
        )
        self._thread.start()
        logger.info("Interactive SSH honeypot listening on %s:%d", self.bind, self.port)

    def _accept_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                sock, addr = self._sock.accept()
            except OSError:
                break
            threading.Thread(
                target=_handle_connection, args=(self, sock, addr),
                daemon=True, name=f"honeypot-ssh-{addr[0] if addr else '?'}",
            ).start()

    def stop(self) -> None:
        self._stopping.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    # honeypot_services.stop_service compat
    def close(self) -> None:
        self.stop()
