"""Lightweight protocol-level honeypot service emulators.

Each emulator responds with realistic banners/handshakes sufficient to fool
scanners (nmap, masscan, etc.) and keeps interacting long enough to capture
attacker input:

- SSH: banner + key-exchange-init capture (no crypto stack — protocol roadmap)
- MySQL: full greeting → auth (accept-all) → COM_QUERY loop with fake
  result sets, capturing usernames and every query
- Redis: RESP/inline command loop with AUTH capture and canned replies
- FTP: USER/PASS credential capture plus a small command surface
- ElasticSearch: HTTP fingerprint responses with request capture
- nginx-admin: fake login console with structured credential extraction

Every event is persisted to the ``events`` table (event source
``site_id="honeypot"``) and every captured credential is additionally written
to ``credential_observations`` with ``source_label="protocol-honeypot"`` so it
shows up on the credentials page and can trigger bound decoy deployments.

Services run as background threads using asyncio TCP servers.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import ssl
import struct
import threading
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import parse_qsl
from uuid import uuid4

logger = logging.getLogger("honeypot_services")

# { service_key: (loop, server, port) }
_running: dict[str, tuple[asyncio.AbstractEventLoop, asyncio.Server, int]] = {}
_lock = threading.Lock()


def start_service(service_key: str, port: int, bind: str = "0.0.0.0") -> bool:
    """Start a honeypot service on the given port. Returns True if started.

    Raises OSError if the port cannot be bound (e.g. already in use).
    """
    with _lock:
        if service_key in _running:
            return False
        handler = _HANDLERS.get(service_key)
        # thinkphp is served by its own uvicorn-in-thread app (below), so it
        # has no asyncio handler in _HANDLERS.
        if not handler and service_key != "thinkphp":
            logger.warning("No handler for service_key=%s", service_key)
            return False

        # The ssh service upgrades to a full paramiko protocol stack when the
        # dependency is available; otherwise it degrades to the banner-level
        # asyncio handler below (still fooling scanners, just not interactive).
        if service_key == "ssh":
            from app.services import honeypot_ssh

            if honeypot_ssh.SSH_AVAILABLE:
                ssh_server = honeypot_ssh.SshHoneypotServer(port, bind)
                ssh_server.start()
                _running[service_key] = ("thread", ssh_server, port)
                logger.info("Started interactive honeypot %s on :%d", service_key, port)
                return True
            logger.warning(
                "paramiko is not installed — ssh honeypot on :%d degrades to banner mode", port
            )

        if service_key == "thinkphp":
            # HTTP honeypot: uvicorn-in-thread (mirrors the ssh thread branch;
            # the emulation app lives in honeypot_thinkphp)
            from app.services.honeypot_thinkphp import ThinkPHPHoneypotServer

            tp_server = ThinkPHPHoneypotServer(port, bind)
            tp_server.start()
            _running[service_key] = ("thread", tp_server, port)
            logger.info("Started ThinkPHP honeypot %s on :%d", service_key, port)
            return True

        loop = asyncio.new_event_loop()
        server_ref: list[asyncio.Server] = []
        error_ref: list[Exception] = []

        async def _run():
            try:
                server = await asyncio.start_server(
                    lambda r, w: handler(r, w, service_key, port),
                    bind, port,
                )
                server_ref.append(server)
                await server.serve_forever()
            except asyncio.CancelledError:
                # raised when stop_service() closes the server or the loop
                # shuts down — this is the normal stop path, not an error
                pass
            except OSError as exc:
                error_ref.append(exc)

        t = threading.Thread(target=loop.run_until_complete, args=(_run(),),
                             daemon=True, name=f"honeypot-{service_key}-{port}")
        t.start()
        # Wait briefly for server to bind or fail
        import time
        for _ in range(20):
            if server_ref or error_ref:
                break
            time.sleep(0.05)
        if error_ref:
            raise error_ref[0]
        if server_ref:
            _running[service_key] = ("asyncio", loop, server_ref[0], port)
            logger.info("Started honeypot %s on :%d", service_key, port)
            return True
        return False


def stop_service(service_key: str) -> bool:
    """Stop a running honeypot service."""
    with _lock:
        entry = _running.pop(service_key, None)
    if not entry:
        return False
    kind = entry[0]
    port = entry[-1]
    if kind == "thread":
        ssh_server = entry[1]
        try:
            ssh_server.stop()
        except Exception:
            pass
    else:
        loop, server = entry[1], entry[2]
        try:
            loop.call_soon_threadsafe(server.close)
        except Exception:
            pass
    logger.info("Stopped honeypot %s (was :%d)", service_key, port)
    return True


def is_running(service_key: str) -> bool:
    return service_key in _running


def port_listening(port: int, host: str = "127.0.0.1", timeout: float = 0.3) -> bool:
    """Probe whether anything is actually listening on the port.

    The in-memory ``_running`` map is per-process: after a hot reload (or a
    duplicated worker) a stale process can hold the port while the current
    process believes the service is stopped — or vice versa. This probe is
    the ground truth the services page displays alongside the DB status.
    """
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def running_services() -> dict[str, int]:
    """Return {service_key: port} for all running services.

    Entries are ``(kind, handle..., port)`` tuples — the port is always the
    last element regardless of handler kind (paramiko thread vs asyncio).
    """
    return {k: v[-1] for k, v in _running.items()}


def sync_services_status(db) -> int:
    """Reconcile persisted ``ServiceCatalog.status`` with the in-memory runtime.

    Services whose key is present in :data:`_running` are marked ``running``;
    all others are marked ``stopped``. Returns the number of rows that changed.

    Call this on the services page entry and at startup so the DB never lies
    about what is actually listening on a port.
    """
    # Import locally to avoid a circular import at module load time.
    from app.models.service import ServiceCatalog
    from sqlalchemy import select

    running = set(running_services().keys())
    changed = 0
    services = db.scalars(select(ServiceCatalog)).all()
    for svc in services:
        desired = "running" if svc.service_key in running else "stopped"
        if svc.status != desired:
            svc.status = desired
            db.add(svc)
            changed += 1
    if changed:
        db.commit()
    return changed


# ---------------------------------------------------------------------------
# Event logging + credential capture
# ---------------------------------------------------------------------------

def _honeypot_session(service_key: str, addr: tuple) -> str:
    """One session per TCP connection (previously all connections from an IP
    were merged, which made session replay/portraits meaningless)."""
    source_ip = addr[0] if addr else "unknown"
    return f"{service_key}:{source_ip}:{uuid4().hex[:8]}"


def _outbound_advertised_ip(addr: tuple) -> str:
    """Best local address to advertise in a PASV reply to this client.

    The data channel must point the client at an address that reaches this
    host — for the common honeypot topologies that is either the same-loopback
    case (frontend proxies on the box) or the interface the client connected
    through.
    """
    client_ip = addr[0] if addr else ""
    if client_ip in ("127.0.0.1", "::1"):
        return "127.0.0.1"
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # No packet is actually sent (UDP connect only picks a route).
            probe.connect((client_ip or "8.8.8.8", 80))
            return probe.getsockname()[0]
        finally:
            probe.close()
    except Exception:
        return "127.0.0.1"


def _match_decoy_credentials(db, username: str, password: str) -> int:
    """Trigger decoy deployments whose generated credentials were replayed.

    Closing the loop between protocol honeypots and the decoy chain: an
    attacker who uses credentials harvested from a file/credential bait on one
    of our protocol honeypots flips that deployment to ``triggered`` so the
    operator sees the full reuse chain.
    """
    if not username or not password:
        return 0
    from app.models.decoy import DecoyDeployment
    from sqlalchemy import select

    stmt = select(DecoyDeployment).where(
        DecoyDeployment.generated_username == username,
        DecoyDeployment.generated_password == password,
    )
    rows = db.scalars(stmt).all()
    for deployment in rows:
        if deployment.status != "triggered":
            deployment.status = "triggered"
            deployment.last_triggered_at = datetime.now(timezone.utc)
            db.add(deployment)
    if rows:
        db.commit()
    return len(rows)


def _log_event(service_key: str, port: int, addr: tuple, event_type: str,
               payload: dict | None = None, *, session_id: str | None = None,
               credential: dict | None = None):
    """Log a honeypot interaction event (and optional captured credential)."""
    try:
        from app.core.db import SessionLocal
        from app.services.events import create_credential_observation, create_event
        source_ip = addr[0] if addr else "unknown"
        session = session_id or _honeypot_session(service_key, addr)
        with SessionLocal() as db:
            create_event(
                db,
                site_id="honeypot",
                session_id=session[:64],
                source_ip=source_ip,
                method="TCP",
                path=f"/{service_key}:{port}",
                status_code=0,
                event_type=event_type,
                user_agent="",
                headers_json={},
                payload_json={
                    "service": service_key,
                    "port": port,
                    **(payload or {}),
                },
                signals_json=["honeypot-service"],
                risk_score=85,
                decision="observe",
            )
            if credential and (credential.get("username") or credential.get("password")):
                create_credential_observation(
                    db,
                    source_ip=source_ip,
                    node_name="honeypot-node",
                    service_name=f"{service_key}:{port}",
                    username=str(credential.get("username", ""))[:128],
                    password=str(credential.get("password", ""))[:256],
                    path=f"/{service_key}:{port}",
                    session_id=session[:64],
                    source_label="protocol-honeypot",
                )
                try:
                    _match_decoy_credentials(
                        db,
                        str(credential.get("username", "")),
                        str(credential.get("password", "")),
                    )
                except Exception as exc:
                    logger.debug("Decoy credential match failed: %s", exc)
            from app.services.alert_dispatcher import AlertPayload, get_alert_dispatcher
            get_alert_dispatcher().start_event(AlertPayload(
                event_type=event_type,
                source_ip=source_ip,
                decision="observe",
                risk_score=85,
                signals=["honeypot-service"],
                path=f"/{service_key}:{port}",
                method="TCP",
                summary=f"honeypot {event_type}: {service_key}:{port} from {source_ip}",
                timestamp=datetime.now(timezone.utc),
            ))
    except Exception as exc:
        logger.warning("Honeypot event log failed (%s): %s", event_type, exc)


def parse_credential_form(body: bytes, content_type: str = "") -> dict:
    """Extract username/password from a urlencoded or JSON form body.

    Used by the HTTP-shaped honeypots (nginx-admin console) so captured
    credentials land as structured fields instead of a raw body blob.
    """
    user_keys = ("username", "user", "account", "login", "email", "mail")
    pass_keys = ("password", "pass", "passwd", "pwd", "password1")
    out = {"username": "", "password": ""}
    text = body.decode("utf-8", errors="replace")
    flat: dict[str, str] = {}
    if "json" in (content_type or "").lower() or text.strip().startswith("{"):
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                flat = {k.lower(): v for k, v in data.items() if isinstance(v, str)}
        except (ValueError, TypeError):
            flat = {}
    else:
        flat = {k.lower(): v for k, v in parse_qsl(text, keep_blank_values=True)}
    for key, value in flat.items():
        if not out["username"] and key in user_keys:
            out["username"] = value
        if not out["password"] and key in pass_keys:
            out["password"] = value
    return out


# ---------------------------------------------------------------------------
# MySQL wire helpers (pure functions — unit-testable without sockets)
# ---------------------------------------------------------------------------

MYSQL_CAP_LONG_PASSWORD = 0x00000001
MYSQL_CAP_CONNECT_WITH_DB = 0x00000008
MYSQL_CAP_PROTOCOL_41 = 0x00000200
MYSQL_CAP_TRANSACTIONS = 0x00002000
MYSQL_CAP_SECURE_CONNECTION = 0x00008000
MYSQL_CAP_PLUGIN_AUTH = 0x00080000
# Advertise CLIENT_SSL: without it, secure-by-default clients
# (MariaDB 11.8+, MySQL 8 default policy) abort before sending any
# credential. The handler upgrades the socket with a self-signed cert.
MYSQL_CAP_SSL = 0x00000800
MYSQL_SERVER_CAPS = (
    MYSQL_CAP_LONG_PASSWORD | MYSQL_CAP_PROTOCOL_41 | MYSQL_CAP_TRANSACTIONS
    | MYSQL_CAP_SECURE_CONNECTION | MYSQL_CAP_PLUGIN_AUTH | MYSQL_CAP_SSL
)
COM_QUIT = 0x01
COM_INIT_DB = 0x02
COM_QUERY = 0x03
COM_FIELD_LIST = 0x04
COM_STATISTICS = 0x09
COM_PING = 0x0E


def mysql_lenenc(data: bytes) -> bytes:
    n = len(data)
    if n < 251:
        return bytes([n]) + data
    if n < 65536:
        return b"\xfc" + struct.pack("<H", n) + data
    return b"\xfd" + struct.pack("<I", n) + data


def mysql_packet(body: bytes, seq: int) -> bytes:
    return struct.pack("<I", len(body))[:3] + bytes([seq & 0xFF]) + body


MYSQL_BANNER_VERSION = "5.7.42"


def build_mysql_greeting(salt: bytes, thread_id: int = 42, version: str = MYSQL_BANNER_VERSION) -> bytes:
    """Server greeting (protocol 10) advertising mysql_native_password.

    The 5.x banner is deliberate: MySQL 8 / MariaDB clients demand TLS when
    the server advertises an 8.x version and drop the connection before any
    credential can be captured. A 5.7 greeting keeps those clients talking.
    """
    if len(salt) < 20:
        salt = (salt + os.urandom(20))[:20]
    return (
        b"\x0a" + version.encode() + b"\x00"
        + struct.pack("<I", thread_id)
        + salt[:8] + b"\x00"
        + struct.pack("<H", MYSQL_SERVER_CAPS & 0xFFFF)
        + b"\x21"  # utf8_general_ci
        + struct.pack("<H", 0x0002)  # SERVER_STATUS_AUTOCOMMIT
        + struct.pack("<H", MYSQL_SERVER_CAPS >> 16)
        + b"\x15"  # auth-plugin-data length (8 + 1 + 12)
        + b"\x00" * 10
        + salt[8:20] + b"\x00"
        + b"mysql_native_password\x00"
    )


def parse_mysql_handshake_response(data: bytes) -> dict:
    """Parse a protocol-41 HandshakeResponse (username/auth/db/plugin)."""
    result = {
        "username": "", "auth_response": b"", "database": "", "plugin": "", "caps": 0,
    }
    if len(data) < 33:
        return result
    caps = struct.unpack("<I", data[0:4])[0]
    result["caps"] = caps
    i = 32  # 4 caps + 4 max-packet + 1 charset + 23 reserved
    nul = data.find(b"\x00", i)
    if nul < 0:
        return result
    result["username"] = data[i:nul].decode("utf-8", errors="replace")
    i = nul + 1
    if caps & MYSQL_CAP_SECURE_CONNECTION:
        if i >= len(data):
            return result
        auth_len = data[i]
        i += 1
        result["auth_response"] = data[i:i + auth_len]
        i += auth_len
    else:
        nul = data.find(b"\x00", i)
        if nul >= 0:
            result["auth_response"] = data[i:nul]
            i = nul + 1
    if caps & MYSQL_CAP_PLUGIN_AUTH:
        nul = data.find(b"\x00", i)
        if nul >= 0:
            result["plugin"] = data[i:nul].decode("utf-8", errors="replace")
            i = nul + 1
    if caps & MYSQL_CAP_CONNECT_WITH_DB:
        nul = data.find(b"\x00", i)
        if nul >= 0:
            result["database"] = data[i:nul].decode("utf-8", errors="replace")
    return result


def build_mysql_ok(seq: int = 2) -> bytes:
    body = b"\x00" + b"\x00" + b"\x00" + struct.pack("<H", 0x0002) + struct.pack("<H", 0)
    return mysql_packet(body, seq)


def build_mysql_err(code: int, message: str, seq: int) -> bytes:
    body = b"\xff" + struct.pack("<H", code) + b"#28000" + message.encode("utf-8", "replace")
    return mysql_packet(body, seq)


def build_mysql_resultset(columns: list[str], rows: list[list], start_seq: int) -> bytes:
    """A classic (EOF-terminated) text resultset — we never advertise
    CLIENT_DEPRECATE_EOF so clients use the simple framing."""
    seq = start_seq
    parts = [mysql_packet(bytes([len(columns)]), seq)]
    seq += 1
    for col in columns:
        name = col.encode("utf-8")
        body = (
            mysql_lenenc(b"def") + mysql_lenenc(b"") + mysql_lenenc(b"")
            + mysql_lenenc(b"") + mysql_lenenc(name) + mysql_lenenc(name)
            + b"\x0c" + struct.pack("<H", 0x21) + struct.pack("<I", 1024)
            + b"\xfd" + struct.pack("<H", 0) + b"\x00" + struct.pack("<H", 0)
        )
        parts.append(mysql_packet(body, seq))
        seq += 1
    parts.append(mysql_packet(b"\xfe" + struct.pack("<H", 0) + struct.pack("<H", 0x0002), seq))
    seq += 1
    for row in rows:
        parts.append(
            mysql_packet(b"".join(mysql_lenenc(str(v).encode("utf-8")) for v in row), seq)
        )
        seq += 1
    parts.append(mysql_packet(b"\xfe" + struct.pack("<H", 0) + struct.pack("<H", 0x0002), seq))
    return b"".join(parts)


def mysql_query_response(query: str, start_seq: int) -> bytes:
    """Canned-but-plausible answers for the common probe queries."""
    q = " ".join(query.strip().lower().split())
    if q.startswith("select version()"):
        return build_mysql_resultset(["version()"], [[MYSQL_BANNER_VERSION]], start_seq)
    if q.startswith(("select user()", "select current_user()")):
        return build_mysql_resultset(["user()"], [["root@localhost"]], start_seq)
    if q.startswith("select database()"):
        return build_mysql_resultset(["database()"], [["mysql"]], start_seq)
    if q.startswith("show databases"):
        return build_mysql_resultset(
            ["Database"], [["information_schema"], ["mysql"], ["performance_schema"], ["sys"]],
            start_seq,
        )
    if q.startswith(("show tables", "show tables from")):
        return build_mysql_resultset(
            ["Tables_in_mysql"], [["user"], ["db"], ["host"], ["func"]], start_seq
        )
    if q.startswith("select"):
        return build_mysql_resultset(["result"], [["1"]], start_seq)
    return build_mysql_ok(start_seq)


# ---------------------------------------------------------------------------
# SSH Emulator
# ---------------------------------------------------------------------------

async def _handle_ssh(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                      service_key: str, port: int):
    addr = writer.get_extra_info("peername")
    session = _honeypot_session(service_key, addr)
    try:
        # Send SSH banner
        writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
        await writer.drain()
        _log_event(service_key, port, addr, "ssh_connect", {"protocol": "ssh"},
                   session_id=session)

        # Read client banner
        client_banner = await asyncio.wait_for(reader.readline(), timeout=10)
        banner = client_banner.decode("utf-8", errors="replace").strip()

        # Read key exchange init
        data = await asyncio.wait_for(reader.read(4096), timeout=10)
        kex_algos = ""
        if b"curve25519-sha256" in data:
            kex_algos = "curve25519-sha256"
        elif b"ecdh-sha2-nistp256" in data:
            kex_algos = "ecdh-sha2-nistp256"
        _log_event(service_key, port, addr, "ssh_handshake", {
            "client_banner": banner,
            "data_len": len(data),
            "kex_hint": kex_algos,
        }, session_id=session)

        # Send disconnect (protocol mismatch) to end cleanly
        # SSH_MSG_DISCONNECT = 2, reason = 2 (protocol error)
        disconnect = struct.pack(">I", 1 + 1 + 4 + 1 + 4)  # packet length
        disconnect += b"\x02"  # padding
        disconnect += b"\x02"  # SSH_MSG_DISCONNECT
        disconnect += struct.pack(">I", 2)  # reason: protocol error
        disconnect += b"\x00\x00\x00\x00"  # description: empty
        disconnect += b"\x00\x00\x00\x00"  # language: empty
        writer.write(disconnect)
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


# ---------------------------------------------------------------------------
# MySQL Emulator
# ---------------------------------------------------------------------------

def _mysql_tls_context() -> "ssl.SSLContext":
    """Self-signed TLS context for the MySQL honeypot (persisted like the
    SSH host key so the fingerprint stays stable across restarts)."""
    from pathlib import Path
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime as _dt
    from app.core.config import get_settings

    settings = get_settings()
    data_dir = Path(
        settings.database_url.replace("sqlite:///", "").rsplit("/", 1)[0] or "."
    )
    cert_path = data_dir / "mysql_tls_cert.pem"
    key_path = data_dir / "mysql_tls_key.pem"
    if cert_path.exists() and key_path.exists():
        return ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "mysql-honeypot")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.now(_dt.timezone.utc))
        .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    data_dir.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    return context


async def _handle_mysql(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                        service_key: str, port: int):
    addr = writer.get_extra_info("peername")
    session = _honeypot_session(service_key, addr)
    try:
        writer.write(mysql_packet(build_mysql_greeting(os.urandom(20)), 0))
        await writer.drain()
        _log_event(service_key, port, addr, "mysql_connect", {"protocol": "mysql"},
                   session_id=session)

        header = await asyncio.wait_for(reader.readexactly(4), timeout=15)
        length = int.from_bytes(header[:3], "little")
        payload = await asyncio.wait_for(reader.readexactly(length), timeout=15)
        # SSL Request detection must read the caps directly: the packet is
        # exactly 32 bytes, below the parser's >=33 threshold, so the parser
        # would zero out caps and the branch would never fire.
        ssl_request = (
            length <= 36
            and int.from_bytes(payload[0:4], "little") & 0x0800
        )
        handshake = parse_mysql_handshake_response(payload)
        if ssl_request:
            # SSL Request packet: the client wants TLS before sending real
            # credentials. Modern (MariaDB 11.8+, MySQL 8.0 default-policy)
            # clients hard-fail without it, so upgrade the socket with a
            # self-signed certificate and read the real handshake over TLS.
            transport = writer.transport
            loop = asyncio.get_running_loop()
            protocol = transport.get_protocol()
            new_transport = await loop.start_tls(
                transport, protocol, _mysql_tls_context(), server_side=True,
            )
            protocol._stream_reader._transport = new_transport
            writer._transport = new_transport
            _log_event(service_key, port, addr, "mysql_tls_upgrade",
                       {"protocol": "mysql"}, session_id=session)
            header = await asyncio.wait_for(reader.readexactly(4), timeout=15)
            length = int.from_bytes(header[:3], "little")
            payload = await asyncio.wait_for(reader.readexactly(length), timeout=15)
            handshake = parse_mysql_handshake_response(payload)
        _log_event(service_key, port, addr, "mysql_login", {
            "username": handshake["username"],
            "database": handshake["database"],
            "plugin": handshake["plugin"],
            "auth_response_len": len(handshake["auth_response"]),
            "accepted": True,
        }, session_id=session,
           credential={"username": handshake["username"], "password": ""},
        )

        # Accept any credentials (the password arrives as a salted scramble we
        # cannot verify anyway) and keep the session open for queries.
        writer.write(build_mysql_ok(2))
        await writer.drain()

        while True:
            header = await asyncio.wait_for(reader.readexactly(4), timeout=30)
            length = int.from_bytes(header[:3], "little")
            seq = header[3]
            payload = await asyncio.wait_for(reader.readexactly(length), timeout=30) if length else b""
            command = payload[0] if payload else COM_QUIT
            if command == COM_QUIT:
                break
            if command == COM_PING:
                writer.write(build_mysql_ok(seq + 1))
            elif command == COM_QUERY:
                query = payload[1:].decode("utf-8", errors="replace").strip()
                _log_event(service_key, port, addr, "mysql_query",
                           {"query": query[:500]}, session_id=session)
                writer.write(mysql_query_response(query, seq + 1))
            elif command == COM_INIT_DB:
                writer.write(build_mysql_ok(seq + 1))
            elif command == COM_FIELD_LIST:
                writer.write(mysql_packet(
                    b"\xfe" + struct.pack("<H", 0) + struct.pack("<H", 0x0002), seq + 1))
            elif command == COM_STATISTICS:
                stats = b"Uptime: 86400  Threads: 2  Questions: 145  Slow queries: 0"
                writer.write(mysql_packet(stats, seq + 1))
            else:
                writer.write(build_mysql_err(1047, "Unknown command", seq + 1))
            await writer.drain()
    except (asyncio.IncompleteReadError, TimeoutError):
        pass
    except Exception:
        pass
    finally:
        writer.close()


# ---------------------------------------------------------------------------
# Redis Emulator
# ---------------------------------------------------------------------------

async def _handle_redis(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                        service_key: str, port: int):
    addr = writer.get_extra_info("peername")
    session = _honeypot_session(service_key, addr)
    try:
        _log_event(service_key, port, addr, "redis_connect", {"protocol": "redis"},
                   session_id=session)

        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=30)
            if not line:
                break
            cmd = line.decode("utf-8", errors="replace").strip()

            # Parse RESP or inline command
            parts = cmd.split()
            if not parts:
                continue

            # Handle RESP array header
            if cmd.startswith("*"):
                # Read the specified number of bulk strings
                count = int(cmd[1:])
                args = []
                for _ in range(count):
                    bulk_header = await asyncio.wait_for(reader.readline(), timeout=5)
                    if bulk_header.startswith(b"$"):
                        length = int(bulk_header[1:].strip())
                        data = await asyncio.wait_for(reader.readexactly(length), timeout=5)
                        args.append(data.decode("utf-8", errors="replace"))
                        await asyncio.wait_for(reader.readline(), timeout=5)  # trailing CRLF
                command = args[0].upper() if args else ""
                command_args = args[1:]
            else:
                command = parts[0].upper()
                command_args = parts[1:]

            _log_event(service_key, port, addr, "redis_command", {
                "command": command,
                "args": command_args[:5],
            }, session_id=session)

            if command == "PING":
                writer.write(b"+PONG\r\n")
            elif command == "AUTH":
                # AUTH [user] password — capture both shapes, stay online so
                # the attacker keeps probing (and keeps revealing material).
                if len(command_args) >= 2:
                    credential = {"username": command_args[0], "password": command_args[1]}
                elif command_args:
                    credential = {"username": "default", "password": command_args[0]}
                else:
                    credential = {"username": "", "password": ""}
                _log_event(service_key, port, addr, "redis_auth_fail", {
                    "username": credential["username"],
                    "password_len": len(credential["password"]),
                }, session_id=session, credential=credential)
                writer.write(b"-ERR invalid password\r\n")
            elif command in ("SET", "SETEX", "HSET", "LPUSH", "RPUSH", "SADD", "EXPIRE"):
                writer.write(b"+OK\r\n")
            elif command in ("GET", "HGET"):
                writer.write(b"$-1\r\n")  # nil
            elif command in ("DEL", "EXISTS", "TTL", "HLEN", "LLEN"):
                writer.write(b":0\r\n")
            elif command == "SELECT":
                writer.write(b"+OK\r\n")
            elif command == "INFO":
                info = (
                    "redis_version:7.0.15\r\n"
                    "redis_mode:standalone\r\n"
                    "os:Linux 5.15.0 x86_64\r\n"
                    "tcp_port:6379\r\n"
                    "uptime_in_seconds:86400\r\n"
                    "connected_clients:1\r\n"
                    "used_memory_human:1.00M\r\n"
                )
                writer.write(f"${len(info)}\r\n{info}\r\n".encode())
            elif command == "COMMAND":
                writer.write(b"*0\r\n")
            elif command == "QUIT":
                writer.write(b"+OK\r\n")
                break
            else:
                writer.write(b"-ERR unknown command\r\n")
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


# ---------------------------------------------------------------------------
# FTP Emulator
# ---------------------------------------------------------------------------

async def _handle_ftp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                      service_key: str, port: int):
    addr = writer.get_extra_info("peername")
    session = _honeypot_session(service_key, addr)
    try:
        writer.write(b"220 ProFTPD 1.3.8 Server ready.\r\n")
        await writer.drain()
        _log_event(service_key, port, addr, "ftp_connect", {"protocol": "ftp"},
                   session_id=session)

        username = ""
        logged_in = False
        data_conn: dict = {}  # "server" -> asyncio.Server, "writer" -> StreamWriter
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=30)
            if not line:
                break
            cmd = line.decode("utf-8", errors="replace").strip()
            parts = cmd.split(None, 1)
            if not parts:
                continue
            verb = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            if verb == "USER":
                username = arg
                writer.write(b"331 Password required for " + arg.encode() + b"\r\n")
            elif verb == "PASS":
                if not username:
                    writer.write(b"503 Login with USER first.\r\n")
                else:
                    _log_event(service_key, port, addr, "ftp_login", {
                        "username": username,
                        "password_len": len(arg),
                    }, session_id=session,
                       credential={"username": username, "password": arg})
                    # Accept any credential (logged above) and grant access: a
                    # working session keeps attackers engaged far longer than
                    # an instant 530 rejection.
                    logged_in = True
                    writer.write(b"230 Login successful.\r\n")
            elif verb == "QUIT":
                writer.write(b"221 Goodbye.\r\n")
                break
            elif verb == "FEAT":
                writer.write(b"211-Features:\r\n UTF8\r\n PASV\r\n211 End\r\n")
            elif verb == "SYST":
                writer.write(b"215 UNIX Type: L8\r\n")
            elif verb == "PWD":
                writer.write(b'257 "/" is the current directory\r\n')
            elif verb == "TYPE":
                writer.write(b"200 Type set to " + (arg.encode() or b"I") + b"\r\n")
            elif verb == "NOOP":
                writer.write(b"200 NOOP ok.\r\n")
            elif verb == "CWD":
                writer.write(b"250 CWD command successful\r\n")
            elif verb in ("PASV", "EPSV"):
                if not logged_in:
                    writer.write(b"530 Please login with USER and PASS.\r\n")
                else:
                    is_epsv = verb == "EPSV"
                    # Close any previous data channel first.
                    old = data_conn.pop("server", None)
                    if old is not None:
                        old.close()
                    data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    data_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    data_sock.bind(("0.0.0.0", 0))
                    data_sock.listen(1)
                    loop_tmp = asyncio.get_running_loop()
                    data_server = await loop_tmp.create_server(
                        asyncio.Protocol, sock=data_sock
                    )
                    data_conn["server"] = data_server
                    data_conn["sock"] = data_sock
                    dport = data_sock.getsockname()[1]
                    if is_epsv:
                        writer.write(f"229 Entering Extended Passive Mode (|||{dport}|)\r\n".encode())
                    else:
                        advert_ip = _outbound_advertised_ip(addr)
                        p_hi, p_lo = dport // 256, dport % 256
                        writer.write(
                            b"227 Entering Passive Mode ("
                            + ",".join(str(o).encode() for o in advert_ip.split("."))
                            + f",{p_hi},{p_lo}".encode() + b")\r\n"
                        )

                    loop = asyncio.get_running_loop()

                    async def _accept_data():
                        try:
                            client_sock, _ = await loop.sock_accept(
                                data_conn["sock"]
                            )
                            _r, w = await asyncio.open_connection(sock=client_sock)
                            data_conn["writer"] = w
                        except Exception:
                            pass

                    data_conn["accept_task"] = asyncio.ensure_future(_accept_data())
            elif verb in ("LIST", "NLST"):
                dwriter = data_conn.get("writer")
                if not logged_in:
                    writer.write(b"530 Please login with USER and PASS.\r\n")
                elif dwriter is None and data_conn.get("accept_task") is not None:
                    # The client's data connection may race our accept task;
                    # give it a moment before giving up.
                    try:
                        await asyncio.wait_for(
                            asyncio.shield(data_conn["accept_task"]), timeout=3
                        )
                    except Exception:
                        pass
                    dwriter = data_conn.get("writer")
                if dwriter is None:
                    writer.write(b"425 Use PASV first.\r\n")
                else:
                    writer.write(b"150 Here comes the directory listing.\r\n")
                    listing = (
                        "total 28\r\n"
                        "drwxr-xr-x  2 root root 4096 Mar 14 09:32 .\r\n"
                        "drwxr-xr-x  3 root root 4096 Mar 14 09:32 ..\r\n"
                        "-rw-------  1 root root  220 Mar 14 09:32 .bash_history\r\n"
                        "-rw-r--r--  1 root root  3771 Mar  9 14:11 .bashrc\r\n"
                        "drwxr-xr-x  2 root root 4096 Mar 12 18:04 backup\r\n"
                        "drwxr-xr-x  2 root root 4096 Mar 11 10:47 conf\r\n"
                        "drwxr-xr-x  2 root root 4096 Feb 28 21:20 logs\r\n"
                        "-rw-r--r--  1 root root 18954 Mar 13 22:58 nohup.out\r\n"
                    )
                    try:
                        dwriter.write(
                            listing.encode() if verb == "LIST"
                            else "\n".join(
                                ln.split()[-1] for ln in listing.strip().splitlines()
                            ).encode() + b"\r\n"
                        )
                        await dwriter.drain()
                    except Exception:
                        pass
                    finally:
                        dwriter.close()
                        data_conn.pop("writer", None)
                    writer.write(b"226 Directory send OK.\r\n")
            elif verb in ("RETR", "STOR", "APPE", "DELE", "MKD", "RMD"):
                writer.write(b"550 Permission denied.\r\n")
            elif verb == "HELP":
                writer.write(b"214-Commands supported:\r\n USER PASS QUIT FEAT SYST PWD CWD LIST PASV\r\n214 End\r\n")
            else:
                writer.write(b"500 Unknown command.\r\n")
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            if data_conn.get("server"):
                data_conn["server"].close()
            if data_conn.get("sock"):
                data_conn["sock"].close()
        except Exception:
            pass
        writer.close()


# ---------------------------------------------------------------------------
# ElasticSearch Emulator (HTTP-based)
# ---------------------------------------------------------------------------

async def _handle_elasticsearch(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                service_key: str, port: int):
    addr = writer.get_extra_info("peername")
    session = _honeypot_session(service_key, addr)
    try:
        _log_event(service_key, port, addr, "elasticsearch_connect", {"protocol": "http"},
                   session_id=session)

        data = await asyncio.wait_for(reader.read(16384), timeout=15)
        head = data.split(b"\r\n\r\n", 1)
        header_block = head[0].decode("utf-8", errors="replace") if data else ""
        body_bytes = head[1][:1024] if len(head) > 1 else b""
        lines = header_block.split("\r\n")
        request_line = lines[0] if lines else ""
        parts = request_line.split()
        method = parts[0] if parts else "GET"
        path = parts[1] if len(parts) > 1 else "/"
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip().lower()] = value.strip()

        _log_event(service_key, port, addr, "elasticsearch_request", {
            "method": method,
            "path": path,
            "request_line": request_line[:200],
            "auth_present": bool(headers.get("authorization")),
            "body": body_bytes.decode("utf-8", errors="replace")[:1024],
        }, session_id=session)

        # Build realistic Elasticsearch response
        if path == "/" or path == "":
            body = json.dumps({
                "name": "honeypot-node-1",
                "cluster_name": "elasticsearch-cluster",
                "cluster_uuid": "aBcDeFgHiJkLmNoPqRsT",
                "version": {
                    "number": "7.17.9",
                    "build_flavor": "default",
                    "build_type": "deb",
                    "build_hash": "ef48222227ee6b9e70e502f275c0e86e376c",
                    "build_date": "2023-01-31T08:39:25.234567Z",
                    "build_snapshot": False,
                    "lucene_version": "8.11.1",
                    "minimum_wire_compatibility_version": "6.8.0",
                    "minimum_index_compatibility_version": "6.0.0-beta1",
                },
                "tagline": "You Know, for Search",
            }, indent=2)
        elif "/_cluster" in path:
            body = json.dumps({"cluster_name": "elasticsearch-cluster", "status": "green"})
        elif "/_cat" in path:
            body = "honeypot-node-1 127.0.0.1 7.17.9\n"
        elif "/_search" in path:
            body = json.dumps({"hits": {"total": {"value": 0}, "hits": []}})
        else:
            body = json.dumps({"error": {"root_cause": [{"type": "index_not_found_exception", "reason": f"no such index [{path.strip('/').split('/')[0]}]"}]}})

        status_line = "HTTP/1.1 200 OK"
        if "index_not_found" in body:
            status_line = "HTTP/1.1 404 Not Found"

        response = (
            f"{status_line}\r\n"
            "Content-Type: application/json; charset=UTF-8\r\n"
            "X-elastic-product: Elasticsearch\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{body}"
        )
        writer.write(response.encode())
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


async def _handle_nginx_admin(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                              service_key: str, port: int):
    """Fake nginx admin console over HTTP — login page + credential capture."""
    addr = writer.get_extra_info("peername")
    session = _honeypot_session(service_key, addr)
    try:
        _log_event(service_key, port, addr, "nginx_admin_connect", {"protocol": "http"},
                   session_id=session)

        data = await asyncio.wait_for(reader.read(16384), timeout=15)
        head = data.split(b"\r\n\r\n", 1)
        header_lines = (head[0].decode("utf-8", errors="replace") if data else "").split("\r\n")
        body_bytes = head[1] if len(head) > 1 else b""
        request_line = header_lines[0] if header_lines else ""
        parts = request_line.split()
        method = parts[0] if parts else "GET"
        path = parts[1] if len(parts) > 1 else "/"
        headers = {}
        for line in header_lines[1:]:
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip().lower()] = value.strip()

        _log_event(service_key, port, addr, "nginx_admin_request", {
            "method": method,
            "path": path,
            "request_line": request_line[:200],
        }, session_id=session)

        if method == "POST" and "/login" in path:
            creds = parse_credential_form(body_bytes, headers.get("content-type", ""))
            _log_event(service_key, port, addr, "nginx_admin_login", {
                "username": creds["username"],
                "password_len": len(creds["password"]),
                "body": body_bytes.decode("utf-8", errors="replace")[:400],
            }, session_id=session, credential=creds)
            body = json.dumps({"error": "Invalid credentials"}, separators=(",", ":"))
            status_line = "HTTP/1.1 401 Unauthorized"
            content_type = "application/json"
        else:
            body = (
                "<!doctype html><html><head><meta charset='utf-8'><title>Nginx Admin</title>"
                "<style>body{font-family:system-ui;background:#f0f2f5;display:grid;place-items:center;min-height:100vh;margin:0}"
                "form{background:#fff;padding:32px;border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.08);width:320px}"
                "h1{font-size:18px;margin:0 0 16px;color:#0f172a}input{width:100%;margin-top:10px;padding:10px;border:1px solid #cbd5e1;border-radius:6px;box-sizing:border-box}"
                "button{width:100%;margin-top:16px;padding:10px;border:0;border-radius:6px;background:#0e9f6e;color:#fff;font-weight:600;cursor:pointer}</style></head>"
                "<body><form method='post' action='/login'><h1>Nginx Admin Console</h1>"
                "<input name='email' placeholder='admin@example.com' autofocus>"
                "<input name='password' type='password' placeholder='Password'>"
                "<button>Sign in</button></form></body></html>"
            )
            status_line = "HTTP/1.1 200 OK"
            content_type = "text/html; charset=utf-8"

        response = (
            f"{status_line}\r\n"
            "Server: nginx/1.24.0\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body.encode())}\r\n"
            "Connection: close\r\n"
            "\r\n"
            f"{body}"
        )
        writer.write(response.encode())
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


# ---------------------------------------------------------------------------
# Handler registry
# ---------------------------------------------------------------------------

_HANDLERS: dict[str, Callable] = {
    "ssh": _handle_ssh,
    "mysql": _handle_mysql,
    "redis": _handle_redis,
    "ftp": _handle_ftp,
    "elasticsearch": _handle_elasticsearch,
    "nginx-admin": _handle_nginx_admin,
}


def supported_services() -> list[str]:
    return list(_HANDLERS.keys())
