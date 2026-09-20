"""Interactive session simulation for the protocol honeypots (MySQL /
Redis / FTP / ElasticSearch) and pcap export for session replay.

Protocol handlers previously only logged events; this module gives every
protocol connection a first-class HoneypotSession with an incrementally
written transcript using the same entry shape as the SSH honeypot
(session_open / auth / cmd+out), so the existing replay page renders all
protocols uniformly.

``export_pcap`` synthesizes a capture file from the transcript: each
client line becomes a client→server TCP payload packet, each server
output a server→client packet, with timestamps taken from the entries.
Pure stdlib — no external pcap tooling required.
"""
from __future__ import annotations

import struct
from datetime import datetime, timezone

_MAX_ENTRY_CHARS = 8000
_MAX_ENTRIES = 600

_CLIENT_IP = "198.51.100.20"   # synthetic attacker address in exported pcap
_SERVER_IP = "10.0.0.5"        # synthetic honeypot address


def _append_transcript(entries: list[dict], entry: dict) -> list[dict]:
    entry = dict(entry)
    for field_name in ("cmd", "out"):
        value = entry.get(field_name)
        if isinstance(value, str) and len(value) > _MAX_ENTRY_CHARS:
            entry[field_name] = value[:_MAX_ENTRY_CHARS] + f"\n… [truncated {len(value)} chars]"
    entries.append(entry)
    excess = len(entries) - _MAX_ENTRIES
    if excess > 0:
        entries = entries[excess:]
    return entries


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def open_protocol_session(*, service: str, source_ip: str, port: int,
                          username: str = "") -> int:
    from app.core.db import SessionLocal
    from app.models.honeypot_session import HoneypotSession

    with SessionLocal() as db:
        row = HoneypotSession(
            session_id=f"{service}-{source_ip}"[:64],
            service=service,
            source_ip=source_ip,
            port=port,
            status="active",
            username=(username or "")[:64],
            transcript_json=_append_transcript([], {"ts": _now_iso(), "kind": "session_open"}),
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row.id


def log_interaction(session_pk: int, *, client_line: str | None = None,
                    server_line: str | None = None, auth: dict | None = None) -> None:
    """Append one request/response step to the session transcript."""
    from app.core.db import SessionLocal
    from app.models.honeypot_session import HoneypotSession

    with SessionLocal() as db:
        row = db.get(HoneypotSession, session_pk)
        if row is None:
            return
        entries = list(row.transcript_json or [])
        if auth is not None:
            entries = _append_transcript(entries, {
                "ts": _now_iso(), "kind": "auth", "method": "password",
                "user": auth.get("username", ""), "accepted": auth.get("accepted", True),
            })
            if auth.get("username"):
                row.username = str(auth["username"])[:64]
            if auth.get("password"):
                row.password = str(auth["password"])[:256]
            row.auth_attempts = (row.auth_attempts or 0) + 1
        if client_line is not None:
            row.command_count = (row.command_count or 0) + 1
            entries = _append_transcript(entries, {"ts": _now_iso(), "kind": "cmd",
                                                   "cmd": client_line[:_MAX_ENTRY_CHARS]})
        if server_line is not None:
            entries = _append_transcript(entries, {"ts": _now_iso(), "kind": "out",
                                                   "out": server_line[:_MAX_ENTRY_CHARS]})
        row.transcript_json = entries
        db.add(row)
        db.commit()


def close_session(session_pk: int) -> None:
    from app.core.db import SessionLocal
    from app.models.honeypot_session import HoneypotSession

    with SessionLocal() as db:
        row = db.get(HoneypotSession, session_pk)
        if row is None:
            return
        row.status = "closed"
        row.ended_at = datetime.now(timezone.utc)
        row.transcript_json = _append_transcript(list(row.transcript_json or []),
                                                 {"ts": _now_iso(), "kind": "session_close"})
        db.add(row)
        db.commit()


# ---------------------------------------------------------------------------
# pcap export
# ---------------------------------------------------------------------------

def _ipv4_checksum(header: bytes) -> int:
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) + header[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _tcp_packet(src_ip: str, dst_ip: str, sport: int, dport: int,
                payload: bytes, seq: int) -> bytes:
    src = bytes(int(x) for x in src_ip.split("."))
    dst = bytes(int(x) for x in dst_ip.split("."))
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, (seq + max(len(payload), 1)) & 0xFFFFFFFF,
                      (5 << 4), 0x18, 65535, 0, 0) + payload
    total_len = 20 + len(tcp)
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 0, 0, 64, 6, 0, src, dst)
    checksum = _ipv4_checksum(ip_header)
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 0, 0, 64, 6,
                            checksum, src, dst)
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    return eth + ip_header + tcp


def _pcap_record(payload: bytes, ts: datetime) -> bytes:
    return struct.pack("!IIII", int(ts.timestamp()), ts.microsecond, len(payload), len(payload)) + payload


def _entry_ts(entry: dict) -> datetime:
    try:
        return datetime.fromisoformat(entry.get("ts"))
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)


def export_pcap(transcript: list[dict], *, service: str, source_ip: str,
                port: int) -> bytes:
    """Synthesize a libpcap capture from the session transcript.

    Client lines become client→server packets, server outputs become
    server→client packets on the session's service port.
    """
    port = port or 2222
    out = bytearray()
    out += struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    seq_c, seq_s = 1000, 5000
    sport = 51000

    for entry in transcript or []:
        ts = _entry_ts(entry)
        kind = entry.get("kind")
        if kind == "auth":
            payload = f"AUTH user={entry.get('user', '')} pass=********".encode()
            pkt = _tcp_packet(_CLIENT_IP, _SERVER_IP, sport, port, payload, seq_c)
            seq_c += len(payload)
        elif kind == "cmd":
            payload = entry.get("cmd", "").encode("utf-8", errors="replace")
            if not payload:
                continue
            pkt = _tcp_packet(_CLIENT_IP, _SERVER_IP, sport, port, payload, seq_c)
            seq_c += len(payload)
        elif kind == "out":
            payload = entry.get("out", "").encode("utf-8", errors="replace")
            if not payload:
                continue
            pkt = _tcp_packet(_SERVER_IP, _CLIENT_IP, port, sport, payload, seq_s)
            seq_s += len(payload)
        else:
            continue
        out += _pcap_record(pkt, ts)
    return bytes(out)
