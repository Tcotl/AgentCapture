"""
Alert dispatcher — sends threat/credential/system events to external channels.

Supports webhook, 钉钉机器人, 飞书机器人, SMTP email.
Dry-run mode by default (ALERTS_ENABLED=false).

Fire-and-forget via threading.Thread(daemon=True) — matches
honeypot_services.py pattern.
"""

from __future__ import annotations

import hashlib
import hmac
import base64
import json
import logging
import smtplib
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from email.mime.text import MIMEText
from typing import Any
from urllib.parse import quote_plus

import httpx

from app.core.config import get_settings

logger = logging.getLogger("agent_capture.alerts")
logger.setLevel(logging.INFO)
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(_handler)
    logger.propagate = False  # avoid duplicate output

# ---------------------------------------------------------------------------
# AlertPayload — what flows through the pipeline
# ---------------------------------------------------------------------------

@dataclass
class AlertPayload:
    event_type: str          # e.g. "http_request", "credential_attempt", "c2_heartbeat"
    source_ip: str
    decision: str            # "block" | "isolate" | "challenge" | "observe" | "allow"
    risk_score: int
    signals: list[str]
    path: str
    method: str
    summary: str             # one-line human-readable summary for IM messages
    timestamp: datetime

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d

# ---------------------------------------------------------------------------
# Dispatcher singleton
# ---------------------------------------------------------------------------

_alert_dispatcher: AlertDispatcher | None = None

def get_alert_dispatcher() -> AlertDispatcher:
    global _alert_dispatcher
    if _alert_dispatcher is None:
        _alert_dispatcher = AlertDispatcher()
    return _alert_dispatcher


class AlertDispatcher:
    """Fire-and-forget alert delivery with deduplication and policy matching."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # dedupe: {(source_ip, event_type, channel_id): monotonic_ts}
        self._seen: dict[tuple, float] = {}
        self._dedupe_ttl = 300.0  # 5 min
        # policy/channel cache
        self._cache_lock = threading.Lock()
        self._cache: dict[str, Any] = {}  # {"ts": float, "policies": [...], "channels": {name: AlertChannel}}
        self._cache_ttl = 60.0  # 60s

    # ---- public entry point (fire-and-forget) ----------------------------

    def start_event(self, payload: AlertPayload) -> None:
        """Schedule alert dispatch in a daemon thread. Never raises."""
        def _run() -> None:
            try:
                self._dispatch(payload)
            except Exception:
                logger.exception("alert dispatch failed for %s from %s",
                                 payload.event_type, payload.source_ip)
        threading.Thread(target=_run, daemon=True,
                         name=f"alert-{payload.event_type}").start()

    # ---- synchronous dispatch (used by test-send too) --------------------

    def dispatch_sync(self, payload: AlertPayload, *, force: bool = False) -> dict[str, Any]:
        """Run dispatch synchronously. Returns {ok: bool, results: [...]}.
        force=True bypasses dedupe and policy matching."""
        return self._dispatch(payload, force=force)

    def dispatch_channel_sync(self, channel, payload: AlertPayload) -> dict[str, Any]:
        """Run a direct one-channel test send, bypassing policies and dedupe."""
        settings = get_settings()
        ok = self._send_to_channel(channel, payload, dry_run=(not settings.alerts_enabled))
        return {
            "ok": ok,
            "dry_run": not settings.alerts_enabled,
            "results": [{"channel": channel.name, "type": channel.channel_type, "ok": ok}],
        }

    def invalidate_cache(self) -> None:
        """Clear cached policies/channels after admin-side configuration changes."""
        with self._cache_lock:
            self._cache = {}

    # ---- internal --------------------------------------------------------

    def _dispatch(self, payload: AlertPayload, *, force: bool = False) -> dict[str, Any]:
        settings = get_settings()
        results: list[dict[str, Any]] = []

        logger.debug(
            "dispatch event=%s from=%s decision=%s score=%s force=%s",
            payload.event_type,
            payload.source_ip,
            payload.decision,
            payload.risk_score,
            force,
        )

        if not settings.alerts_enabled and not force:
            msg = f"[alert-dry-run] would send {payload.event_type} from {payload.source_ip}: {payload.summary}"
            logger.info(msg)
            return {"ok": True, "dry_run": True, "results": []}

        policies, channels_by_name = self._load_policy_and_channels()
        if not policies:
            logger.debug("no active policies, skipping %s", payload.event_type)
            return {"ok": True, "no_policies": True, "results": []}

        for policy in policies:
            if not policy.is_active:
                continue
            if not self._policy_matches(policy, payload):
                continue
            for channel_name in policy.delivery_channels_json or []:
                ch = channels_by_name.get(channel_name)
                if not ch or not ch.is_active:
                    continue
                if not force and self._is_duped(payload.source_ip, payload.event_type, ch.id):
                    continue
                ok = self._send_to_channel(ch, payload, dry_run=(not settings.alerts_enabled))
                results.append({"channel": ch.name, "type": ch.channel_type, "ok": ok})
                logger.debug(
                    "dispatched %s to %s (%s): ok=%s",
                    payload.event_type,
                    ch.name,
                    ch.channel_type,
                    ok,
                )

        return {"ok": True, "results": results}

    # ---- policy matching -------------------------------------------------

    def _policy_matches(self, policy, payload: AlertPayload) -> bool:
        scope = policy.event_scope
        if scope == "threat":
            return payload.risk_score >= policy.min_risk_score
        if scope == "credential":
            # Only event types that are actually produced by the decoy/trap
            # routes; a stale name here silently dropped every credential
            # alert for policies scoped to it.
            return payload.event_type in {"credential_attempt", "decoy_fetch"}
        if scope == "system":
            return payload.event_type in {
                "c2_heartbeat", "c2_task_result", "c2_recruit_hit",
                "c2_bundle_generated", "c2_artifact_generated",
                "c2_managed_register",
                "service_started", "service_stopped",
                "login_failed_admin", "login_success_admin",
            }
        return False

    # ---- dedupe ----------------------------------------------------------

    def _is_duped(self, source_ip: str, event_type: str, channel_id: int) -> bool:
        key = (source_ip, event_type, channel_id)
        now = time.monotonic()
        with self._lock:
            last = self._seen.get(key)
            if last is not None and (now - last) < self._dedupe_ttl:
                return True
            self._seen[key] = now
            # prune stale entries (occasional)
            if len(self._seen) > 2000:
                cutoff = now - self._dedupe_ttl
                self._seen = {k: v for k, v in self._seen.items() if v >= cutoff}
            return False

    # ---- policy/channel cache --------------------------------------------

    def _load_policy_and_channels(self) -> tuple[list, dict[str, Any]]:
        now = time.monotonic()
        with self._cache_lock:
            if self._cache and (now - self._cache["ts"]) < self._cache_ttl:
                return self._cache["policies"], self._cache["channels"]

        # rebuild from DB
        from app.core.db import SessionLocal
        from app.models.notification import AlertChannel, AlertPolicy
        from sqlalchemy import select

        with SessionLocal() as db:
            policies = list(db.scalars(select(AlertPolicy).where(AlertPolicy.is_active.is_(True))).all())
            channels = list(db.scalars(select(AlertChannel).where(AlertChannel.is_active.is_(True))).all())
        channels_by_name = {c.name: c for c in channels}

        with self._cache_lock:
            self._cache = {"ts": now, "policies": policies, "channels": channels_by_name}
        return policies, channels_by_name

    # ---- channel dispatch ------------------------------------------------

    def _send_to_channel(self, channel, payload: AlertPayload,
                         *, dry_run: bool = False) -> bool:
        """Send to one channel. Returns True on success. Never raises."""
        try:
            adapter = _ADAPTERS.get(channel.channel_type)
            if adapter is None:
                logger.warning("unknown channel_type=%r for channel=%s, skipping",
                               channel.channel_type, channel.name)
                return False
            return adapter(channel.config_json, payload, dry_run=dry_run)
        except Exception:
            logger.exception("adapter %s failed for channel=%s",
                             channel.channel_type, channel.name)
            return False

# ---------------------------------------------------------------------------
# Adapter functions
# ---------------------------------------------------------------------------

def _send_webhook(config: dict, payload: AlertPayload, *, dry_run: bool = False) -> bool:
    """Generic webhook — POST JSON to config.url."""
    url = config.get("url")
    if not url:
        logger.warning("webhook channel missing url in config_json")
        return False
    body = {
        "event": payload.to_dict(),
        "channel": "webhook",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    headers = config.get("headers") or {}
    timeout = config.get("timeout", 5)
    if dry_run:
        logger.info("[dry-run] webhook POST to %s: %s", url, json.dumps(body, ensure_ascii=False)[:500])
        return True
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(url, json=body, headers=headers)
    if 200 <= resp.status_code < 300:
        logger.info("webhook sent ok to %s (status=%d)", url, resp.status_code)
        return True
    logger.warning("webhook failed to %s: status=%d body=%s",
                   url, resp.status_code, resp.text[:300])
    return False


def _send_dingtalk(config: dict, payload: AlertPayload, *, dry_run: bool = False) -> bool:
    """钉钉机器人 webhook。可选 HMAC-SHA256 签名。"""
    url = config.get("webhook_url")
    if not url:
        logger.warning("dingtalk channel missing webhook_url")
        return False

    sign_secret = config.get("sign_secret", "")
    at_all = config.get("at_all", False)

    # markdown message
    md_title = f"[警告] {payload.summary}"
    md_text = (
        f"### {md_title}\n\n"
        f"- **事件**: `{payload.event_type}`\n"
        f"- **决策**: `{payload.decision}` (score={payload.risk_score})\n"
        f"- **来源**: `{payload.source_ip}`\n"
        f"- **路径**: `{payload.method} {payload.path}`\n"
        f"- **信号**: {', '.join(f'`{s}`' for s in payload.signals[:5])}\n"
        f"- **时间**: {payload.timestamp.isoformat()}\n"
    )

    body: dict[str, Any] = {
        "msgtype": "markdown",
        "markdown": {"title": md_title, "text": md_text},
        "at": {"isAtAll": at_all},
    }

    at_mobiles = config.get("at_mobiles")
    if at_mobiles:
        body["at"]["atMobiles"] = at_mobiles

    # HMAC signature (required when sign_secret is set)
    if sign_secret:
        timestamp = str(int(time.time() * 1000))
        string_to_sign = f"{timestamp}\n{sign_secret}"
        hmac_code = hmac.new(
            sign_secret.encode("utf-8"),
            string_to_sign.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).digest()
        sign = quote_plus(base64.b64encode(hmac_code).decode("utf-8"))
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}timestamp={timestamp}&sign={sign}"

    if dry_run:
        logger.info("[dry-run] dingtalk POST to %s: %s",
                    config.get("webhook_url"), json.dumps(body, ensure_ascii=False)[:500])
        return True

    with httpx.Client(timeout=5) as client:
        resp = client.post(url, json=body)
    ok = 200 <= resp.status_code < 300
    if not ok:
        logger.warning("dingtalk failed: status=%d body=%s", resp.status_code, resp.text[:300])
    return ok


def _send_feishu(config: dict, payload: AlertPayload, *, dry_run: bool = False) -> bool:
    """飞书机器人 webhook。可选 HMAC-SHA256 签名。"""
    url = config.get("webhook_url")
    if not url:
        logger.warning("feishu channel missing webhook_url")
        return False

    sign_secret = config.get("sign_secret", "")

    card = {
        "header": {
            "title": {"tag": "plain_text", "content": f"[警告] {payload.summary}"},
            "template": "red" if payload.decision in ("block", "isolate") else "orange",
        },
        "elements": [
            {
                "tag": "div",
                "fields": [
                    {"is_short": True, "text": {"tag": "lark_md", "content": f"**事件**\n`{payload.event_type}`"}},
                    {"is_short": True, "text": {"tag": "lark_md", "content": f"**决策**\n`{payload.decision}` (score={payload.risk_score})"}},
                    {"is_short": True, "text": {"tag": "lark_md", "content": f"**来源**\n`{payload.source_ip}`"}},
                    {"is_short": True, "text": {"tag": "lark_md", "content": f"**路径**\n`{payload.method} {payload.path}`"}},
                ],
            },
            {
                "tag": "div",
                "text": {
                    "tag": "lark_md",
                    "content": f"**信号**: {', '.join(f'`{s}`' for s in payload.signals[:5])}",
                },
            },
        ],
    }

    body: dict[str, Any] = {
        "msg_type": "interactive",
        "card": card,
    }

    if sign_secret:
        timestamp = str(int(time.time()))
        string_to_sign = f"{timestamp}\n{sign_secret}"
        hmac_code = hmac.new(
            string_to_sign.encode("utf-8"),
            b"",
            digestmod=hashlib.sha256,
        ).digest()
        sign = base64.b64encode(hmac_code).decode("utf-8")
        body["timestamp"] = timestamp
        body["sign"] = sign

    if dry_run:
        logger.info("[dry-run] feishu POST to %s: %s",
                    config.get("webhook_url"), json.dumps(body, ensure_ascii=False)[:500])
        return True

    with httpx.Client(timeout=5) as client:
        resp = client.post(url, json=body)
    ok = 200 <= resp.status_code < 300
    if not ok:
        logger.warning("feishu failed: status=%d body=%s", resp.status_code, resp.text[:300])
    return ok


def _send_smtp(config: dict, payload: AlertPayload, *, dry_run: bool = False) -> bool:
    """SMTP email via stdlib smtplib (synchronous, called from daemon thread)."""
    host = config.get("host")
    port = int(config.get("port", 465))
    username = config.get("username", "")
    password = config.get("password", "")
    from_addr = config.get("from_addr", "")
    to_addrs = config.get("to_addrs") or []
    use_tls = config.get("use_tls", True)
    subject_tpl = config.get("subject_template", "[AgentCapture] {event_type}: {summary}")

    if not host or not from_addr or not to_addrs:
        logger.warning("smtp channel incomplete config: host=%s from=%s to=%s",
                       host, from_addr, to_addrs)
        return False

    subject = subject_tpl.format(**payload.to_dict())
    body = (
        f"AgentCapture Alert\n"
        f"{'=' * 40}\n"
        f"事件: {payload.event_type}\n"
        f"决策: {payload.decision} (score={payload.risk_score})\n"
        f"来源: {payload.source_ip}\n"
        f"路径: {payload.method} {payload.path}\n"
        f"信号: {', '.join(payload.signals)}\n"
        f"时间: {payload.timestamp.isoformat()}\n"
        f"摘要: {payload.summary}\n"
    )

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)

    if dry_run:
        logger.info("[dry-run] smtp would send to %s: %s", to_addrs, subject)
        return True

    try:
        if use_tls:
            smtp = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            smtp = smtplib.SMTP(host, port, timeout=10)
            smtp.starttls()
        if username:
            smtp.login(username, password)
        smtp.sendmail(from_addr, to_addrs, msg.as_string())
        smtp.quit()
        logger.info("smtp sent to %s: %s", to_addrs, subject)
        return True
    except Exception:
        logger.exception("smtp send failed to %s", to_addrs)
        return False


# ---------------------------------------------------------------------------
# Adapter registry
# ---------------------------------------------------------------------------

_ADAPTERS: dict[str, Any] = {
    "webhook": _send_webhook,
    "dingtalk": _send_dingtalk,
    "feishu": _send_feishu,
    "email": _send_smtp,
}
