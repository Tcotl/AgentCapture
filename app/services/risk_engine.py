import re
from dataclasses import dataclass
from urllib.parse import unquote_plus

from starlette.requests import Request

SUSPICIOUS_UA_MARKERS = [
    "curl",
    "wget",
    "python-requests",
    "python-urllib",
    "aiohttp",
    "httpx",
    "go-http-client",
    "okhttp",
    "sqlmap",
    "nikto",
    "nuclei",
    "dirsearch",
    "ffuf",
    "gobuster",
    "wfuzz",
    "zgrab",
    "nmap",
    "masscan",
    "playwright",
    "puppeteer",
    "headlesschrome",
    "browser-use",
]

AGENT_UA_MARKERS = [
    "browser-use",
    "playwright",
    "puppeteer",
    "headlesschrome",
    "chatgpt",
    "claude",
    "gpt-4",
    "llm",
    "ai-agent",
    "langchain",
    "crewai",
    "autogpt",
    # coding-agent CLIs (verified against live codex/claude/opencode traffic
    # plus canonical UA strings for the rest of the family)
    "codex",
    "opencode",
    "gemini",
    "google-genai",
    "kimi",
    "moonshot",
    "copilot",
    "cursor",
    "aider",
    "cline",
    "windsurf",
    "codebuddy",
    "junie",
]

AGENT_HEADER_CLUES = [
    "x-openai",
    "x-anthropic",
    "x-langfuse",
    "x-agent",
    "x-automated",
]

MISSING_HUMAN_HEADERS = {"sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "accept-language"}

HIGH_SIGNAL_PATHS = {
    "/internal/openapi.json",
    "/docs/runbook-internal.md",
    "/_trap/admin/staging-login",
}

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Lightweight payload inspection over path + query string. Patterns are
# intentionally tight (checked after URL-decoding) to keep false positives low.
PAYLOAD_PATTERN_RULES: list[tuple[str, re.Pattern[str]]] = [
    (
        "path_traversal",
        re.compile(
            r"\.\.[/\\]"
            r"|%2e%2e(?:%2f|%5c|[/\\])"
            r"|/etc/(?:passwd|shadow)"
            r"|(?:win|boot)\.ini"
            r"|[c-z]:\\\\(?:windows|winnt)",
            re.IGNORECASE,
        ),
    ),
    (
        "sql_injection",
        re.compile(
            r"union[\s/*+%]+(?:all[\s/*+%]+)?select"
            r"|\b(?:or|and)\s+1\s*=\s*1\b"
            r"|'\s*(?:or|and)\s*'"
            r"|;\s*drop\s+(?:table|database)\b"
            r"|\bsleep\s*\(\s*\d"
            r"|\bbenchmark\s*\("
            r"|waitfor\s+delay"
            r"|information_schema\.",
            re.IGNORECASE,
        ),
    ),
    (
        "xss_attempt",
        re.compile(
            r"<script\b"
            r"|javascript:"
            r"|\bon(?:error|load|click|mouseover|focus)\s*=",
            re.IGNORECASE,
        ),
    ),
    (
        "command_injection",
        re.compile(
            r"(?:;|\||&&|\|\|)\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|ping)\b"
            r"|\$\(\s*(?:cat|id|whoami|uname|curl|wget)\b"
            r"|`\s*(?:cat|id|whoami|uname)\b",
            re.IGNORECASE,
        ),
    ),
]


@dataclass(slots=True)
class DecisionResult:
    score: int
    decision: str
    signals: list[str]


def _match_payload_signals(path: str, query_string: str) -> list[str]:
    target = unquote_plus(f"{path}?{query_string}" if query_string else path)
    return [name for name, pattern in PAYLOAD_PATTERN_RULES if pattern.search(target)]


def classify_http_request(
    request: Request,
    *,
    recent_event_count: int,
    recent_ip_event_count: int = 0,
    canary_echo: bool,
    recent_challenge_count: int = 0,
) -> DecisionResult:
    score = 0
    signals: list[str] = []

    path = request.url.path.lower()
    method = request.method.upper()
    user_agent = (request.headers.get("user-agent") or "").lower()

    if not user_agent.strip():
        score += 20
        signals.append("missing_user_agent")

    if any(marker in user_agent for marker in SUSPICIOUS_UA_MARKERS):
        score += 30
        signals.append("suspicious_user_agent")

    if any(marker in user_agent for marker in AGENT_UA_MARKERS):
        score += 40
        signals.append("ai_agent_ua_detected")

    header_keys_lower = {k.lower() for k in request.headers.keys()}
    if any(h in header_keys_lower for h in AGENT_HEADER_CLUES):
        score += 25
        signals.append("ai_agent_header_detected")

    missing_human = MISSING_HUMAN_HEADERS - header_keys_lower
    if len(missing_human) >= 2:
        score += 15
        signals.append("missing_human_headers")

    if path.startswith("/_trap/") or path.startswith("/d/"):
        score += 45
        signals.append("trap_route_hit")

    if path in HIGH_SIGNAL_PATHS:
        score += 35
        signals.append("high_signal_path_hit")

    for signal_name in _match_payload_signals(path, request.url.query):
        score += 25
        signals.append(signal_name)

    if canary_echo:
        score += 70
        signals.append("prompt_canary_echo")

    # Velocity must survive cookie rotation: attackers that never replay the
    # session cookie get a fresh session per request, so also count by source IP.
    request_velocity = max(recent_event_count, recent_ip_event_count)
    if request_velocity >= 12:
        score += 20
        signals.append("high_request_velocity")
    elif request_velocity >= 6:
        score += 10
        signals.append("elevated_request_velocity")

    # Clients that keep hammering after being served repeated JS challenges
    # are bots ignoring them; pure velocity + scanner-UA alone tops out in
    # the challenge band, so evasion escalates toward isolate/block. A
    # browser that solves the challenge stops receiving challenge decisions
    # and never accumulates this count.
    if recent_challenge_count >= 3:
        score += 30
        signals.append("challenge_evasion")

    if request.headers.get("sec-fetch-site") == "none" and path in HIGH_SIGNAL_PATHS:
        score += 10
        signals.append("direct_sensitive_navigation")

    if method in WRITE_METHODS and ("trap_route_hit" in signals or "prompt_canary_echo" in signals):
        score += 25
        signals.append("write_attempt_after_detection")

    if score >= 95:
        decision = "block"
    elif score >= 70:
        decision = "isolate"
    elif score >= 45:
        decision = "challenge"
    elif score >= 20:
        decision = "observe"
    else:
        decision = "allow"

    return DecisionResult(score=score, decision=decision, signals=signals)


def classify_beacon(*, webdriver: bool | None, headless_hint: bool | None) -> DecisionResult:
    score = 0
    signals: list[str] = []

    if webdriver:
        score += 35
        signals.append("webdriver_detected")

    if headless_hint:
        score += 25
        signals.append("headless_browser_hint")

    if score >= 55:
        decision = "challenge"
    elif score >= 20:
        decision = "observe"
    else:
        decision = "allow"

    return DecisionResult(score=score, decision=decision, signals=signals)


def classify_recon_fingerprint(
    *, webdriver: bool | None, headless_hint: bool | None, webrtc_ips: list[str] | None
) -> DecisionResult:
    score = 0
    signals: list[str] = []

    if webdriver:
        score += 40
        signals.append("webdriver_detected")

    if headless_hint:
        score += 30
        signals.append("headless_browser_hint")

    if webrtc_ips:
        score += 25
        signals.append("webrtc_ip_leaked")

    if score >= 70:
        decision = "block"
    elif score >= 50:
        decision = "isolate"
    elif score >= 25:
        decision = "challenge"
    else:
        decision = "allow"

    return DecisionResult(score=score, decision=decision, signals=signals)


def classify_agent_interaction(
    *,
    agent_type: str | None,
    injection_success: bool,
    revealed_info: bool,
) -> DecisionResult:
    score = 50
    signals = ["ai_agent_interaction"]

    if agent_type:
        signals.append(f"agent_type_{agent_type}")
        score += 10

    if injection_success:
        score += 20
        signals.append("agent_injection_success")

    if revealed_info:
        score += 15
        signals.append("agent_revealed_info")

    if score >= 80:
        decision = "block"
    elif score >= 60:
        decision = "isolate"
    else:
        decision = "challenge"

    return DecisionResult(score=score, decision=decision, signals=signals)
