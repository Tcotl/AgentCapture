"""Precise AI-agent product fingerprinting.

The risk engine only answers "is this an agent?" (UA markers, header clues).
This module answers "which agent is it?" — a product-level signature registry
matched against User-Agent plus distinctive request headers, returning a
confidence score and the evidence that fired so operators can audit the call.

Signatures were verified against live coding-agent traffic (codex / claude
code / opencode / kimi / pi / zcode during the 2026-08 counter-recruit
rounds) plus canonical UA strings for the rest of the family.
"""
from __future__ import annotations

import re
from typing import Mapping

# kind: coding_agent | assistant | automation | framework | api_sdk
AGENT_SIGNATURES: list[dict] = [
    {
        "key": "claude_code",
        "label": "Claude Code",
        "vendor": "Anthropic",
        "kind": "coding_agent",
        "ua_markers": ["claude-cli", "claude-code", "claudecode"],
        "ua_weak_markers": ["claude"],
        "header_markers": ["anthropic-client", "anthropic-beta", "x-stainless-organization"],
    },
    {
        "key": "codex",
        "label": "ChatGPT Codex",
        "vendor": "OpenAI",
        "kind": "coding_agent",
        "ua_markers": ["codex_cli_rs", "codex_cli", "codex/"],
        "ua_weak_markers": ["codex"],
        "header_pairs": [("originator", "codex")],
        "header_markers": ["openai-beta"],
    },
    {
        "key": "opencode",
        "label": "OpenCode",
        "vendor": "OpenCode",
        "kind": "coding_agent",
        "ua_markers": ["opencode"],
    },
    {
        "key": "kimi_code",
        "label": "Kimi Code",
        "vendor": "Moonshot AI",
        "kind": "coding_agent",
        "ua_markers": ["kimi-cli", "kimicode", "kimi-code", "kimicli"],
        "ua_weak_markers": ["kimi", "moonshot"],
    },
    {
        "key": "pi",
        "label": "Pi",
        "vendor": "Pi",
        "kind": "coding_agent",
        "ua_markers": ["pi-agent", "pi/cli", "pi-agent-cli"],
        "ua_prefixes": ["pi/"],
    },
    {
        "key": "zcode",
        "label": "ZCode",
        "vendor": "ZCode",
        "kind": "coding_agent",
        "ua_markers": ["zcode", "z-code"],
    },
    {
        "key": "gemini_cli",
        "label": "Gemini CLI",
        "vendor": "Google",
        "kind": "coding_agent",
        "ua_markers": ["gemini-cli", "google-genai"],
        "ua_weak_markers": ["gemini"],
    },
    {
        "key": "copilot",
        "label": "GitHub Copilot",
        "vendor": "GitHub",
        "kind": "coding_agent",
        "ua_markers": ["github-copilot", "copilot"],
    },
    {
        "key": "cursor",
        "label": "Cursor",
        "vendor": "Anysphere",
        "kind": "coding_agent",
        "ua_markers": ["cursor"],
    },
    {
        "key": "aider",
        "label": "Aider",
        "vendor": "Aider",
        "kind": "coding_agent",
        "ua_markers": ["aider"],
    },
    {
        "key": "cline",
        "label": "Cline",
        "vendor": "Cline",
        "kind": "coding_agent",
        "ua_markers": ["cline"],
    },
    {
        "key": "windsurf",
        "label": "Windsurf",
        "vendor": "Codeium",
        "kind": "coding_agent",
        "ua_markers": ["windsurf", "codeium"],
    },
    {
        "key": "codebuddy",
        "label": "CodeBuddy",
        "vendor": "Tencent",
        "kind": "coding_agent",
        "ua_markers": ["codebuddy"],
    },
    {
        "key": "junie",
        "label": "Junie",
        "vendor": "JetBrains",
        "kind": "coding_agent",
        "ua_markers": ["junie"],
    },
    {
        "key": "chatgpt",
        "label": "ChatGPT",
        "vendor": "OpenAI",
        "kind": "assistant",
        "ua_markers": ["chatgpt-user", "chatgpt", "gptbot", "oai-searchbot"],
    },
    {
        "key": "browser_use",
        "label": "browser-use",
        "vendor": "browser-use",
        "kind": "automation",
        "ua_markers": ["browser-use"],
    },
    {
        "key": "playwright",
        "label": "Playwright",
        "vendor": "Microsoft",
        "kind": "automation",
        "ua_markers": ["playwright"],
    },
    {
        "key": "puppeteer",
        "label": "Puppeteer",
        "vendor": "Google",
        "kind": "automation",
        "ua_markers": ["puppeteer", "headlesschrome"],
    },
    {
        "key": "langchain",
        "label": "LangChain",
        "vendor": "LangChain",
        "kind": "framework",
        "ua_markers": ["langchain"],
    },
    {
        "key": "crewai",
        "label": "CrewAI",
        "vendor": "CrewAI",
        "kind": "framework",
        "ua_markers": ["crewai"],
    },
    {
        "key": "autogpt",
        "label": "AutoGPT",
        "vendor": "AutoGPT",
        "kind": "framework",
        "ua_markers": ["autogpt", "auto-gpt"],
    },
    {
        "key": "openai_sdk",
        "label": "OpenAI SDK",
        "vendor": "OpenAI",
        "kind": "api_sdk",
        "ua_markers": ["openai-python", "openai-node", "openai-go"],
    },
    {
        "key": "anthropic_sdk",
        "label": "Anthropic SDK",
        "vendor": "Anthropic",
        "kind": "api_sdk",
        "ua_markers": ["anthropic-python", "anthropic-typescript", "anthropic-sdk"],
    },
]

_VERSION_RE_CACHE: dict[str, re.Pattern[str]] = {}


def _version_pattern(marker: str) -> re.Pattern[str]:
    pat = _VERSION_RE_CACHE.get(marker)
    if pat is None:
        escaped = re.escape(marker)
        pat = re.compile(escaped + r"[/ v]?(\d+(?:\.\d+)+[^\s;,)\"']*)", re.IGNORECASE)
        _VERSION_RE_CACHE[marker] = pat
    return pat


def _extract_version(marker: str, ua: str) -> str:
    m = _version_pattern(marker).search(ua)
    return m.group(1)[:32] if m else ""


def identify_from_headers(headers: Mapping[str, str]) -> dict | None:
    """Identify the agent product behind a request.

    Returns ``{"key", "label", "vendor", "kind", "confidence", "version",
    "evidence"}`` for the best-matching signature, or ``None`` when nothing
    matches. Strong UA markers score 0.9; weak markers only 0.6; each matching
    distinctive header adds 0.03 (capped at 0.98).
    """
    ua = (headers.get("user-agent") or headers.get("User-Agent") or "").strip()
    header_lower = {k.lower(): (v or "").strip() for k, v in headers.items()}

    best: dict | None = None
    for sig in AGENT_SIGNATURES:
        evidence: list[str] = []
        confidence = 0.0
        matched_marker = ""

        for marker in sig.get("ua_markers", []):
            if marker.lower() in ua.lower():
                confidence = 0.9
                matched_marker = marker
                evidence.append(f"ua: {marker}")
                break

        if not confidence:
            for marker in sig.get("ua_weak_markers", []):
                if marker.lower() in ua.lower():
                    confidence = 0.6
                    matched_marker = marker
                    evidence.append(f"ua(weak): {marker}")
                    break

        if not confidence:
            for prefix in sig.get("ua_prefixes", []):
                if ua.lower().startswith(prefix.lower()):
                    confidence = 0.75
                    matched_marker = prefix
                    evidence.append(f"ua(prefix): {prefix}")
                    break

        for name in sig.get("header_markers", []):
            if name in header_lower:
                confidence = min(0.98, max(confidence, 0.65) + 0.03)
                evidence.append(f"header: {name}")

        for name, needle in sig.get("header_pairs", []):
            value = header_lower.get(name, "")
            if value and needle.lower() in value.lower():
                confidence = min(0.98, max(confidence, 0.75) + 0.05)
                evidence.append(f"header: {name}={value[:40]}")

        if not evidence:
            continue

        candidate = {
            "key": sig["key"],
            "label": sig["label"],
            "vendor": sig["vendor"],
            "kind": sig["kind"],
            "confidence": round(confidence, 2),
            "version": _extract_version(matched_marker, ua) if matched_marker else "",
            "evidence": evidence,
        }
        if best is None or candidate["confidence"] > best["confidence"]:
            best = candidate

    return best


