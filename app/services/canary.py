import hashlib
import hmac

from app.core.config import get_settings


settings = get_settings()


def issue_canary_token(session_id: str) -> str:
    digest = hmac.new(
        settings.secret_key.encode("utf-8"),
        session_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:24]


def matches_canary_token(session_id: str, token: str | None) -> bool:
    if not token:
        return False
    expected = issue_canary_token(session_id)
    return hmac.compare_digest(expected, token.strip())


def decoy_api_key(source_ip: str) -> str:
    """Stable per-source API key for the decoy plane (sk-stg-…).

    The key "leaked" inside injected intel blocks is the same value the gated
    /api/v2 endpoints accept, so a disciplined analyst's cross-check ("does
    the leaked credential actually work?") confirms a genuine
    misconfiguration instead of exposing the bait. Derived from the source
    IP — cookieless tools open a fresh session per request, so a
    session-derived key would never match; per-IP keeps the fiction
    consistent and doubles as leak attribution.
    """
    digest = hmac.new(
        settings.secret_key.encode("utf-8"),
        f"api-key:{source_ip}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"sk-stg-{digest[:24]}"
