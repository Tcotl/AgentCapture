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
