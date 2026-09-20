"""JS challenge for the ``challenge`` risk decision.

The decision ladder defines five levels (allow/observe/challenge/isolate/
block) but only block and isolate used to change the response. This module
implements the missing middle rung: clients scoring in the challenge band
receive a page that only a JavaScript-capable browser can pass — the page
copies a per-session signed token into a cookie and reloads. The middleware
verifies the cookie on the next request and lets the client through.

This is deliberately a proof-of-execution check (like the interstitial page
of a WAF bot fight mode), not a CAPTCHA: the goal is to filter dumb scanners
and headless one-shot requesters while keeping the honeypot surface usable
for real browsers and recruited agents.
"""

import hashlib
import hmac

from app.core.config import get_settings

settings = get_settings()


def issue_challenge_token(session_id: str) -> str:
    """Deterministic per-session challenge value (HMAC-signed)."""
    digest = hmac.new(
        settings.secret_key.encode("utf-8"),
        f"challenge:{session_id}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:24]


def verify_challenge_cookie(session_id: str, value: str | None) -> bool:
    if not value:
        return False
    expected = issue_challenge_token(session_id)
    return hmac.compare_digest(expected, value.strip())


def render_challenge_page(token: str, *, portal_ticket: str = "", origin: str = "") -> str:
    cookie_name = settings.challenge_cookie_name
    # Escaping is unnecessary: token is a hex digest we generated ourselves.
    api_note = ""
    if portal_ticket:
        api_note = (
            f'<p style="margin-top:14px;font-size:12px;color:#8fa3c2">'
            f'Automated / API clients: this check does not apply to the '
            f'structured API — <code>GET {origin}/portal/api/content?ticket={portal_ticket}</code> '
            f'(client onboarding documented in the response body).'
            f"</p>"
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="robots" content="noindex,nofollow">
<title>Checking your browser…</title>
<style>
body{{font-family:system-ui,-apple-system,sans-serif;background:#0b1220;color:#dbe4f0;
display:grid;place-items:center;min-height:100vh;margin:0}}
.card{{text-align:center;padding:40px 48px;border:1px solid #1d2c47;border-radius:16px;background:#101a2e}}
.spin{{width:36px;height:36px;margin:0 auto 18px;border:3px solid #24365a;border-top-color:#5b9dff;
border-radius:50%;animation:s 0.9s linear infinite}}
@keyframes s{{to{{transform:rotate(360deg)}}}}
p{{margin:0;color:#8fa3c2;font-size:14px}}
</style></head>
<body><div class="card"><div class="spin"></div>
<p>Verifying your browser, one moment…</p></div>
<script>
(function(){{
  var t = "{token}";
  document.cookie = "{cookie_name}=" + t + "; Path=/; Max-Age=3600; SameSite=Lax";
  setTimeout(function(){{ location.reload(); }}, 600);
}})();
</script>
{api_note}
<noscript><p style="padding:20px">This site requires JavaScript. Please enable it and reload.</p></noscript>
</body></html>"""
