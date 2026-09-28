"""Display-time formatting helpers.

Events are stored timezone-aware in UTC. Operators expect wall-clock times
in the server's local timezone (deployments set TZ accordingly, e.g.
Asia/Shanghai on the CN test host), so every rendered timestamp goes
through `fmt_dt` — registered as the Jinja `dt` filter — instead of
calling `.strftime` on the raw UTC value.
"""
from datetime import datetime, timezone

DEFAULT_FORMAT = "%Y-%m-%d %H:%M:%S"


def fmt_dt(value, fmt: str = DEFAULT_FORMAT, none_text: str = "—") -> str:
    """Render a datetime (or ISO string) in the server-local timezone."""
    if value is None or value == "":
        return none_text
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    if not isinstance(value, datetime):
        return str(value)
    if value.tzinfo is None:
        # Naive values in the database are UTC by convention.
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone().strftime(fmt)


def register(template_env) -> None:
    """Attach the `dt` filter to a Jinja2 environment."""
    template_env.filters["dt"] = fmt_dt
