import hashlib
import secrets
from datetime import datetime, timezone

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models.api_token import ApiToken


def generate_api_token(name: str) -> tuple[str, str, str]:
    raw = f"ach_{secrets.token_urlsafe(24)}"
    token_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    prefix = raw[:12]
    return raw, token_hash, prefix


def create_api_token(db: Session, *, name: str, permissions: list[str]) -> tuple[ApiToken, str]:
    raw, token_hash, prefix = generate_api_token(name)
    item = ApiToken(name=name, token_hash=token_hash, token_prefix=prefix, permissions_json=permissions)
    db.add(item)
    db.commit()
    db.refresh(item)
    return item, raw


def list_api_tokens(db: Session) -> list[ApiToken]:
    stmt = select(ApiToken).order_by(desc(ApiToken.created_at))
    return list(db.scalars(stmt).all())


def resolve_api_token(db: Session, raw_token: str | None) -> ApiToken | None:
    if not raw_token:
        return None
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    item = db.scalar(select(ApiToken).where(ApiToken.token_hash == token_hash, ApiToken.is_active.is_(True)))
    if not item:
        return None
    item.last_used_at = datetime.now(timezone.utc)
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


def api_token_has_permission(token: ApiToken, permission: str) -> bool:
    perms = token.permissions_json or []
    return "*" in perms or permission in perms
