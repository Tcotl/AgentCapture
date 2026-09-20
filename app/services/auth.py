import hashlib
import hmac
import secrets
from datetime import datetime, timezone

from fastapi import HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.login_log import LoginLog
from app.models.user import User

settings = get_settings()
ITERATIONS = 390_000


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        ITERATIONS,
    ).hex()
    return f"pbkdf2_sha256${ITERATIONS}${salt}${digest}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        scheme, iter_text, salt, expected = password_hash.split("$", 3)
    except ValueError:
        return False
    if scheme != "pbkdf2_sha256":
        return False
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        int(iter_text),
    ).hex()
    return hmac.compare_digest(digest, expected)


def ensure_bootstrap_admin(db: Session) -> None:
    stmt = select(func.count()).select_from(User)
    if int(db.scalar(stmt) or 0) > 0:
        return
    admin = User(
        username=settings.bootstrap_admin_username,
        password_hash=hash_password(settings.bootstrap_admin_password),
        name="System Administrator",
        email=settings.bootstrap_admin_email,
        role="admin",
        is_active=True,
    )
    db.add(admin)
    db.commit()


def authenticate_user(db: Session, username: str, password: str) -> User | None:
    user = db.scalar(select(User).where(User.username == username))
    if not user or not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    user.last_login_at = datetime.now(timezone.utc)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_user_by_id(db: Session, user_id: int) -> User | None:
    return db.get(User, user_id)


def require_user(request: Request, db: Session) -> User:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/admin/login"})
    user = get_user_by_id(db, int(user_id))
    if not user or not user.is_active:
        request.session.clear()
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/admin/login"})
    return user


def require_admin(request: Request, db: Session) -> User:
    user = require_user(request, db)
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin required")
    return user


def create_login_log(
    db: Session,
    *,
    user_id: int | None,
    username: str,
    login_status: str,
    ip_address: str | None,
    user_agent: str | None,
    fail_reason: str | None = None,
    browser: str | None = None,
    os_name: str | None = None,
    device_type: str | None = None,
) -> LoginLog:
    log = LoginLog(
        user_id=user_id,
        username=username,
        login_status=login_status,
        fail_reason=fail_reason,
        ip_address=ip_address,
        user_agent=user_agent,
        browser=browser,
        os_name=os_name,
        device_type=device_type,
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    # fire alert for login events
    if login_status in ("failed", "success"):
        from app.services.alert_dispatcher import AlertPayload, get_alert_dispatcher
        get_alert_dispatcher().start_event(AlertPayload(
            event_type=f"login_{login_status}_admin",
            source_ip=ip_address or "unknown",
            decision="observe",
            risk_score=0,
            signals=[f"login_{login_status}", "admin"],
            path="/admin/login",
            method="POST",
            summary=f"admin login {login_status}: {username} from {ip_address or 'unknown'}" + (f" ({fail_reason})" if fail_reason else ""),
            timestamp=datetime.now(timezone.utc),
        ))
    return log


def filter_login_logs(
    db: Session,
    *,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    username: str = "",
    login_status: str = "",
    ip_address: str = "",
    limit: int = 2000,
) -> list[LoginLog]:
    """Filtered, time-scoped query over ``LoginLog`` for list/export."""
    from sqlalchemy import desc

    stmt = select(LoginLog)
    if date_from:
        stmt = stmt.where(LoginLog.created_at >= date_from)
    if date_to:
        stmt = stmt.where(LoginLog.created_at < date_to)
    if username:
        stmt = stmt.where(LoginLog.username == username)
    if login_status:
        stmt = stmt.where(LoginLog.login_status == login_status)
    if ip_address:
        stmt = stmt.where(LoginLog.ip_address == ip_address)
    stmt = stmt.order_by(desc(LoginLog.created_at)).limit(limit)
    return list(db.scalars(stmt).all())
