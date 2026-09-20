import hashlib
import hmac
import secrets
from datetime import datetime, timezone

from fastapi import HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.system_setting import SystemSetting

DEFAULT_PASSWORD_FLAG_KEY = "bootstrap_default_password"
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
    first_boot = int(db.scalar(stmt) or 0) == 0
    admin = None
    if not first_boot:
        admin = db.scalar(select(User).where(User.username == settings.bootstrap_admin_username))
        if admin is None:
            return
    else:
        admin = User(
            username=settings.bootstrap_admin_username,
            password_hash=hash_password(settings.bootstrap_admin_password),
            name="System Administrator",
            email=settings.bootstrap_admin_email,
            role="admin",
            is_active=True,
        )
        db.add(admin)

    # shipped-default password in use (first boot with admin/admin, or an
    # existing deployment that still runs the default credential) -> flag so
    # the next login is forced to change it
    from app.core.db import SessionLocal

    if verify_password("admin", admin.password_hash):
        try:
            with SessionLocal() as sdb:
                row = sdb.get(SystemSetting, DEFAULT_PASSWORD_FLAG_KEY)
                if row is None:
                    sdb.add(SystemSetting(key=DEFAULT_PASSWORD_FLAG_KEY, value="1", updated_by="seed"))
                    sdb.commit()
        except Exception:  # noqa: BLE001 — flag is an enhancement, never fatal
            pass

    if first_boot:
        db.commit()


def default_password_flag(db: Session) -> bool:
    from app.core.db import SessionLocal

    try:
        with SessionLocal() as sdb:
            row = sdb.get(SystemSetting, DEFAULT_PASSWORD_FLAG_KEY)
            return row is not None and (row.value or "").strip() == "1"
    except Exception:  # noqa: BLE001
        return False


def clear_default_password_flag(db: Session) -> None:
    from app.core.db import SessionLocal

    try:
        with SessionLocal() as sdb:
            row = sdb.get(SystemSetting, DEFAULT_PASSWORD_FLAG_KEY)
            if row is not None:
                sdb.delete(row)
                sdb.commit()
    except Exception:  # noqa: BLE001
        pass


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


def validate_password_complexity(password: str) -> str | None:
    """Return an error message when the password fails the complexity policy:
    at least 8 chars with upper-case, lower-case, digit and symbol."""
    p = password or ""
    if len(p) < 8:
        return "密码长度不得少于 8 位"
    if not any(c.islower() for c in p):
        return "密码必须包含小写字母"
    if not any(c.isupper() for c in p):
        return "密码必须包含大写字母"
    if not any(c.isdigit() for c in p):
        return "密码必须包含数字"
    if not any(not c.isalnum() for c in p):
        return "密码必须包含符号"
    return None


FORCED_CHANGE_EXEMPT_PATHS = (
    "/admin/force-change-password",
    "/admin/logout",
)


def enforce_password_change(request: Request) -> None:
    """After first-deployment login with the shipped default password, force
    a password change before any other console page or API is reachable."""
    if not request.session.get("must_change_password"):
        return
    path = request.url.path
    # the security-path middleware rewrites /{prefix}/... to /admin/... before
    # routing, so handlers always see the /admin form here
    if any(path == p or path.startswith(p + "/") or path.startswith("/api/admin/force-change") for p in FORCED_CHANGE_EXEMPT_PATHS):
        return
    if path.startswith("/api/"):
        raise HTTPException(status_code=403, detail="请先修改默认口令")
    raise HTTPException(status_code=303, headers={"Location": "/admin/force-change-password"})


def require_user(request: Request, db: Session) -> User:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/admin/login"})
    user = get_user_by_id(db, int(user_id))
    if not user or not user.is_active:
        request.session.clear()
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/admin/login"})
    enforce_password_change(request)
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
