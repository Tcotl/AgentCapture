from collections.abc import Generator
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy import event as sa_event
from sqlalchemy import inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings

settings = get_settings()
APP_STARTED_AT = datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine_kwargs: dict = {"connect_args": connect_args}
if not settings.database_url.startswith("sqlite"):
    # Network databases (e.g. PostgreSQL via postgresql+psycopg://...) get
    # stale-connection detection; SQLite does not need it.
    engine_kwargs["pool_pre_ping"] = True
engine = create_engine(settings.database_url, **engine_kwargs)

if settings.database_url.startswith("sqlite"):
    @sa_event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):
        """Concurrency hardening for the per-request write path.

        The capture middleware commits an event on every request while C2 and
        node heartbeats write in parallel threads; the default rollback-journal
        mode turns that into frequent 'database is locked' errors.
        """
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from app.models.api_token import ApiToken  # noqa: F401
    from app.models.c2_agent import C2Agent  # noqa: F401
    from app.models.c2_listener import C2Listener  # noqa: F401
    from app.models.c2_task import C2Task  # noqa: F401
    from app.models.credential import CredentialObservation  # noqa: F401
    from app.models.decoy import DecoyDeployment, DecoyTemplate  # noqa: F401
    from app.models.event import Event  # noqa: F401
    from app.models.execution import ExecutionHistory  # noqa: F401
    from app.models.honeypot_session import HoneypotSession  # noqa: F401
    from app.models.intel import ThreatIntelEntry  # noqa: F401
    from app.models.internet_system import InternetSystem  # noqa: F401
    from app.models.isolation import IsolationEntry  # noqa: F401
    from app.models.jsonp_template import JsonpTemplate  # noqa: F401
    from app.models.login_log import LoginLog  # noqa: F401
    from app.models.managed import (  # noqa: F401
        ManagedEvidence,
        ManagedHost,
        ManagedListener,
        ManagedSession,
        ManagedTask,
    )
    from app.models.node import Node  # noqa: F401
    from app.models.node_runtime import NodeHeartbeat, NodeTask  # noqa: F401
    from app.models.notification import AlertChannel, AlertPolicy  # noqa: F401
    from app.models.portal_config import PortalConfig  # noqa: F401
    from app.models.counter_surface import CounterSurface  # noqa: F401
    from app.models.prompt_injection import PromptInjectionTemplate  # noqa: F401
    from app.models.service import ServiceCatalog, ServiceTemplate  # noqa: F401
    from app.models.user import User  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _ensure_legacy_columns()


def _ensure_legacy_columns() -> None:
    """Keep local SQLite databases compatible when the demo schema evolves."""
    if not settings.database_url.startswith("sqlite"):
        return
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    if "decoy_templates" not in table_names:
        return
    existing = {col["name"] for col in inspector.get_columns("decoy_templates")}
    migrations = {
        "decoy_type": "ALTER TABLE decoy_templates ADD COLUMN decoy_type VARCHAR(32) DEFAULT 'credential'",
        "route_path": "ALTER TABLE decoy_templates ADD COLUMN route_path VARCHAR(255) DEFAULT ''",
        "exposure_channel": "ALTER TABLE decoy_templates ADD COLUMN exposure_channel VARCHAR(80) DEFAULT 'manual'",
        "bind_route_template_id": "ALTER TABLE decoy_templates ADD COLUMN bind_route_template_id INTEGER",
        "bind_credential_template_id": "ALTER TABLE decoy_templates ADD COLUMN bind_credential_template_id INTEGER",
        "metadata_json": "ALTER TABLE decoy_templates ADD COLUMN metadata_json JSON DEFAULT '{}'",
    }
    with engine.begin() as conn:
        for column, ddl in migrations.items():
            if column not in existing:
                conn.execute(text(ddl))

    # counter_surfaces.config_json (added after first release of the table)
    if "counter_surfaces" in table_names:
        cs_cols = {col["name"] for col in inspector.get_columns("counter_surfaces")}
        if "config_json" not in cs_cols:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE counter_surfaces ADD COLUMN config_json JSON DEFAULT '{}'")
                )

    # service_catalog.status
    if "service_catalog" in table_names:
        sc_cols = {col["name"] for col in inspector.get_columns("service_catalog")}
        if "status" not in sc_cols:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "ALTER TABLE service_catalog ADD COLUMN status VARCHAR(16) DEFAULT 'stopped'"
                    )
                )

    # events.template_id / node_id / deploy_port / deploy_route
    if "events" in table_names:
        ev_cols = {col["name"] for col in inspector.get_columns("events")}
        ev_migrations = {
            "template_id": "ALTER TABLE events ADD COLUMN template_id INTEGER",
            "node_id": "ALTER TABLE events ADD COLUMN node_id INTEGER",
            "deploy_port": "ALTER TABLE events ADD COLUMN deploy_port INTEGER",
            "deploy_route": "ALTER TABLE events ADD COLUMN deploy_route VARCHAR(255)",
        }
        with engine.begin() as conn:
            for column, ddl in ev_migrations.items():
                if column not in ev_cols:
                    conn.execute(text(ddl))

    # c2_listeners.registration_token / description / created_by
    # (C2 listener token system ported from PentestManusWeb c2_control)
    if "c2_listeners" in table_names:
        ls_cols = {col["name"] for col in inspector.get_columns("c2_listeners")}
        ls_migrations = {
            "registration_token": "ALTER TABLE c2_listeners ADD COLUMN registration_token VARCHAR(128)",
            "description": "ALTER TABLE c2_listeners ADD COLUMN description TEXT",
            "created_by": "ALTER TABLE c2_listeners ADD COLUMN created_by VARCHAR(64)",
        }
        with engine.begin() as conn:
            for column, ddl in ls_migrations.items():
                if column not in ls_cols:
                    conn.execute(text(ddl))

    # c2_agents.listener_id (agent-to-listener binding)
    if "c2_agents" in table_names:
        ag_cols = {col["name"] for col in inspector.get_columns("c2_agents")}
        if "listener_id" not in ag_cols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE c2_agents ADD COLUMN listener_id INTEGER"))

    # Indexes for hot-path filters. Columns added through the ALTER TABLE
    # path above never receive the model's declared indexes, and the
    # (session_id|source_ip|event_type, created_at) composite indexes the
    # per-request velocity counters need do not exist on pre-existing
    # databases at all. CREATE INDEX IF NOT EXISTS keeps both worlds aligned.
    legacy_indexes = (
        "CREATE INDEX IF NOT EXISTS ix_events_session_created ON events (session_id, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_events_ip_created ON events (source_ip, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_events_type_created ON events (event_type, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_events_template_id ON events (template_id)",
        "CREATE INDEX IF NOT EXISTS ix_events_node_id ON events (node_id)",
        "CREATE INDEX IF NOT EXISTS ix_events_site_created ON events (site_id, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_decoy_templates_decoy_type ON decoy_templates (decoy_type)",
        "CREATE INDEX IF NOT EXISTS ix_c2_agents_listener_id ON c2_agents (listener_id)",
        ("CREATE INDEX IF NOT EXISTS ix_credential_observations_session"
         " ON credential_observations (session_id)"),
        ("CREATE INDEX IF NOT EXISTS ix_node_heartbeats_node_created"
         " ON node_heartbeats (node_id, created_at)"),
    )
    with engine.begin() as conn:
        for ddl in legacy_indexes:
            try:
                conn.execute(text(ddl))
            except Exception:  # table missing on a very old DB — create_all covers fresh ones
                pass
