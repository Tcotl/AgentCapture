from functools import lru_cache
from pathlib import Path

from pydantic import computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Agent-Capture-Honeypot"
    app_env: str = "dev"
    host: str = "0.0.0.0"
    port: int = 4877
    # Console security access path. The admin console answers on
    # /{admin_access_path}/... while /admin is answered with 404 so the
    # console is not discoverable at the well-known location. DB value
    # (system_settings.admin_access_path, editable from 系统设置) wins.
    admin_access_path: str = "agentcapture"
    site_id: str = "local-demo"
    database_url: str = "sqlite:///./agent_capture.db"
    secret_key: str = "change-me-before-production"
    session_cookie_name: str = "ach_sid"
    admin_session_cookie_name: str = "ach_admin"
    canary_header_name: str = "X-Agent-Canary"
    injector_enabled: bool = True
    collect_path: str = "/collect/beacon"
    knowledge_base_root: str = "./data/knowledge_base"
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = "admin"
    bootstrap_admin_email: str = "admin@example.local"
    public_api_default_limit: int = 100
    agent_injection_enabled: bool = True
    agent_injection_aggressiveness: str = "medium"
    recon_jsonp_enabled: bool = True
    recon_beacon_path: str = "/recon/fingerprint"
    payload_callback_host: str = ""
    c2_enabled: bool = True
    c2_poll_interval: int = 5
    c2_register_max_per_ip_hour: int = 10  # cap anonymous C2 agent registrations
    node_auth_token: str = ""  # when set, node endpoints require X-Node-Token
    alerts_enabled: bool = False  # true = real sends; false = dry-run (log only)

    # Trust X-Forwarded-For / X-Real-IP for client IP resolution. Keep false
    # unless deployed behind a trusted reverse proxy: an untrusted client can
    # otherwise rotate spoofed IPs to dodge velocity counters or forge a
    # whitelisted source IP (which forces decision=allow).
    trust_proxy_headers: bool = False
    # Decision ladder enforcement
    challenge_enabled: bool = True  # serve a JS challenge for decision=challenge
    challenge_cookie_name: str = "ach_chal"
    isolation_ttl_minutes: int = 60  # persistence window for isolate/canary-echo
    # /console/events leaks signals/payloads; require an admin session unless
    # a deployment explicitly opts in (e.g. wall-mounted SOC screens).
    console_public: bool = False
    # Data retention (days; 0 disables the cleanup for that table)
    event_retention_days: int = 30
    heartbeat_retention_days: int = 7
    login_log_retention_days: int = 90
    honeypot_session_retention_days: int = 60

    # Interactive SSH honeypot (paramiko). When the dependency is missing the
    # ssh service silently degrades to the legacy banner-level handler.
    ssh_accept_all: bool = True  # accept any password; capture never lock out
    ssh_hostname: str = "web-prod-01"  # hostname shown inside the fake shell

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def knowledge_base_root_path(self) -> Path:
        return Path(self.knowledge_base_root).resolve()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
