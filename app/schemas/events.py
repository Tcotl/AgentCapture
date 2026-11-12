from typing import Any

from pydantic import BaseModel, ConfigDict


class BeaconPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    url: str
    title: str | None = None
    referrer: str | None = None
    tz: str | None = None
    lang: str | None = None
    screen: dict[str, Any] | None = None
    webdriver: bool | None = None
    headless_hint: bool | None = None
    dwell_ms: int | None = None


class ReconPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    url: str
    session_id: str | None = None
    webrtc_ips: list[str] = []
    canvas_hash: str | None = None
    webgl_vendor: str | None = None
    webgl_renderer: str | None = None
    plugins: list[str] = []
    fonts: list[str] = []
    timezone: str | None = None
    language: str | None = None
    platform: str | None = None
    cores: int | None = None
    memory_gb: int | None = None
    screen_width: int | None = None
    screen_height: int | None = None
    pixel_ratio: float | None = None
    touch_points: int | None = None
    webdriver: bool | None = None
    headless_hint: bool | None = None


class AgentInteractionPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    agent_type: str | None = None
    injected_prompts: list[str] = []
    agent_response: str | None = None
    revealed_ip: str | None = None
    revealed_system_info: dict[str, Any] | None = None
    injection_success: bool = False
