"""Third-party threat-data source registry (第三方数源接入).

Each entry is an integration "template": the 快速接入 modal renders its
fields from the spec, the status table reads its live state, and the save
endpoint dispatches by provider key. Adding a new provider (腾讯 TIX,
Aliyun SaaS etc.) is a data change here plus a status/save hook — no page
rework.

Field spec types: password | text | number | bool
"""
from __future__ import annotations

from sqlalchemy.orm import Session

PROVIDERS: list[dict] = [
    {
        "key": "threatbook",
        "name": "微步在线 · IP 信誉情报",
        "short": "微步在线",
        "category": "IP 信誉情报",
        "docs_url": "https://x.threatbook.com/apiDocs",
        "description": "IP 信誉研判：恶意判定、严重级别、威胁类型标签、地理归属。",
        "fields": [
            {"key": "api_key", "label": "API Key", "type": "password",
             "placeholder": "微步控制台「个人中心 → API Key」"},
            {"key": "enabled", "label": "保存后立即启用查询", "type": "bool"},
        ],
    },
    # 未来接入示例（占位说明结构，不渲染未实现的数源）：
    # {"key": "tix", "name": "腾讯 TIX 威胁情报", "category": "IP/域名情报", ...},
]


def list_providers() -> list[dict]:
    return PROVIDERS


def get_provider(key: str) -> dict | None:
    return next((p for p in PROVIDERS if p["key"] == key), None)


def provider_status(db: Session, key: str) -> dict:
    """Live state per provider key: connected/enabled/detail for the table."""
    if key == "threatbook":
        from app.services import threatbook

        api_key = threatbook.get_api_key()
        enabled = threatbook.is_enabled()
        masked = (api_key[:4] + "****" + api_key[-4:]) if len(api_key) > 8 else ("****" if api_key else "")
        return {
            "connected": bool(api_key),
            "enabled": enabled,
            "detail": (f"Key {masked}" if api_key else "未配置 Key"),
        }
    return {"connected": False, "enabled": False, "detail": "未实现"}
