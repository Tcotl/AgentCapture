from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.prompt_injection import PromptInjectionTemplate


def variables_from_csv(text: str) -> list[str]:
    return [item.strip() for item in (text or "").split(",") if item.strip()]


def prompt_template_runtime_dict(item: PromptInjectionTemplate) -> dict:
    return {
        "id": item.id,
        "template_key": item.template_key,
        "name": item.name,
        "description": item.description,
        "target_scope": item.target_scope,
        "trigger_type": item.trigger_type,
        "priority": item.priority,
        "content_template": item.content_template,
        "variables_json": item.variables_json or [],
        "is_active": item.is_active,
    }


def list_active_prompt_templates(db: Session, target_scopes: set[str] | None = None) -> list[dict]:
    stmt = (
        select(PromptInjectionTemplate)
        .where(PromptInjectionTemplate.is_active.is_(True))
        .order_by(PromptInjectionTemplate.priority, PromptInjectionTemplate.name)
    )
    items = db.scalars(stmt).all()
    if target_scopes:
        items = [item for item in items if item.target_scope in target_scopes or item.target_scope == "all"]
    return [prompt_template_runtime_dict(item) for item in items]
