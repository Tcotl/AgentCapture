"""Lightweight i18n for the admin console.

Chinese is the source locale: template text stays in Chinese and `_()`
translates it to English when the operator's preferred language is "en".
Strings without an entry fall back to the Chinese source, so partial
coverage degrades gracefully instead of breaking pages.

Dictionaries live in `app/services/i18n_*.py` group modules (EN dict each)
so parallel contributors never edit the same file; this module merges them
at import time.
"""
import importlib

from app.services import i18n_groups

EN: dict[str, str] = {}

# Longest-prefix table for dynamically composed strings, e.g.
# "攻击详情 / <session-id>" -> "Attack Detail / <session-id>".
_PREFIXES: list[tuple[str, str]] = []


def _load() -> None:
    for group in i18n_groups.GROUPS:
        mod = importlib.import_module(f"app.services.i18n_{group}")
        table = getattr(mod, "EN", {})
        EN.update(table)
    for src, dst in getattr(i18n_groups, "PREFIXES", {}).items():
        _PREFIXES.append((src, dst))
    _PREFIXES.sort(key=lambda pair: len(pair[0]), reverse=True)


_load()


def translate(text: str) -> str:
    """Translate a Chinese source string to English (zh passthrough elsewhere)."""
    if not text:
        return text
    hit = EN.get(text)
    if hit is not None:
        return hit
    for src, dst in _PREFIXES:
        if text.startswith(src):
            return dst + text[len(src):]
    return text


def gettext_for(lang: str | None):
    """Return a Jinja-callable `_` bound to the operator's language."""
    if lang == "en":
        return translate
    return lambda text: text
