"""i18n dictionary groups. Each entry has a sibling module
`app/services/i18n_<name>.py` exposing `EN: dict[str, str]` (Chinese source
-> English). Add new groups here plus their module when splitting work."""

GROUPS = [
    "chrome",
    "lists",
    "honeypots",
    "resources",
    "c2",
    "settings",
]

# Longest-prefix translations for dynamically composed titles, e.g.
# f"攻击详情 / {sid}" or f"删除 {name}".
PREFIXES = {
    "攻击详情 / ": "Attack Detail / ",
    "会话画像 / ": "Session Profile / ",
    "攻击来源 ": "Attack Source ",
    "节点详情 / ": "Node Detail / ",
    "蜜罐会话回放 / ": "Honeypot Session / ",
    "删除 ": "Delete ",
    "编辑 ": "Edit ",
    "确认删除 ": "Confirm deletion of ",
}
