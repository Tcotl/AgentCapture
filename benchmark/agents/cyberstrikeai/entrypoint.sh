#!/bin/sh
echo "[cyberstrikeai] target=$TARGET_URL"
if [ -x /opt/cyberstrikeai/cyberstrikeai ]; then /opt/cyberstrikeai/cyberstrikeai --target "$TARGET_URL"; else echo "[$NAME] bring-your-source: mount the Go build at benchmark/agents/cyberstrikeai/bin/"; fi 2>&1 | tee "/results/cyberstrikeai.log"
