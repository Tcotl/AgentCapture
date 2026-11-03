#!/bin/sh
echo "[artex] target=$TARGET_URL"
if [ -x /opt/artex/artex ]; then /opt/artex/artex --target "$TARGET_URL"; else echo "[$NAME] bring-your-source: mount the ARTEX build at benchmark/agents/artex/bin/"; fi 2>&1 | tee "/results/artex.log"
