#!/bin/sh
echo "[sapper] target=$TARGET_URL"
if command -v sapper >/dev/null; then SAPPER_BIN="claude --dangerously-skip-permissions" sapper auto --goal "$TASK"; else echo "[$NAME] placeholder — needs sapper + nested claude CLI"; fi 2>&1 | tee "/results/sapper.log"
