#!/bin/sh
echo "[codex-cli] target=$TARGET_URL"
codex exec --dangerously-bypass-approvals-and-sandbox "$TASK" 2>&1 | tee "/results/codex-cli.log"
