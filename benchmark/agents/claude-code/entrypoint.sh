#!/bin/sh
echo "[claude-code] target=$TARGET_URL"
claude -p "$TASK" --model "$ANTHROPIC_MODEL" --dangerously-skip-permissions 2>&1 | tee "/results/claude-code.log"
