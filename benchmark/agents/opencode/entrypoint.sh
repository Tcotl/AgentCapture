#!/bin/sh
echo "[opencode] target=$TARGET_URL"
opencode run "$TASK" 2>&1 | tee "/results/opencode.log"
