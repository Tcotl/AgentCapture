#!/bin/sh
echo "[strix] target=$TARGET_URL"
strix "$TARGET_URL" 2>&1 | tee "/results/strix.log"
