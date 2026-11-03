#!/bin/sh
echo "[hexstrike] target=$TARGET_URL"
if [ -f hexstrike_server.py ]; then python3 hexstrike_server.py >/dev/null 2>&1 & sleep 3; fi
# 已验证的平台侧指纹 UA（2026-11 实弹）
curl -s -A "HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)" "$TARGET_URL" | head -c 2000
echo
