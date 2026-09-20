#!/usr/bin/env bash
# ============================================================================
# AgentCapture 演示环境一次性配置脚本（本机执行）
#
# 前提：本机已登录 vercel CLI（执行过 `vercel login`）。
# 动作：创建 agentcapture-demo 项目 → 写入演示环境变量 → 生产部署 → 打印演示地址。
# ============================================================================
set -eu
cd "$(dirname "$0")/.."

PROJECT="agentcapture-demo"

log() { printf '\033[1;34m[vercel-demo]\033[0m %s\n' "$*"; }
ok()  { printf '\033[1;32m[ok]\033[0m %s\n' "$*"; }

vercel link --yes --project "$PROJECT"
echo "Admin@123" | vercel env add BOOTSTRAP_ADMIN_PASSWORD production 2>/dev/null || true
echo "Admin@123" | vercel env add BOOTSTRAP_ADMIN_PASSWORD preview 2>/dev/null || true
echo "agentcapture-demo-secret-key-050" | vercel env add SECRET_KEY production 2>/dev/null || true
echo "agentcapture-demo-secret-key-050" | vercel env add SECRET_KEY preview 2>/dev/null || true

log "部署生产环境…"
URL=$(vercel deploy --prod --yes | tail -1)
ok "演示地址：$URL"
ok "演示口令：Admin@123（首次登录后按提示改密，演示环境可保留）"
log "建议将 $URL 设置到 GitHub 仓库 Website 字段（如尚未设置）。"
