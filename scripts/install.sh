#!/usr/bin/env bash
# ============================================================================
# AgentCapture 一键网络部署脚本
#
#   curl -fsSL https://raw.githubusercontent.com/Tcotl/AgentCapture/main/scripts/install.sh | bash
#
# 跨系统 / 跨架构：自动识别 Linux (x86_64/aarch64) 与 macOS (Apple Silicon/Intel)，
# 自动选择部署路径：
#   1) Docker 路径  — 宿主机已有 Docker 时优先（docker compose 构建启动）
#   2) 原生路径     — Python 3.11+ venv + uvicorn（Linux 自动注册 systemd 服务）
#
# 可选参数（放在 `bash` 后使用，例如：curl -fsSL ... | bash -s -- --docker --port 8080）：
#   --docker            强制使用 Docker 路径
#   --native            强制使用原生路径
#   --dir <目录>        安装目录（默认 /opt/AgentCapture，原生路径 macOS 默认 ~/AgentCapture）
#   --port <端口>       管理面端口（默认 4877；蜜罐面固定 48777）
#   --admin-password <密码>   覆盖默认管理员口令（不填则自动生成强口令）
#   --tag <tag>         使用指定发布标签源码（默认 main 分支）
#   --no-start          只安装不启动
#   --dry-run           只打印将执行的动作
# ============================================================================
set -eu

REPO="Tcotl/AgentCapture"
BRANCH="main"
INSTALL_DIR=""
PORT="4877"
ADMIN_PASSWORD=""
MODE=""          # docker | native | 空=自动
NO_START=0
DRY_RUN=0
TAG=""

log()  { printf '\033[1;34m[agentcapture]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ok]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[err]\033[0m %s\n' "$*"; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --docker) MODE="docker" ;;
    --native) MODE="native" ;;
    --dir) INSTALL_DIR="$2"; shift ;;
    --port) PORT="$2"; shift ;;
    --admin-password) ADMIN_PASSWORD="$2"; shift ;;
    --tag) TAG="$2"; shift ;;
    --no-start) NO_START=1 ;;
    --dry-run) DRY_RUN=1 ;;
    *) err "未知参数：$1（支持 --docker --native --dir --port --admin-password --tag --no-start --dry-run）" ;;
  esac
  shift
done

run() {
  if [ "$DRY_RUN" = "1" ]; then log "[dry-run] $*"; else "$@"; fi
}

# ---------------------------------------------------------------------------
# 环境识别
# ---------------------------------------------------------------------------
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
  Linux) OS_NAME="linux" ;;
  Darwin) OS_NAME="darwin" ;;
  *) err "不支持的操作系统：${OS}（支持 Linux / macOS）" ;;
esac
case "$ARCH" in
  x86_64|amd64) ARCH_NAME="amd64" ;;
  aarch64|arm64) ARCH_NAME="arm64" ;;
  *) err "不支持的架构：${ARCH}（支持 x86_64 / aarch64）" ;;
esac
log "环境识别：$OS_NAME / $ARCH_NAME"

need_cmd() { command -v "$1" >/dev/null 2>&1; }

if [ -z "$INSTALL_DIR" ]; then
  [ "$OS_NAME" = "darwin" ] && INSTALL_DIR="$HOME/AgentCapture" || INSTALL_DIR="/opt/AgentCapture"
fi

# Docker 可用性
DOCKER_OK=0
if need_cmd docker; then
  if docker info >/dev/null 2>&1; then DOCKER_OK=1; else warn "Docker 已安装但守护进程不可用"; fi
fi

# 自动选择路径：有可用 Docker → docker，否则原生
if [ -z "$MODE" ]; then
  if [ "$DOCKER_OK" = "1" ]; then MODE="docker"; else MODE="native"; fi
fi
if [ "$MODE" = "docker" ] && [ "$DOCKER_OK" != "1" ]; then
  warn "Docker 不可用，回退到原生路径"; MODE="native"
fi

# ---------------------------------------------------------------------------
# 依赖准备
# ---------------------------------------------------------------------------
if ! need_cmd curl && ! need_cmd wget; then err "需要 curl 或 wget 下载源码"; fi
fetch() {
  if need_cmd curl; then curl -fsSL "$1"; else wget -qO- "$1"; fi
}
fetch_file() {
  if need_cmd curl; then curl -fsSL "$1" -o "$2"; else wget -qO "$2" "$1"; fi
}

if [ "$MODE" = "docker" ]; then
  need_cmd docker || err "Docker 路径需要 docker 命令"
  if docker compose version >/dev/null 2>&1; then COMPOSE="docker compose";
  elif need_cmd docker-compose; then COMPOSE="docker-compose";
  else err "缺少 Docker Compose（请安装 compose 插件）"; fi
else
  PY=""
  for c in python3.12 python3.11 python3; do
    if need_cmd "$c"; then
      v=$("$c" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo 0)
      case "$v" in
        3.11|3.12|3.13|3.14) PY="$c"; break ;;
      esac
    fi
  done
  [ -n "$PY" ] || err "原生路径需要 Python 3.11+（未找到可用的 python3.11/3.12/3.13）。请安装后重试，或改用 --docker"
  ok "使用 Python：$PY ($v)"
  need_cmd openssl || warn "缺少 openssl（SECRET_KEY 将使用 python secrets 生成）"
fi

# ---------------------------------------------------------------------------
# 源码获取（优先发布标签 tar，其次 main 分支）
# ---------------------------------------------------------------------------
SRC_URL="https://github.com/$REPO/archive/refs/heads/$BRANCH.tar.gz"
[ -n "$TAG" ] && SRC_URL="https://github.com/$REPO/archive/refs/tags/$TAG.tar.gz"
log "获取源码：$SRC_URL"

if [ "$DRY_RUN" = "1" ]; then
  log "[dry-run] 下载并解压到 ${INSTALL_DIR}（模式：${MODE}，端口：${PORT}）"
  log "[dry-run] 完成后访问 http://<本机>:$PORT/agentcapture/（登录）与 :48777（蜜罐面）"
  exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fetch_file "$SRC_URL" "$TMP/src.tar.gz"
mkdir -p "$INSTALL_DIR"
tar -xzf "$TMP/src.tar.gz" -C "$TMP"
# tar 顶层目录形如 AgentCapture-main / AgentCapture-<tag>
mkdir -p "$TMP/root"
cp -R "$TMP"/AgentCapture-*/. "$TMP/root"/
mkdir -p "$INSTALL_DIR"
cp -R "$TMP/root"/. "$INSTALL_DIR"/
ok "源码就绪：$INSTALL_DIR"

# ---------------------------------------------------------------------------
# 公共配置：SECRET_KEY / 管理员口令
# ---------------------------------------------------------------------------
gen_secret() {
  if need_cmd openssl; then openssl rand -hex 32; else "$PY" -c 'import secrets;print(secrets.token_hex(32))' 2>/dev/null || echo "change-me-$(date +%s)"; fi
}
gen_password() {
  if need_cmd openssl; then openssl rand -base64 15 | tr -d '/+=' | cut -c1-14; else "$PY" -c 'import secrets;print(secrets.token_urlsafe(12))' 2>/dev/null || echo "AgentCapture-$(date +%s)"; fi
}
SECRET_KEY="$(gen_secret)"
[ -n "$ADMIN_PASSWORD" ] || ADMIN_PASSWORD="$(gen_password)"

write_env() {
  cat > "$1/.env" <<ENV
SECRET_KEY=$SECRET_KEY
BOOTSTRAP_ADMIN_PASSWORD=$ADMIN_PASSWORD
PORT=$PORT
ENV
}

# ---------------------------------------------------------------------------
# 路径 1：Docker Compose
# ---------------------------------------------------------------------------
if [ "$MODE" = "docker" ]; then
  write_env "$INSTALL_DIR"
  printf 'HOST_PORT=%s\n' "$PORT" >> "$INSTALL_DIR/.env"
  log "Docker Compose 构建并启动…"
  run sh -c "cd '$INSTALL_DIR' && $COMPOSE --env-file .env up -d --build"
  ok "部署完成。访问 http://<本机>:$PORT/agentcapture/"
  ok "管理员口令：${ADMIN_PASSWORD}（首次登录将要求修改默认口令）"
  [ "$NO_START" = "0" ] || warn "--no-start 与 Docker 路径互斥，容器已启动"
  exit 0
fi

# ---------------------------------------------------------------------------
# 路径 2：原生 venv + uvicorn
# ---------------------------------------------------------------------------
log "创建虚拟环境并安装依赖…"
run sh -c "cd '$INSTALL_DIR' && '$PY' -m venv .venv && .venv/bin/pip install -q --upgrade pip && .venv/bin/pip install -q -e ."
write_env "$INSTALL_DIR"

if [ "$OS_NAME" = "linux" ] && [ "$NO_START" = "0" ] && [ -d /etc/systemd/system ]; then
  log "注册 systemd 服务 agentcapture.service…"
  run sh -c "cat > /etc/systemd/system/agentcapture.service <<UNIT
[Unit]
Description=AgentCapture Honeypot Platform
After=network.target

[Service]
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=$INSTALL_DIR/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port $PORT
Restart=always

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable --now agentcapture"
  ok "服务已启动：systemctl status agentcapture"
else
  if [ "$NO_START" = "1" ]; then
    ok "--no-start：跳过前台启动（手动启动：cd $INSTALL_DIR && .venv/bin/uvicorn app.main:app --port ${PORT}）"
  else
    log "前台启动（macOS / 无 systemd）：Ctrl+C 停止"
    run sh -c "cd '$INSTALL_DIR' && set -a && . ./.env && set +a && .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port $PORT"
  fi
fi

ok "部署完成。访问 http://<本机>:$PORT/agentcapture/"
ok "管理员账号：admin（用户名可在环境变量覆盖）；口令：$ADMIN_PASSWORD"
ok "蜜罐面（48777）随服务自动启动；端口服务蜜罐可在控制台逐项开启"
