#!/usr/bin/env bash
set -Eeuo pipefail

# AgentCapture Honeypot one-click Docker deployment script.
# Supports Linux/macOS on x86_64/amd64 and arm64/aarch64 hosts.

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$PROJECT_DIR/docker-compose.yml"
ENV_FILE="${ENV_FILE:-$PROJECT_DIR/.env.docker}"
SERVICE_NAME="honeypot"
CONTAINER_NAME="agent-capture-honeypot"

HOST_PORT_FROM_ENV="${HOST_PORT+x}"
SITE_ID_FROM_ENV="${SITE_ID+x}"
ADMIN_USER_FROM_ENV="${BOOTSTRAP_ADMIN_USERNAME+x}"
ADMIN_PASS_FROM_ENV="${BOOTSTRAP_ADMIN_PASSWORD+x}"
ADMIN_EMAIL_FROM_ENV="${BOOTSTRAP_ADMIN_EMAIL+x}"
SECRET_KEY_FROM_ENV="${SECRET_KEY+x}"

HOST_PORT="${HOST_PORT:-4877}"
SITE_ID="${SITE_ID:-docker-local}"
BOOTSTRAP_ADMIN_USERNAME="${BOOTSTRAP_ADMIN_USERNAME:-admin}"
BOOTSTRAP_ADMIN_PASSWORD="${BOOTSTRAP_ADMIN_PASSWORD:-admin}"
BOOTSTRAP_ADMIN_EMAIL="${BOOTSTRAP_ADMIN_EMAIL:-admin@example.local}"
SECRET_KEY="${SECRET_KEY:-}"
HOST_PORT_FROM_CLI=0
SITE_ID_FROM_CLI=0
ADMIN_USER_FROM_CLI=0
ADMIN_PASS_FROM_CLI=0
ADMIN_EMAIL_FROM_CLI=0
SECRET_KEY_FROM_CLI=0
BUILD=1
PULL_BASE=0
RESET_DATA=0
ASSUME_YES=0
SHOW_LOGS=0
DRY_RUN=0
INSTALL_DOCKER=0
FORCE_PLATFORM="${DOCKER_DEFAULT_PLATFORM:-}"

log() { printf '\033[1;34m[AgentCapture]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[Warn]\033[0m %s\n' "$*" >&2; }
err() { printf '\033[1;31m[Error]\033[0m %s\n' "$*" >&2; }
die() { err "$*"; exit 1; }

usage() {
  cat <<'EOF'
AgentCapture 一键 Docker 部署脚本

用法:
  ./deploy.sh [选项]

常用选项:
  --port 4877                 宿主机访问端口，默认 4877
  --admin-user admin          初始管理员用户名，默认 admin
  --admin-password PASS       初始管理员密码，默认 admin
  --admin-email EMAIL         初始管理员邮箱
  --site-id docker-local      站点/租户标识
  --secret-key KEY            Session 密钥；不传会自动生成并写入 .env.docker
  --platform linux/amd64      手动指定镜像平台；默认按系统架构自动检测
  --no-build                  不重新构建镜像，仅启动已有镜像
  --pull                      部署前拉取 python:3.12-slim 对应架构基础镜像
  --reset-data                删除 Docker volume 后重建，清空历史数据
  -y, --yes                   与 --reset-data 配合使用，跳过确认
  --logs                      启动后跟随查看日志
  --dry-run                   只打印将执行的动作，不真正部署
  --install-docker            Docker 缺失时尝试安装（Linux 使用官方脚本，macOS 使用 brew cask）
  -h, --help                  查看帮助

示例:
  ./deploy.sh
  ./deploy.sh --port 8080 --admin-password 'admin'
  ./deploy.sh --platform linux/arm64 --pull
  ./deploy.sh --reset-data --yes
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) HOST_PORT="${2:-}"; HOST_PORT_FROM_CLI=1; shift 2 ;;
    --admin-user) BOOTSTRAP_ADMIN_USERNAME="${2:-}"; ADMIN_USER_FROM_CLI=1; shift 2 ;;
    --admin-password) BOOTSTRAP_ADMIN_PASSWORD="${2:-}"; ADMIN_PASS_FROM_CLI=1; shift 2 ;;
    --admin-email) BOOTSTRAP_ADMIN_EMAIL="${2:-}"; ADMIN_EMAIL_FROM_CLI=1; shift 2 ;;
    --site-id) SITE_ID="${2:-}"; SITE_ID_FROM_CLI=1; shift 2 ;;
    --secret-key) SECRET_KEY="${2:-}"; SECRET_KEY_FROM_CLI=1; shift 2 ;;
    --platform) FORCE_PLATFORM="${2:-}"; shift 2 ;;
    --no-build) BUILD=0; shift ;;
    --pull) PULL_BASE=1; shift ;;
    --reset-data) RESET_DATA=1; shift ;;
    -y|--yes) ASSUME_YES=1; shift ;;
    --logs) SHOW_LOGS=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --install-docker) INSTALL_DOCKER=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "未知参数: $1。使用 --help 查看帮助。" ;;
  esac
done

[[ -f "$COMPOSE_FILE" ]] || die "找不到 docker-compose.yml: $COMPOSE_FILE"
[[ "$HOST_PORT" =~ ^[0-9]+$ ]] || die "--port 必须是数字端口"
[[ "$HOST_PORT" -ge 1 && "$HOST_PORT" -le 65535 ]] || die "--port 超出范围: $HOST_PORT"

command_exists() { command -v "$1" >/dev/null 2>&1; }

random_secret() {
  if command_exists openssl; then
    openssl rand -hex 32
  elif [[ -r /dev/urandom ]]; then
    LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 64
  else
    date +%s | sha256sum | awk '{print $1}'
  fi
}

get_env_value() {
  local key="$1" file="$2"
  [[ -f "$file" ]] || return 1
  awk -F= -v k="$key" '$1 == k {sub(/^[^=]*=/, ""); print; exit}' "$file"
}

if [[ -z "$SECRET_KEY" ]]; then
  if existing_secret="$(get_env_value SECRET_KEY "$ENV_FILE" 2>/dev/null)" && [[ -n "$existing_secret" ]]; then
    SECRET_KEY="$existing_secret"
  else
    SECRET_KEY="$(random_secret)"
  fi
fi

if [[ -f "$ENV_FILE" ]]; then
  # Preserve existing deploy values unless CLI flags or environment variables override them.
  existing_port="$(get_env_value HOST_PORT "$ENV_FILE" 2>/dev/null || true)"
  existing_site="$(get_env_value SITE_ID "$ENV_FILE" 2>/dev/null || true)"
  existing_user="$(get_env_value BOOTSTRAP_ADMIN_USERNAME "$ENV_FILE" 2>/dev/null || true)"
  existing_pass="$(get_env_value BOOTSTRAP_ADMIN_PASSWORD "$ENV_FILE" 2>/dev/null || true)"
  existing_email="$(get_env_value BOOTSTRAP_ADMIN_EMAIL "$ENV_FILE" 2>/dev/null || true)"
  [[ -n "$existing_port" && "$HOST_PORT_FROM_CLI" -eq 0 && -z "$HOST_PORT_FROM_ENV" ]] && HOST_PORT="$existing_port"
  [[ -n "$existing_site" && "$SITE_ID_FROM_CLI" -eq 0 && -z "$SITE_ID_FROM_ENV" ]] && SITE_ID="$existing_site"
  [[ -n "$existing_user" && "$ADMIN_USER_FROM_CLI" -eq 0 && -z "$ADMIN_USER_FROM_ENV" ]] && BOOTSTRAP_ADMIN_USERNAME="$existing_user"
  [[ -n "$existing_pass" && "$ADMIN_PASS_FROM_CLI" -eq 0 && -z "$ADMIN_PASS_FROM_ENV" ]] && BOOTSTRAP_ADMIN_PASSWORD="$existing_pass"
  [[ -n "$existing_email" && "$ADMIN_EMAIL_FROM_CLI" -eq 0 && -z "$ADMIN_EMAIL_FROM_ENV" ]] && BOOTSTRAP_ADMIN_EMAIL="$existing_email"
fi

detect_platform() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m | tr '[:upper:]' '[:lower:]')"
  case "$arch" in
    x86_64|amd64) echo "linux/amd64" ;;
    arm64|aarch64) echo "linux/arm64" ;;
    armv7l|armv7*) echo "linux/arm/v7" ;;
    *) die "暂不支持的 CPU 架构: $arch ($os)。可用 --platform 手动指定。" ;;
  esac
}

HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"
PLATFORM="${FORCE_PLATFORM:-$(detect_platform)}"
export DOCKER_DEFAULT_PLATFORM="$PLATFORM"

install_docker_if_requested() {
  if command_exists docker; then
    return 0
  fi
  [[ "$INSTALL_DOCKER" -eq 1 ]] || die "未检测到 docker。请先安装 Docker，或使用 --install-docker 尝试自动安装。"
  case "$(uname -s)" in
    Linux)
      command_exists curl || die "自动安装 Docker 需要 curl，请先安装 curl。"
      warn "即将使用 Docker 官方脚本安装 Docker，需要 sudo 权限。"
      if [[ "$DRY_RUN" -eq 1 ]]; then
        log "DRY-RUN: curl -fsSL https://get.docker.com | sh"
      else
        curl -fsSL https://get.docker.com | sh
      fi
      ;;
    Darwin)
      command_exists brew || die "macOS 自动安装需要 Homebrew；也可以手动安装 Docker Desktop。"
      warn "即将通过 Homebrew 安装 Docker Desktop。"
      if [[ "$DRY_RUN" -eq 1 ]]; then
        log "DRY-RUN: brew install --cask docker"
      else
        brew install --cask docker
        warn "请启动 Docker Desktop 后重新运行本脚本。"
        exit 0
      fi
      ;;
    *) die "当前系统不支持自动安装 Docker，请手动安装。" ;;
  esac
}

install_docker_if_requested
command_exists docker || die "未检测到 docker 命令。"

DOCKER_CMD=(docker)
if ! docker info >/dev/null 2>&1; then
  if command_exists sudo && sudo docker info >/dev/null 2>&1; then
    DOCKER_CMD=(sudo docker)
  else
    die "Docker daemon 不可用。请启动 Docker Desktop / Docker 服务后重试。"
  fi
fi

if "${DOCKER_CMD[@]}" compose version >/dev/null 2>&1; then
  COMPOSE_CMD=("${DOCKER_CMD[@]}" compose)
elif command_exists docker-compose; then
  if docker-compose version >/dev/null 2>&1; then
    COMPOSE_CMD=(docker-compose)
  elif command_exists sudo && sudo docker-compose version >/dev/null 2>&1; then
    COMPOSE_CMD=(sudo docker-compose)
  else
    die "docker-compose 不可用。"
  fi
else
  die "未检测到 Docker Compose。请安装 Docker Compose v2。"
fi

write_env_file() {
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp" <<EOF
# Generated by AgentCapture deploy.sh
HOST_PORT=$HOST_PORT
APP_ENV=production
HOST=0.0.0.0
PORT=4877
SITE_ID=$SITE_ID
DATABASE_URL=sqlite:////data/agent_capture.db
SECRET_KEY=$SECRET_KEY
SESSION_COOKIE_NAME=ach_sid
ADMIN_SESSION_COOKIE_NAME=ach_admin
CANARY_HEADER_NAME=X-Agent-Canary
INJECTOR_ENABLED=true
RECON_JSONP_ENABLED=true
AGENT_INJECTION_ENABLED=true
C2_ENABLED=true
COLLECT_PATH=/collect/beacon
KNOWLEDGE_BASE_ROOT=/data/knowledge_base
BOOTSTRAP_ADMIN_USERNAME=$BOOTSTRAP_ADMIN_USERNAME
BOOTSTRAP_ADMIN_PASSWORD=$BOOTSTRAP_ADMIN_PASSWORD
BOOTSTRAP_ADMIN_EMAIL=$BOOTSTRAP_ADMIN_EMAIL
EOF
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "DRY-RUN: 写入环境文件 $ENV_FILE"
    cat "$tmp"
    rm -f "$tmp"
  else
    mv "$tmp" "$ENV_FILE"
    chmod 600 "$ENV_FILE" || true
  fi
}

run_cmd() {
  log "+ $*"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    "$@"
  fi
}

wait_health() {
  local url="http://127.0.0.1:${HOST_PORT}/healthz"
  local i status
  log "等待服务健康检查: $url"
  for i in $(seq 1 90); do
    if command_exists curl && curl -fsS "$url" >/dev/null 2>&1; then
      log "服务已就绪。"
      return 0
    fi
    status="$("${DOCKER_CMD[@]}" inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER_NAME" 2>/dev/null || true)"
    if [[ "$status" == "healthy" ]]; then
      log "容器健康检查已通过。"
      return 0
    fi
    sleep 2
  done
  warn "健康检查超时，最近日志如下："
  "${COMPOSE_CMD[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" logs --tail 80 "$SERVICE_NAME" || true
  return 1
}

log "项目目录: $PROJECT_DIR"
log "系统: $HOST_OS / $HOST_ARCH -> Docker 平台: $PLATFORM"
log "Compose: ${COMPOSE_CMD[*]}"
log "访问端口: $HOST_PORT"

write_env_file

if [[ "$RESET_DATA" -eq 1 ]]; then
  if [[ "$ASSUME_YES" -ne 1 ]]; then
    warn "--reset-data 会删除 Docker volume honeypot_data，历史事件/账号/配置会丢失。"
    read -r -p "确认清空数据并继续？输入 yes: " confirm
    [[ "$confirm" == "yes" ]] || die "已取消。"
  fi
  run_cmd "${COMPOSE_CMD[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" down -v --remove-orphans
fi

if [[ "$PULL_BASE" -eq 1 ]]; then
  run_cmd "${DOCKER_CMD[@]}" pull --platform "$PLATFORM" python:3.12-slim
fi

UP_ARGS=(--env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d)
if [[ "$BUILD" -eq 1 ]]; then
  UP_ARGS+=(--build)
fi
run_cmd "${COMPOSE_CMD[@]}" "${UP_ARGS[@]}"

if [[ "$DRY_RUN" -eq 0 ]]; then
  wait_health
  "${COMPOSE_CMD[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" ps
fi

cat <<EOF

部署完成：
  后台地址: http://127.0.0.1:${HOST_PORT}/admin/login
  默认账号: ${BOOTSTRAP_ADMIN_USERNAME}
  默认密码: ${BOOTSTRAP_ADMIN_PASSWORD}
  平台架构: ${PLATFORM}

常用命令：
  查看日志: ${COMPOSE_CMD[*]} --env-file "$ENV_FILE" -f "$COMPOSE_FILE" logs -f ${SERVICE_NAME}
  停止服务: ${COMPOSE_CMD[*]} --env-file "$ENV_FILE" -f "$COMPOSE_FILE" down
  更新重建: ./deploy.sh --port ${HOST_PORT}

提示：如果数据库 volume 已存在，修改 BOOTSTRAP_ADMIN_PASSWORD 不会自动重置已有管理员密码，请在后台用户管理中修改。
EOF

if [[ "$SHOW_LOGS" -eq 1 && "$DRY_RUN" -eq 0 ]]; then
  "${COMPOSE_CMD[@]}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" logs -f "$SERVICE_NAME"
fi
