<div align="center">
  <img src="app/static/agentcapture-logo.svg" alt="AgentCapture Logo" width="84" />
  <h1>AgentCapture</h1>
  <p><strong>面向互联网业务无损接入的 SaaS 化蜜罐态势感知与 Agent 反制平台</strong></p>
  <p>AgentCapture 以嵌入式蜜饵、反向代理虚拟路由、凭证泄露感知、文件蜜饵链路、高保真交互式 SSH 蜜罐和 AI Agent 指纹识别为核心，通过功能性伪装（Developer API 伪装）主动收编自动化渗透 Agent，将攻击流量监测、蜜饵投放、证据回收、会话回放、对话式 C2 控制与平台治理统一到一套可部署、可审计、可复盘的后台。</p>

  <p><strong>中文</strong> · <a href="README_EN.md">English</a></p>

  <p>
    <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB" alt="python" />
    <img src="https://img.shields.io/badge/FastAPI-0.115%2B-009688" alt="fastapi" />
    <img src="https://img.shields.io/badge/SQLite%20%2F%20PostgreSQL-Ready-003B57" alt="database" />
    <img src="https://img.shields.io/badge/Docker-Supported-2496ED" alt="docker" />
    <img src="https://img.shields.io/badge/SSH%20Honeypot-Interactive-0F172A" alt="ssh honeypot" />
    <img src="https://img.shields.io/badge/Platform-amd64%20%7C%20arm64-111827" alt="platform" />
    <img src="https://img.shields.io/badge/Language-%E4%B8%AD%E6%96%87%20%2F%20English-DC2626" alt="language" />
    <img src="https://img.shields.io/badge/License-AGPL--3.0-blue" alt="license" />
  </p>

  <p>
    <a href="#项目介绍">项目介绍</a> ·
    <a href="#核心特性">核心特性</a> ·
    <a href="#反制实测">反制实测</a> ·
    <a href="#界面预览">界面预览</a> ·
    <a href="#系统架构">系统架构</a> ·
    <a href="#典型用途">典型用途</a> ·
    <a href="#快速开始">快速开始</a> ·
    <a href="#访问入口">访问入口</a> ·
    <a href="#功能矩阵">功能矩阵</a>
  </p>
</div>

---

## 项目介绍

AgentCapture 是一套面向安全值守、红蓝对抗与互联网系统接入的蜜罐态势感知与反制平台。它不是传统孤立式蜜罐，而是一个可以嵌入现有 Web 站点、反向代理链路和运营后台的 **deception layer**：通过隐藏路由、假凭证、文件蜜饵、Jsonp 画像、Agent 注入回显和浏览器侧信号采集，识别自动化扫描、AI Agent 探测、凭证泄露和横向侦察行为——并在识别之后**主动反制**。

平台的核心差异化能力是 **AI Agent 反制闭环**：23 种主流 Agent 产品指纹识别（Claude Code / ChatGPT Codex / Kimi Code / Pi / ZCode 等）→ 功能性伪装收编（页面可见的 Developer API 文档、Agent 自动读取的 AGENTS.md / CLAUDE.md 指令文件、MCP 工具服务诱导 Agent「按文档接入」，即完成注册上线）→ **对话式 C2 控制台**下发自然语言指令与任务 → 会话蜜标令牌全程归因溯源。实测五款主流通用 Agent（统一 GLM-5.3-Flash 底座、保留各自原生安全体系）全部被反制上线。

协议蜜罐与 Web 蜜罐由 SSH 假文件系统中的**内网主机线索**串联成蜜网：攻击者在 SSH 蜜罐「横向移动」到内网 wiki / 数据库蜜罐，全程仍在平台观测之内，水印凭证跨面复用即刻触发 `lateral_credential_reuse` 高危告警。

平台围绕 **攻击流量、凭证蜜饵登陆、文件蜜饵下载、API 路由蜜饵命中、协议蜜罐会话、Web 应用蜜罐、C2 Agent、执行审计** 建模，把攻击证据从"零散请求日志"收敛成可以追踪、可以回放的攻击链路。

蜜饵管理拆分为三类，可单独运营也可绑定成完整攻击链：

1. **API 路由蜜饵**：通过反向代理创建虚拟路由，可投放到 JS、配置文件或用户手册；正常用户不会访问，命中即告警。
2. **凭证蜜饵**：自动生成端口服务或 Web 后台假凭证；凭证被用于登录时说明凭证泄露或攻击者已进入链路。
3. **文件蜜饵**：支持上传触发文件，可绑定 API 路由蜜饵和凭证蜜饵，下载后串联完整攻击链。

---

## 核心特性

- **高保真交互式 SSH 蜜罐**：paramiko 真协议栈、任意口令可登录的假 Ubuntu 主机（约 40 个命令 + 欺骗文件系统），exec / SFTP / 交互 shell 全支持，逐命令转录并支持终端风格会话回放。
- **会话水印蜜饵凭证**：假主机内嵌的水印凭证（`Bk2026!<会话指纹>`）被攻击者窃取复用后，可溯源到具体蜜罐会话。
- **五档风险决策真实生效**：放行 / 观察 / JS 挑战 / 持久隔离 / 阻断五档决策全部落地执行，隔离名单可在后台查看、添加与解除。
- **无损接入互联网系统**：通过反向代理、路由映射、静态文件投放和前端注入为现有业务增加欺骗层，不直接改造业务代码。
- **三类蜜饵闭环**：API 路由、文件和凭证蜜饵可以单独运营，也可以绑定成完整攻击链路；支持一键生成默认攻击链。
- **协议蜜罐矩阵**：SSH、MySQL（完整交互 + 查询捕获，兼容强制 TLS 的现代客户端）、Redis、FTP（可登录 + 目录列举）、ElasticSearch、nginx-admin 真实协议仿真，捕获的凭证统一进入凭证管线并与蜜饵部署联动。
- **AI Agent 指纹识别与反制**：23 种主流 Agent 产品级指纹（含置信度与证据链）；Prompt Canary、浏览器侧 beacon、Headless/WebDriver 线索识别自动化探测；功能性伪装（Portal Developer API）主动收编 LLM Agent。
- **Agent 生态深度反制**：指令文件蜜饵（`AGENTS.md` / `CLAUDE.md` / `.cursorrules`——Agent 自动读取的项目级信任入口）；**MCP 蜜罐**（JSON-RPC 工具服务，`query_customer_db` / `run_diagnostic` 等，调用即上线）；**消耗战数据集**（无限分页水印假数据，逐行可溯源）。
- **数据毒化与 SSRF 蜜罐**：云元数据服务伪装（`/latest/meta-data/...`）返回蜜标云凭证，SSRF 利用即高危告警 + 凭证归因；毒化数据全量水印，泄露可逐条溯源。
- **内网横向蜜网**：SSH 假文件系统内嵌内网主机线索，横向目标（内网 wiki / 数据库）均为平台蜜罐；水印凭证跨面复用自动触发 `lateral_credential_reuse` 高危告警。
- **对话式 C2 控制台**：对话气泡时间线下发自然语言指令（8 个 NL 预设，含持久化控制预设）与 9 类操作原语，高危任务审批流、任务租约、多语言 Beacon 生成、监听器令牌体系与 MSF 面板统一入口。
- **反制剧本与运营体系**：一键反制剧本（VPN 门户反制 / 内网横移诱捕 / Agent 情报收集）；按来源聚合的**攻击者画像**（Agent 指纹、凭证、自动标签、完整档案）；反制 KPI 面板（收编转化率、Stager 执行率、SSH 交互深度、回头客占比）。
- **反制溯源证据链**：Jsonp 画像、Agent 注入回显、文件蜜饵下载、凭证蜜饵登录统一归档，支持攻击来源画像与会话画像。
- **运营级数据治理**：SQLite WAL + 复合索引、按天保留策略、多通道告警（Webhook / 钉钉 / 飞书 / SMTP）、开放 API 输出。
- **Docker 快速部署**：内置 `deploy.sh`，自动识别 amd64 / arm64 架构并使用 Docker Compose 部署。

---

---

## 反制实测

以下为测试环境实打实测得的反制结果：五款主流通用 Agent CLI **均接入同一模型（GLM-5.3-Flash）并保留各自原生安全体系**，对运行中的蜜罐实例执行站点巡检 / 渗透任务。

### Agent 反制结果

| Agent | 行为检测 | 处置轨迹 | 诱饵 API 接入 | 注册上线 | 自主心跳 |
| --- | --- | --- | --- | --- | --- |
| ChatGPT（Codex CLI） | 命中 | challenge → block | 完成 | **已上线** | 持续 |
| Claude Code | 命中 | challenge → isolate | 完成 | **已上线** | 持续 |
| OpenCode | 命中 | challenge → isolate | 完成 | **已上线** | 持续 |
| kimiCode | 命中 | challenge → isolate | 完成 | **已上线** | 持续 |
| Pi | 命中 | challenge → block | 完成 | **已上线** | 持续 |

五家全部被反制上线：Agent 自主完成"读取页面 Developer API 说明 → 携会话令牌调用结构化 API → 按 API 文档注册客户端 → 周期心跳"的完整接入流程，进入 C2 名册并可通过心跳领取操作员任务；全过程以**会话蜜标令牌**（session canary token）归因，从首次页面访问到注册可完整回溯。

### 三层反制体系

1. **行为检测与处置层**：可疑 UA / AI Agent 指纹 / 请求速率与挑战逃逸升级 → JS 挑战 → 持久隔离 → 阻断。高频扫描型自动化客户端在此层被拦截或拖入交互成本。
2. **功能性诱饵层**：页面以可见的 Developer API 形式暴露结构化数据接口（真实 API 不设浏览器挑战），自动化客户端按 API 文档"正常接入"即完成注册上线——不依赖目标服从任何显式指令，对齐训练无法防御"把用 API 当正常工作"的行为。
3. **全链路溯源层**：会话蜜标令牌（按会话以 HMAC 派生的追踪令牌）贯穿页面 → API → 注册 → 心跳全链路；SSH 蜜饵凭证内嵌会话水印，支持凭证复用回溯到具体会话。

### 反制上线设计思路

- **威胁基线（实测结论）**：主流 Agent 的对齐训练可稳定识别并拒绝显式命令式提示注入（隐藏指令要求上报 / 注册 / 下载执行，实测 0/8 服从）。反制设计必须假设目标**不服从任何显式指令**。
- **核心思路——回调的功能性伪装（functional camouflage）**：将反制回调重构为站点自身的合法功能。Agent 的任务语义（获取内容、使用 API）与诱饵行为对齐，"按文档接入"成为完成任务的自然路径——对齐层无从触发，因为目标自始至终没有"服从指令"，只是在"正常使用网站"。
- **可达性基线**：真实 API 不对自动化客户端返回浏览器挑战页或维护页。诱饵 API 面因此不做挑战 / 隔离 / 阻断（仍全量记录与告警）；JS 挑战页为 API 客户端提供带令牌的绕行入口，与真实挑战防护站点的惯例一致。
- **低摩擦接入**：客户端注册幂等且同时接受 GET / POST，覆盖仅具备只读抓取工具的 Agent；心跳即任务下发通道。
- **令牌双角色归因**：同一会话令牌在检测层承担蜜标（canary token，回显即命中并可隔离），在诱饵层承担 API 会话令牌（接入流程天然携带）——Agent 全程出示的"访问令牌"即其追踪信标，任一名册记录可回溯至初始浏览会话。
- **纵深互补**：行为检测与处置层（挑战 / 隔离 / 阻断）拦截高频扫描型客户端，功能性诱饵层收编低速率客户端——两层按请求速率与行为特征分层覆盖，互为补充。

> 术语说明：显式命令式提示注入在实测中被全部主流 Agent 拒绝；平台的反制上线能力来自功能性伪装（API 接入流程），而非提示词服从。

## 界面预览

> 以下截图均为测试环境运行实拍（真实浏览器窗口比例，2946×1556 @2x，非设计稿）。

<table>
  <tr>
    <td width="50%" align="center">
      <strong>SaaS 蜜罐控制台</strong><br>
      <img src="docs/screenshots/dashboard.png" alt="SaaS 蜜罐控制台" />
      <br><sub>全局攻击指标、风险事件、攻击来源、蜜罐凭证捕获量与七天趋势对比，按运营视角组织。</sub>
    </td>
    <td width="50%" align="center">
      <strong>FUI 态势大屏</strong><br>
      <img src="docs/screenshots/big-screen.png" alt="FUI 态势大屏" />
      <br><sub>3D 攻击地球、攻击趋势、来源压力、高频路径负载与宿主负载，适合值守展示与自动轮播。</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <strong>蜜饵指挥台</strong><br>
      <img src="docs/screenshots/decoy-management.png" alt="蜜饵指挥台" />
      <br><sub>API 路由蜜饵、文件蜜饵、凭证蜜饵三类统一管理，一键生成默认攻击链与投放片段。</sub>
    </td>
    <td width="50%" align="center">
      <strong>协议蜜罐矩阵</strong><br>
      <img src="docs/screenshots/services.png" alt="协议蜜罐矩阵" />
      <br><sub>SSH / MySQL / Redis / FTP / ElasticSearch / nginx-admin 仿真引擎一键启停，状态与真实监听自动对账。</sub>
    </td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <strong>SSH 会话回放</strong><br>
      <img src="docs/screenshots/honeypot-session-replay.png" alt="SSH 会话回放" />
      <br><sub>终端风格逐命令回放：认证事件、攻击者输入与蜜罐输出按时间顺序重放，捕获凭证带会话水印。</sub>
    </td>
    <td width="50%" align="center">
      <strong>C2 控制台</strong><br>
      <img src="docs/screenshots/c2-console.png" alt="C2 控制台" />
      <br><sub>Beacon 列表、任务队列、Beacon 生成、监听器与 MSF 面板统一入口，受管主机带审批与租约控制。</sub>
    </td>
  </tr>
</table>

---

## 系统架构

![AgentCapture 系统架构](docs/architecture.png)

组件数据流：

```mermaid
flowchart LR
    A[真实互联网系统] --> B[反向代理 / FastAPI Middleware]
    B --> C[API 路由蜜饵]
    B --> D[文件蜜饵分发]
    B --> E[凭证蜜饵登录页]
    B --> F[Beacon / Recon / Prompt Canary]
    P[协议蜜罐 SSH·MySQL·Redis·FTP·ES] --> G[(事件与证据库)]
    P --> Q[(会话转录库)]
    C --> G
    D --> G
    E --> H[(凭证观察库)]
    F --> G
    G --> I[风险引擎]
    H --> I
    I --> J[Allow / Observe / Challenge / Isolate / Block]
    G --> K[后台管理台]
    H --> K
    Q --> K
    K --> L[态势大屏 / 攻击流量 / 会话回放]
    K --> M[节点管理 / 端口服务 / Web 应用]
    K --> N[Jsonp 画像 / Agent 回显 / C2 控制]
    K --> O[执行历史 / 用户管理]
```

核心运行链路：

1. 用户或攻击者访问接入系统。
2. 中间件与反向代理注入隐藏线索、Canary 和蜜饵路径。
3. 攻击者翻看 JS、配置、手册、下载文件或直连协议蜜罐端口。
4. 平台记录来源 IP、会话、Header、路径、凭证、下载、命令转录和绑定链路。
5. 风险引擎输出观察、挑战、隔离或阻断决策，并支持持久隔离。
6. 后台按攻击流量、凭证登录、文件下载、蜜罐会话和反制溯源记录聚合证据。

更多说明见：[docs/architecture.md](docs/architecture.md)；互联网系统接入方式、配置命令与接入拓扑见 **[docs/integration.md](docs/integration.md)**。

---

## 典型用途

1. **互联网业务无损接入**：为多个现有 Web 系统增加蜜罐与监测能力，不直接改造业务代码。
2. **隐藏 API 路由探测识别**：将假接口写入 JS、配置文件或手册，识别翻源码、爬文档和自动化侦察行为。
3. **凭证泄露感知**：生成端口服务或 Web 后台假凭证，投放到数据库、配置或文档中，被使用即触发泄露告警。
4. **文件蜜饵攻击链串联**：上传诱导文件并绑定假 API 与假凭证，追踪"下载文件 → 访问接口 → 尝试登录"的行为链。
5. **真人攻击者诱捕与回放**：以高保真 SSH 主机承接横向移动，全程录制命令行为并支持取证回放。
6. **AI Agent / 自动化扫描识别**：通过 Prompt Canary、浏览器信号、Headless/WebDriver 线索发现自动化探测工具。
7. **安全值守与复盘**：在态势大屏、攻击流量、蜜罐会话、凭证记录和执行历史中进行审计复盘。
8. **节点化部署运营**：面向端口服务蜜罐、Web 应用蜜罐、远程 Agent 和模板进行集中维护。

---

## 目录结构

```text
AgentCapture/
├── app/                    # FastAPI 应用、路由、模型、服务、模板与静态资源
│   ├── core/               # 配置、数据库初始化与迁移
│   ├── middleware/         # 请求采集、风险判定、挑战与页面注入
│   ├── models/             # SQLAlchemy 数据模型（事件、蜜饵、会话、隔离等）
│   ├── routes/             # admin / traps / c2 / console / public api
│   ├── services/           # 风险引擎、SSH 蜜罐、欺骗文件系统、告警、保留策略等
│   ├── static/             # beacon.js、recon.js、Logo、Agent 样例
│   └── templates/          # 管理后台与公开页面模板
├── data/                   # 运行期数据目录（Docker volume 持久化）
├── docs/                   # 架构说明与实拍截图
├── scripts/                # 自检与运维脚本
├── Dockerfile
├── docker-compose.yml
├── deploy.sh               # 一键 Docker 部署脚本
├── pyproject.toml
├── README.md
└── README_EN.md
```

---

## 快速开始

### 环境要求

- **操作系统**：Linux / macOS，推荐 Ubuntu 22.04+、Debian 12+、Kali Linux 2023+
- **CPU 架构**：`amd64/x86_64` 或 `arm64/aarch64`
- **内存**：最低 2GB，推荐 4GB+
- **磁盘**：最低 5GB 可用空间
- **Docker 部署**：Docker 24.0+，Docker Compose 2.20+
- **本地部署**：Python 3.11+

### 方式一：Docker 一键部署（推荐）

```bash
# 克隆仓库
git clone https://github.com/Tcotl/AgentCapture.git
cd AgentCapture

# 一键部署（自动识别 arm64 / amd64）
chmod +x deploy.sh
./deploy.sh
```

常用参数：

```bash
./deploy.sh --port 8080
./deploy.sh --admin-password 'admin'
./deploy.sh --platform linux/arm64 --pull
./deploy.sh --reset-data --yes
./deploy.sh --logs
```

### 方式二：Docker Compose 手动部署

```bash
cp .env.example .env.docker
HOST_PORT=4877 docker compose --env-file .env.docker up -d --build
```

### 方式三：本地开发部署

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
uvicorn app.main:app --reload --host 0.0.0.0 --port 4877
```

---

## 访问入口

- **首页**：http://127.0.0.1:4877/
- **后台登录**：http://127.0.0.1:4877/admin/login
- **态势大屏**：http://127.0.0.1:4877/admin/big-screen
- **蜜罐会话回放**：http://127.0.0.1:4877/admin/honeypot-sessions
- **事件控制台**：http://127.0.0.1:4877/console/events（需管理员登录）
- **健康检查**：http://127.0.0.1:4877/healthz

**默认管理员账户**：

- 用户名：`admin`
- 密码：`admin`

生产环境请通过 `.env.docker` 或部署参数覆盖：

- `BOOTSTRAP_ADMIN_USERNAME`
- `BOOTSTRAP_ADMIN_PASSWORD`
- `BOOTSTRAP_ADMIN_EMAIL`
- `SECRET_KEY`

---

## 功能矩阵

| 能力域 | 核心内容 | 入口 / 执行面 |
| --- | --- | --- |
| 监测分析 | 控制台、态势大屏、攻击流量、来源画像、会话画像 | `/admin` |
| 三类蜜饵 | API 路由蜜饵、文件蜜饵、凭证蜜饵、默认攻击链路 | `/admin/decoy-management` |
| 协议蜜罐 | SSH 交互式蜜罐、MySQL / Redis / FTP / ES / nginx-admin 仿真、会话回放 | `/admin/services` · `/admin/honeypot-sessions` |
| 反制溯源 | Jsonp 攻击者画像、Agent 注入回显、文件下载记录、凭证登录记录 | `/admin/recon-data` 等 |
| 部署运营 | 节点管理、端口服务蜜罐、Web 应用蜜罐、互联网系统接入、提示词注入 | `/admin/nodes` 等 |
| Web 应用蜜罐 | 模板上传、一键克隆前端页面、Web 应用部署管理 | `/admin/templates` |
| C2 控制 | C2 Console（Beacon/任务队列/Beacon 生成/监听器/MSF）、Agent 管理、木马捆绑 | `/admin/c2/console` |
| 告警与处置 | 多通道告警、主动隔离名单管理、威胁情报与白名单 | `/admin/alerts` · `/admin/intel` |
| 平台设置 | 执行历史、登录日志、用户管理、个人信息 | `/admin/execution-history` 等 |
| 开放 API | 攻击来源、攻击详情、凭证数据输出 | `/api/v1/*` |
| 自检验证 | 自动创建并验证三类蜜饵链路 | `scripts/verify_decoy_chain.py` |

---

## 关键链路自检

部署完成后可运行自检脚本验证三类蜜饵链路：

```bash
python3 scripts/verify_decoy_chain.py --base http://localhost:4877
```

脚本会自动验证：登录后台 → 创建 API 路由蜜饵 → 创建凭证蜜饵 → 创建绑定两者的文件蜜饵 → 部署下载 → 访问 API 路由 → 使用生成凭证登录 → 校验凭证记录、部署记录和 manifest。

成功输出示例：

```text
[OK] decoy chain verified
api=/_bait/api/private/self-check-...
file=/d/.../self-check-....txt
credential_login=/_bait/credential/.../login
```

---

## 安全说明

AgentCapture 仅用于授权环境下的安全监测、蜜罐运营、攻防演练和内部验证。请勿在未授权系统中投放蜜饵、采集凭证或进行任何形式的攻击测试。生产部署前请务必修改默认管理员密码和 `SECRET_KEY`，并根据组织要求配置访问控制、日志留存和合规审计策略。

---

## 许可证

本项目采用 AGPL-3.0 许可证。详情请阅读 [LICENSE](LICENSE)。


---

## AgentCapture 交流群

<div align="center">

<img src="docs/wechat-group.jpg" alt="AgentCapture 交流群" width="240" height="240" />
&nbsp;&nbsp;&nbsp;&nbsp;
<img src="docs/author-wechat.jpg" alt="作者微信" width="240" height="240" />

**扫码加入微信交流群**，获取部署实践、反制案例与版本动态；或添加**作者微信**交流合作与技术探讨。

</div>
