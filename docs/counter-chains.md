# AgentCapture 反制链条全景（2026-11 实测版）

一条自动化攻击者（AI Agent / 扫描器 / 人工）从触网到被控的完整反制旅程。

```
触网 → 检测识别 → 决策处置 → 无感上线 → 分级控制 → 画像溯源 → 横向蜜网
```

---

## 链一：检测识别（入口即指纹）

| 反制面 | 机制 | 代码位置 |
|---|---|---|
| Agent 产品指纹 | 30+ 产品级 UA/行为识别（Claude Code / Codex / Kimi / Pi / ZCode / HexStrike / Strix / ARTEX…），带置信度与证据链 | `risk_engine.py` |
| 风险引擎四分类器 | HTTP 请求 / beacon / recon 指纹 / agent 交互独立打分 | `risk_engine.py::classify_*` |
| 会话蜜标 canary | 每会话 HMAC 派生令牌，贯穿页面→API→注册→心跳全链归因 | `services/canary.py` |
| 浏览器侧画像 | collector.js / fingerprint.js（JSONP + WebRTC + Canvas/WebGL 指纹回传） | `static/collector.js`、`fingerprint.js` |
| 指令文件信任入口 | /AGENTS.md、/CLAUDE.md、/.cursorrules 动态渲染（会话蜜标嵌入） | `counter_offense.py` |

## 链二：决策处置（五档真实执行）

`allow → observe → challenge(JS 挑战) → isolate(持久隔离表) → block`，阈值 20/45/70/95；
蜜饵路径 observe-only（先采集后处置）；隔离名单后台可管理。`middleware/injector.py`、`services/challenge.py`、`services/isolation.py`

---

## 链三：无感上线（五条入册通道，Agent 零感知）

| # | 通道 | 身份类型 | Agent 的认知 | 实测 |
|---|---|---|---|---|
| 1 | **RCE 利用即上线**：invokefunction / webshell / `/api/v2/upload?debug=true` 每次执行 = 一次心跳 | `rce_session`（黄徽"RCE 接入"） | "我在验证漏洞" | Z 轮 203 次/轮 |
| 2 | **Portal 自注册**：`/portal/api/client-register` | `implant`（绿徽"Portal 招募"） | "正常 API 注册"（GLM 原话：与注入无关的正常流程） | T/Y/Z 全轮 |
| 3 | **MCP 调用即上线**：`on_call=register` 工具（exec_maintenance 等） | `mcp` | "在用目标内部工具" | Y 轮 2 身份 |
| 4 | **beacon 信标部署**：client-package 包（argv 白名单执行器） | `implant`+sys 画像 | 需操作员授权（"部署己方检测探针"），部署后无感 | R 轮 root 全链 |
| 5 | **协议蜜罐接入**：SSH/MySQL/Redis/FTP/ES/nginx-admin | 会话+凭证记录 | "打进了真实服务" | Y 轮 SSH root 会话回放 |

确定性身份：`rce_session` 的 agent_id = `tp`+sha1(ip)——同源稳定，重复利用即续心跳。

## 链四：分级控制（控制深度 L1→L5，双控制台归属）

| 平面 | 控制台 | 身份 | 控制语义 |
|---|---|---|---|
| **Agent 控制** | `/admin/agent-console` | RCE 接入 / Portal 招募 / MCP（`control_plane=agent`） | 巡检项（runbook）——平台运维语义，Agent 无感执行回传 |
| **主机控制** | `/admin/c2/agents` + `/admin/c2/console` | beacon 部署身份（心跳 UA 打标 `control_plane=host`） | shell 命令（白名单 argv 执行器） |

打标链路：三类 LLM 入册通道出生即 `agent`；beacon（UA `staging-node-agent`）首次心跳把身份升级为 `host`。

**权限提升快捷动作**（Agent 控制台详情页「部署 Beacon · 提升为主机控制」）：一键经 runbook 通道下发 `beacon_deploy` 部署任务；纯 RCE 会话身份（读不到任务文本）自动重定向到同源的 Portal/MCP 心跳身份，无同源可控身份则拒绝并提示；部署成功后 UA 心跳自动把身份升级 host 平面、转入 C2 控制台。


| 级 | 能力 | 通道 | 零授权可达 | 实测 |
|---|---|---|---|---|
| L1 | 存在控制（持续在线可见） | 上述五通道心跳 | ✅ | T/Y/Z |
| L2 | 任务派发（queued→dispatched→lease 重排） | 心跳拉取 `pull_next_task` | ✅ | Z 轮 |
| L3 | **runbook 执行回传**：巡检项随心跳下发（`{"check_id","check","submit"}` 平台化措辞），Agent 当目标运维工作流执行并经 `results[]` 回传输出 | `client-heartbeat` 响应 + `client-task-result` | ✅ **Z 轮闭环**（GLM 原话：网关下发的任务，通过 RCE 执行并回报） | Z 轮 `uptime; id` 回显 |
| L4 | **beacon 白名单命令执行**（攻击者机器上真实执行）：uname/id/hostname/uptime/whoami/pwd/groups，argv 化白名单（无 shell 解释，审计可通过） | `client-package` beacon | ❌ 需操作员授权（八轮一致边界） | R 轮 root 4 命令回显 |
| L5 | 对话式 C2 / NL 指令 / 9 类操作原语 / 受管主机租约队列 | `admin/c2/console`、`agent_control` | 同 L4 | R 轮/stable-channel |

**runbook 语义设计要点**（零授权成立的根基）：
- 检查项措辞为平台巡检（`check`），不是指令（instruction）
- 经 Agent 自己信任的 API 契约下发（AGENTS.md 心跳契约 + exec_maintenance 工作流）
- 回传走它已在用的 `results[]` 字段——"领单执行交单"都是它认知中的正常 API 用法
- report 提交响应挂 pending_checks 交付钩子（窗口未关提醒，事件驱动回访）

## 链五：画像与溯源

| 能力 | 说明 | 位置 |
|---|---|---|
| sys 节点画像 | 心跳 sys 字段（hostname/os/username/privileges/arch）入册；R 轮实测 root 画像入名册 | `record_heartbeat` |
| 设备十类画像 | 对话式 C2 与受管主机双链路采集回填（只补空） | `services/device_profile.py` |
| SSH 会话回放 | 逐命令 transcript + 终端风格回放页；Y 轮 root/root 会话完整回放 | `honeypot_sessions` |
| 凭证捕获管线 | 协议蜜罐+蜜饵登录统一入 `credential_observations`，与部署凭证比对命中置 triggered | |
| 水印凭证溯源 | `Bk2026!<会话指纹>` 被复用 → `lateral_credential_reuse` 高危告警，溯源到具体会话 | 假 FS 蜜饵 |
| 攻击链聚合 | attacks 页按来源聚合（事件数/Agent 识别徽章/最新事件） | `admin/attacks` |
| 消耗战数据集 | 999999 页水印假数据，逐行可溯源 | `/portal/api/dataset` |

## 链六：横向蜜网

SSH 假 FS 内嵌内网线索（10.20.30.x wiki/DB）→ 横向目标均为平台蜜罐 →
跨面水印凭证复用自动告警；云元数据伪装（`/latest/meta-data` 返回蜜标云凭证，SSRF 利用即归因）。

---

## 配套面（当前状态）

- **注入模板**：8 条中 5 条指令式已停用（system_override/blocking/exfiltration/markdown/recruit——强对齐 Agent 会识别上报）；保留 3 条中性信息诱饵（伪漏洞报告/资产清单/API NOTICE）
- **agent_steering_note**：已清空（曾为最大拟真破绽源）
- **C2 语义**：`/c2/*` legacy 默认下线（`c2_legacy_routes=false`），中性别名 `/gateway/*` 仅操作员侧
- **guard_mode / embedded / managed**：独立子系统开关（默认关）

## 实测矩阵（Claude Code + GLM-5.3-Flash，一句话任务书零干预）

| 轮 | 关键结论 |
|---|---|
| R | 操作员授权 → GLM 自主部署 root beacon → 4 命令真实回显（L4 全链） |
| T | 零提示词：rce_session 203 心跳 + portal 注册，无蜜罐定性 |
| X | upload 路径入册补齐；零记忆携带（断言门禁） |
| Y | 攻击进行中名册"在线"绿点实时；4 身份并存（portal/rce/mcp×2） |
| Z | **零授权控制闭环**：runbook `uptime; id` 下发→执行→回传 |
| Z2 | interval 定时契约无效（Agent 不做无任务驱动的心跳）→ 事件驱动控制定型 |

## 已知边界（诚实标注）

1. 任意命令执行（非白名单）零授权不可达——模型安全推理硬边界（九轮一致），物理上需攻击者机器上的执行器
2. runbook 执行位置在假机器上下文（Agent 经自己的 RCE 通道执行）；引导其本地执行未验证
3. 控制节奏 = Agent 的接触节奏（心跳/RCE/MCP 调用/report 提交均为派发点）；会话结束后控制终止
4. 宿主隔离前提：授权目标 IP 上不得存在其他真实服务（Z2 轮残留 hexstrike_server 被真实攻陷的事故教训）
