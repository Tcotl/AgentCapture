"""Integration artifacts — turn an internet-system ledger row into ready to
paste deployment pieces (E: 台账登记补齐).

The ledger registers intent (domain, upstream, mode, policies); this module
renders the concrete config snippets an operator has to apply elsewhere:
Nginx deception-path mount, DNS records, protocol-honeypot DNAT forwarding
and the Guard-mode enforcement checklist. Everything is plain text on
purpose — the operator copies it onto the boxes they already own.
"""
from __future__ import annotations

from typing import Any

# Deception prefixes proxied to AC (mirrors docs/integration.md §5.1.4).
NGINX_LOCATION_RE = (
    "^/(portal/|recon/|collect/|_trap/|d/|_bait/|_clone/|_agent/"
    "|internal/|docs/runbook-internal\\.md|backup/)"
)

# Protocol honeypot exposure: standard intranet port -> AC honeypot port.
PROTOCOL_DEFAULTS: list[dict[str, Any]] = [
    {"key": "ssh", "label": "SSH", "node_port": 22, "ac_port": 2222},
    {"key": "mysql", "label": "MySQL", "node_port": 3306, "ac_port": 33060},
    {"key": "redis", "label": "Redis", "node_port": 6379, "ac_port": 63790},
    {"key": "ftp", "label": "FTP", "node_port": 21, "ac_port": 2121},
    {"key": "elasticsearch", "label": "ElasticSearch", "node_port": 9200, "ac_port": 19200},
]


def build_artifacts(
    *,
    domain: str,
    upstream_url: str,
    deploy_mode: str = "反向代理无损接入",
    tls_mode: str = "沿用原证书",
    failover_mode: str = "异常自动旁路",
    ac_host: str = "",
    ac_port: int = 4877,
) -> dict[str, str]:
    """Render the four copy-ready artifact blocks for one ledger row."""
    ac = (ac_host or "<AC_IP>").strip()
    base = f"http://{ac}:{ac_port}" if ac_port != 80 else f"http://{ac}"
    domain = (domain or "app.intra.example.com").strip()

    nginx = f"""# --- AgentCapture 欺骗层挂载（{domain}）--------------------------------
# 放入业务 Nginx / 内网入口反代的现有 server {{ }} 内；证书与真实路径不动。
location ~ {NGINX_LOCATION_RE} {{
    proxy_pass {base};
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_http_version 1.1;
}}
location = /static/beacon.js {{ proxy_pass {base}/static/beacon.js; }}
location = /static/recon.js  {{ proxy_pass {base}/static/recon.js; }}

# （可选）方式三：真实页面注入采集脚本 —— sub_filter 与 gzip 互斥
# proxy_set_header Accept-Encoding "";
# sub_filter_once off;
# sub_filter '</body>' '<script defer src="{base}/static/beacon.js" data-collect-url="/collect/beacon"></script></body>';

# Guard 串联（可选）：把真实业务整体交给 AC 执法（GUARD_MODE_ENABLED=true 时）
# location / {{
#     proxy_pass {base};
#     proxy_set_header Host $host;
#     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
# }}
# AC 侧台账 upstream = {upstream_url}｜TLS：{tls_mode}｜回退 = 删除本段后 reload"""

    dns = f"""# 内网 DNS（或测试用 hosts）—— 把业务域名指向 AC
{domain}.  IN  A  <AC_IP>
# hosts 行等价写法：
# <AC_IP>    {domain}
#
# Guard 串联生效条件：客户端解析到的 {domain} 必须是 AC（或其前置层）。
# 回退 = 恢复原解析记录，业务立即脱离欺骗层。"""

    dnat_rules = " \\\n".join(
        f"  iptables -t nat -A PREROUTING -p tcp --dport {item['node_port']:5d} -j DNAT --to-destination <AC_IP>:{item['ac_port']}"
        for item in PROTOCOL_DEFAULTS
    )
    dnat = f"""# 协议蜜罐端口旁挂 —— 在网段内网关/跳板机（root）执行，把标准端口扫描导流到 AC
sysctl -w net.ipv4.ip_forward=1
{dnat_rules}
# 低端口绑定为 AC 容器侧能力：docker compose 服务级 cap_add: [NET_BIND_SERVICE]
# 回退 = 将 -A 换成 -D 逐条删除，或 iptables -t nat -F PREROUTING（谨慎：清空整表）"""

    guard = f"""# Guard 执法串联检查单（{domain}）
# 1) AC .env.docker 追加并重启：
GUARD_MODE_ENABLED=true
TRUST_PROXY_HEADERS=true        # 仅当 4877 只对前置层可达时开启
# 2) 内网 DNS 把 {domain} 指向 AC（见 DNS 产物）
# 3) 台账 upstream 已登记：{upstream_url}
# 4) failover：{failover_mode} —— 注意 AC 进程存活仍是串联前提，核心业务建议先「监测模式」观察
# 5) 验证：
#   curl -sI http://{ac}:{ac_port}/ -H 'Host: {domain}' | grep -i x-agent-capture
#   决策头出现即 Guard 生效；block -> 403 / isolate -> 伪 503 / pass -> 注入后转发
# 6) 回退：关 GUARD_MODE_ENABLED 重启，或把 DNS 切回原业务入口"""

    return {
        "nginx": nginx,
        "dns": dns,
        "dnat": dnat,
        "guard": guard,
        "ac_base": base,
    }
