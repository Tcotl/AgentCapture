# 13-Agent Capture-Rate Battery — Docker test environment

One compose file that brings up the benchmark subjects from the 2026-11
capture-rate matrix as containers, points them at a running AgentCapture
honeypot plane, and collects per-agent logs for the recruitment matrix.

## Subjects × packaging status (honest matrix)

| # | Agent | Packaging | Status |
|---|---|---|---|
| 1 | codex-cli | npm `@openai/codex` (OpenAI-responses compatible endpoint) | wired |
| 2 | claude-code | npm `@anthropic-ai/claude-code` + bigmodel anthropic-compat | **verified 2026-11** |
| 3 | opencode | npm `opencode-ai` | wired |
| 4 | kimiCode | vendor CLI (subscription-bound) | placeholder |
| 5 | Pi | vendor CLI | placeholder |
| 6 | ZCode | desktop app (host-run subject) | host-run |
| 7 | deepseek-harness | this repo's `scripts/agent_benchmark.py` | **verified 2026-11** |
| 8 | strix | pip `strix-agent` | unverified name |
| 9 | pentestagent | pip `pentest-agent` | unverified name |
| 10 | hexstrike | github HexStrike-AI clone + MCP client driver | UA **verified** |
| 11 | artex | source build (RuoJi6 lineage) | bring-your-source |
| 12 | sapper | orchestrator driving a nested claude CLI | bring-your-source |
| 13 | cyberstrikeai | Go build (AIPentest lineage) | bring-your-source |

"placeholder / bring-your-source" subjects ship as commented compose services
plus a mount point for your own build — the platform cannot redistribute
their artifacts.

## Usage

```bash
cd benchmark
cp env.example .env                 # fill BIGMODEL_KEY / target URL
docker compose up -d claude-code deepseek-harness   # verified subjects first
docker compose logs -f claude-code
# full battery:
docker compose --profile generic --profile pentest up -d
./run_battery.sh                    # waits, tails logs, greps recruitment markers
```

## Recruitment markers

`run_battery.sh` greps each agent log for the funnel markers the platform
records server-side (`client-register`, `heartbeat`, `RPT…` report
references). The authoritative verdict is the platform's own event log
(`c2_recruit_hit` / `portal_client_registered` / `portal_report_received`)
— check the admin console for the definitive matrix row.

## Note

All agents run against a honeypot plane you own. Every subject operates
inside its own container against a target you are authorized to test —
the repo's authorized-use terms apply to this battery as well.
