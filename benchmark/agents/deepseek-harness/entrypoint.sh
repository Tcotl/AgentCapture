#!/bin/sh
echo "[deepseek-harness] target=$TARGET_URL"
python3 agent_benchmark.py \
  --api-base "$BENCH_API_BASE" --api-key "$BENCH_API_KEY" \
  --target "$TARGET_URL" --models deepseek-chat \
  --personas pentest_agent --rounds 1 --out "/results/deepseek-harness.json"
