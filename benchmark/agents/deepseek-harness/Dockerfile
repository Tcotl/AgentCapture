FROM python:3.12-slim
WORKDIR /app
COPY scripts/agent_benchmark.py /app/
COPY benchmark/agents/deepseek-harness/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV NAME=deepseek-harness
ENTRYPOINT ["/entrypoint.sh"]
