FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git curl \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/0x4d4d/HexStrike-AI /opt/hexstrike \
    || echo "clone failed — mount your HexStrike source at /opt/hexstrike"
WORKDIR /opt/hexstrike
RUN if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV NAME=hexstrike
ENTRYPOINT ["/entrypoint.sh"]
