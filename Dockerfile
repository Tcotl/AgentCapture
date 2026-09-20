FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOST=0.0.0.0 \
    PORT=4877 \
    DATABASE_URL=sqlite:////data/agent_capture.db

WORKDIR /app

COPY pyproject.toml README.md ./
COPY app ./app
COPY docs ./docs

RUN pip install --upgrade pip \
    && pip install . \
    && adduser --disabled-password --gecos '' appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /app /data

USER appuser

EXPOSE 4877

CMD ["sh", "-c", "uvicorn app.main:app --host ${HOST:-0.0.0.0} --port ${PORT:-4877}"]
