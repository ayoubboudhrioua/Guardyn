FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    SENTINEL_TRACE=/var/lib/guardyn/decisions.jsonl
WORKDIR /srv
COPY requirements.lock.txt .
RUN pip install --no-cache-dir -r requirements.lock.txt
COPY app ./app
COPY policies ./policies
COPY observability/index.html ./observability/index.html

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin defender \
    && mkdir -p /var/lib/guardyn \
    && chown 10001:10001 /var/lib/guardyn
USER 10001:10001

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
