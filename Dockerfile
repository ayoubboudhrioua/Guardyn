FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    HOME=/var/lib/guardyn
WORKDIR /srv
COPY requirements.lock.txt .
RUN pip install --no-cache-dir -r requirements.lock.txt typer==0.27.2 rich==15.0.0 \
    && apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system --add safe.directory /sentinel-kit
COPY app ./app
COPY policies ./policies
COPY tools ./tools
COPY observability/live.html ./observability/live.html

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin defender \
    && mkdir -p /var/lib/guardyn/live_runs \
    && chown -R 10001:10001 /var/lib/guardyn
USER 10001:10001

# Mount the official Sentinel checkout read-only at /sentinel-kit and persist
# /var/lib/guardyn/live_runs. Publish this port on host loopback only.
EXPOSE 8090
CMD ["python", "tools/live_dashboard.py", "--kit", "/sentinel-kit", "--runs", "/var/lib/guardyn/live_runs", "--bind", "0.0.0.0", "--port", "8090"]
