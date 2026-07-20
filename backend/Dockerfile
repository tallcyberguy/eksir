# Multi-stage Dockerfile for ISOC backend.
# Pinned to Python 3.12 — matches alert-memory-mcp's tested runtime.
# (User host runs 3.14 but containers use a stable LTS-style image.)
#
# IMPORTANT: build context = repo root (one level above `backend/`). This is
# so the image can vendor `vendor/alert-memory-mcp/` into itself, making the
# final image self-contained — no host-folder mount needed at runtime. Run as:
#   docker build -f backend/Dockerfile -t isoc-backend .
# Or via compose: `context: ..` + `dockerfile: backend/Dockerfile`.

# ── Stage 1: build dependencies ─────────────────────────────────────────
FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6 AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        libmagic1 \
        && rm -rf /var/lib/apt/lists/*

COPY backend/pyproject.toml ./
# `--upgrade pip` brings `packaging` into the builder's *system* site-packages.
# When the next pip install runs with `--prefix=/install`, pip sees packaging
# already satisfied and refuses to copy it into /install. The runtime stage
# only COPYs /install, so packaging vanishes — and `limits` (slowapi's dep)
# imports `packaging.version` at startup, crashing on `ModuleNotFoundError`.
# Fix: install packaging explicitly into the prefix with `--ignore-installed`,
# so it lands in /install regardless of what's already in the builder env.
RUN pip install --upgrade pip setuptools wheel \
    && pip install --prefix=/install --ignore-installed packaging \
    && pip install --prefix=/install .

# ── Stage 2: runtime ────────────────────────────────────────────────────
FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app:/opt/alert-memory-mcp \
    DOCKER_HOST=unix:///var/run/docker.sock

# Install the Docker CLI only (no daemon) so we can `docker exec` into the
# host's REMnux container via the mounted /var/run/docker.sock. Keeps the
# image small (~50MB delta) compared to installing docker.io (~400MB).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        libmagic1 \
        ca-certificates \
        curl \
        gnupg \
        nmap \
        # WeasyPrint (branded PDF reports) loads these via ctypes at runtime.
        # Pango/Cairo do the text+vector layout; gdk-pixbuf rasterises the PNG
        # logo; fonts-dejavu is a guaranteed fallback face so text isn't blank.
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libpangoft2-1.0-0 \
        libgdk-pixbuf-2.0-0 \
        libharfbuzz0b \
        shared-mime-info \
        fonts-dejavu-core \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg \
         | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
            https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
         > /etc/apt/sources.list.d/docker.list \
    && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /install /usr/local
COPY backend/isoc_api ./isoc_api
COPY backend/alembic.ini ./
COPY backend/migrations ./migrations
COPY backend/scripts ./scripts

# Vendored alert-memory-mcp source. Embedded into the image so the runtime
# has no dependency on a host-mounted folder — that's the whole point of
# Phase 2 (shippable image via GHCR). Re-sync from
# ~/claude-cyber-space/alert-memory-mcp/ when the upstream source changes.
COPY vendor/alert-memory-mcp /opt/alert-memory-mcp

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["uvicorn", "isoc_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
