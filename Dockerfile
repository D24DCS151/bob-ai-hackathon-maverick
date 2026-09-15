# THREATICAP — Dockerfile (Phase 2 Hardened)
# Multi-stage build for minimal, hardened production image.
#
# Stage 1: builder — installs all dependencies into an isolated venv
# Stage 2: runtime — copies only the venv and source; no build tools present
#
# Security hardening:
#   - Non-root user (uid 65534 / nobody) — no login shell, no home directory
#   - No build tools, compilers, or package managers in runtime image
#   - Read-only filesystem (enable with --read-only in K8s SecurityContext)
#   - All secrets via environment variables / mounted secrets — never baked in
#   - Health check via lightweight Python httpx call (no curl dependency)
#   - Labels for SBOM / image scanning pipelines

# ---- Stage 1: Builder -------------------------------------------------------
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build tools needed for psycopg2, cryptography, etc.
# These stay in the builder — NOT in the runtime image
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create venv in a well-known location
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip / setuptools first (separate layer for cache efficiency)
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy dependency specification
COPY pyproject.toml ./

# Install core runtime dependencies
RUN pip install --no-cache-dir \
    "pydantic>=2.5.0" \
    "fastapi>=0.109.0" \
    "uvicorn[standard]>=0.27.0" \
    "pyyaml>=6.0.1" \
    "click>=8.1.7" \
    "httpx>=0.26.0"

# Install Phase 2 production dependencies
# All are optional at runtime — system degrades gracefully if absent,
# but production deployments should install the full set.
RUN pip install --no-cache-dir \
    "psycopg2-binary>=2.9.9" \
    "redis>=5.0.1" \
    "networkx>=3.2.0" \
    "prometheus-client>=0.19.0" \
    "python-jose[cryptography]>=3.3.0" \
    || echo "Warning: one or more optional production deps failed to install"

# ---- Stage 2: Runtime -------------------------------------------------------
FROM python:3.11-slim AS runtime

# Install runtime-only system libraries (libpq for psycopg2)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Security: use the built-in nobody user (uid 65534, no login, no home)
# For K8s, pair this with runAsNonRoot: true and readOnlyRootFilesystem: true
# in the pod's SecurityContext.
WORKDIR /app

# Copy virtual environment from builder stage (no build tools come with it)
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application source
COPY threaticap/ ./threaticap/
COPY config/ ./config/
COPY data/ ./data/

# Set correct ownership — files owned by root, run as nobody (files are readable)
RUN chown -R root:root /app && chmod -R o+rX /app

# Create a writable temp directory for the nobody user (e.g. for SQLite dev mode)
RUN mkdir -p /tmp/threaticap && chmod 1777 /tmp/threaticap

# Switch to non-root user
USER nobody

# Expose API port (non-privileged — 8080)
EXPOSE 8080

# Runtime environment defaults — override at deployment time.
# NEVER bake secrets into this file. Mount them via Docker secrets,
# Kubernetes secrets, or a secrets manager (Vault, AWS Secrets Manager, etc.)
ENV THREATICAP_CONFIG="/app/config/config.yaml" \
    LOG_LEVEL="INFO" \
    JSON_LOGS="true" \
    HOST="0.0.0.0" \
    PORT="8080" \
    ENVIRONMENT="production" \
    PYTHONUNBUFFERED="1" \
    PYTHONDONTWRITEBYTECODE="1"

# Health check — lightweight Python call, no curl dependency
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD python -c "import httpx; r = httpx.get('http://localhost:8080/api/v1/health', timeout=5); r.raise_for_status()"

# Entrypoint: uvicorn with single worker by default.
# In production with K8s horizontal scaling, keep workers=1 per container
# and scale via replica count. For bare-metal, increase workers here.
CMD ["uvicorn", "threaticap.api.app:app", \
     "--host", "0.0.0.0", \
     "--port", "8080", \
     "--workers", "1", \
     "--log-level", "warning", \
     "--access-log"]

# OCI image labels for SBOM, scanning, and audit pipelines
LABEL org.opencontainers.image.title="THREATICAP" \
      org.opencontainers.image.description="Threat Intelligence Correlation & Alert Prioritisation System" \
      org.opencontainers.image.version="2.0.0" \
      org.opencontainers.image.vendor="Defence Engineering" \
      org.opencontainers.image.licenses="Proprietary" \
      maintainer="THREATICAP Engineering Team"
