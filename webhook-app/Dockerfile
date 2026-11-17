
# Stage 1: Builder (Compiles Python venv & fetches static Cosign binary)
FROM python:3.12-slim AS builder

WORKDIR /build

# Install curl to download the official Sigstore Cosign binary
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download Cosign v3.1.4 Linux amd64 binary and make it executable
ARG COSIGN_VERSION=v3.1.4
RUN curl -fsSL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64" \
    -o /usr/local/bin/cosign \
    && chmod +x /usr/local/bin/cosign

# Create isolated virtual environment and install pinned Python dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Stage 2: Hardened Non-Root Runtime Image
FROM python:3.12-slim AS runtime

# Install ca-certificates so Cosign can verify TLS connections to Docker Hub/OCI registries
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged user and group (UID/GID 10001) to satisfy NIST AC-6 non-root policy
RUN groupadd --gid 10001 webhook \
    && useradd --uid 10001 --gid webhook --shell /usr/sbin/nologin --create-home webhook

WORKDIR /app

# Copy compiled Python venv, Cosign binary, and application source from builder
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /usr/local/bin/cosign /usr/local/bin/cosign
COPY --chown=webhook:webhook ./app /app/app

# Activate virtual environment in PATH
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Switch to non-root user
USER 10001

# Unprivileged HTTPS port (8443)
EXPOSE 8443

# Launch Uvicorn with TLS certificates mounted via Kubernetes Secret
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8443", "--ssl-keyfile", "/etc/webhook/certs/tls.key", "--ssl-certfile", "/etc/webhook/certs/tls.crt"]