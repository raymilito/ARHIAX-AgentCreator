# =============================================================================
# ARHIAX v11.4 — Agent Trust Kernel Service
# Multi-stage Dockerfile
# Anchors: TR-2026-034-ATK §6 (Performance / SLOs)
# =============================================================================

# ----- Stage 1: builder -----
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Build dependencies (kept in builder layer only)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pin runtime deps. Keep this list minimal: ATK is intentionally lightweight
# (no fastapi-style frameworks in the reference impl). Production deployments
# can swap in fastapi/uvicorn or grpc as needed.
RUN pip install --prefix=/install \
        "uvicorn[standard]==0.32.0" \
        "pytest==8.3.3"

# Copy source — includes Capa 2 (ATK service + B14/B16) and Capa 3 (17 bundles)
COPY arhiax_atk_service.py mcp_interceptor.py demo.py ./
COPY opa_bundles.py ./
COPY test_integration.py test_bundles_b01_b19.py ./
COPY authz.rego authz_test.rego ./
COPY bundles_b01_b19.rego bundles_b01_b19_test.rego ./

# Run BOTH test suites as a build-time gate (OPA-C03 regression).
# If either suite fails, the image build fails. Combined: 116 Python tests
# covering 19/19 bundles (21 integration + 95 bundle unit tests).
RUN PYTHONPATH=/install/lib/python3.12/site-packages \
    python -m pytest test_integration.py test_bundles_b01_b19.py -q


# ----- Stage 2: runtime -----
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="ARHIAX ATK Service" \
      org.opencontainers.image.description="Agent Trust Kernel reference service for ARHIAX v11.4 — 19 OPA/Rego bundles" \
      org.opencontainers.image.version="11.4" \
      org.opencontainers.image.vendor="Sinergia Consulting Group S.A.S." \
      org.opencontainers.image.licenses="Proprietary" \
      arhiax.component="atk" \
      arhiax.bundles="B01-B19" \
      arhiax.controls="ATK-C01,ATK-C02,ATK-C03,ATK-C04,ATK-C05,ATK-C06,ATK-C07,AIM-C01,AIM-C02,AIM-C03,OPA-C01,OPA-C02,OPA-C03,EGA-C01,EGA-C02,EGA-C04,DTG-C01,DTG-C02,DTG-C03,DTG-C04"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ARHIAX_VERSION=11.4 \
    ARHIAX_ATK_PORT=8080 \
    ARHIAX_LOG_LEVEL=INFO

# Non-root user. Production deployments should additionally drop capabilities
# at the orchestrator level (Kubernetes securityContext).
RUN groupadd --system --gid 1000 arhiax \
    && useradd --system --uid 1000 --gid arhiax --home /app --shell /usr/sbin/nologin arhiax

WORKDIR /app

# Bring runtime dependencies from the builder
COPY --from=builder /install /usr/local

# Bring source — Capa 2 + Capa 3
COPY --chown=arhiax:arhiax arhiax_atk_service.py mcp_interceptor.py ./
COPY --chown=arhiax:arhiax opa_bundles.py ./
COPY --chown=arhiax:arhiax authz.rego authz_test.rego ./policies/
COPY --chown=arhiax:arhiax bundles_b01_b19.rego bundles_b01_b19_test.rego ./policies/

USER arhiax

# Health check hits the envelope endpoint with a known invalid payload that
# should fast-fail with 400. This validates that the process is up and the
# HTTP layer is wired correctly.
HEALTHCHECK --interval=10s --timeout=2s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; \
    req = urllib.request.Request('http://127.0.0.1:'+__import__('os').environ.get('ARHIAX_ATK_PORT','8080')+'/v1/envelope/evaluate', \
    data=b'{}', method='POST'); \
    sys.exit(0 if urllib.request.urlopen(req).getcode() in (200,400) else 1)" \
  || exit 1

EXPOSE 8080

# The reference entrypoint uses uvicorn against the build_asgi_app() factory
# wired to in-memory clients. Production deployments override CMD to point
# at a configured factory that wires the real AIM/OPA/BBR/EGA/HIC clients.
CMD ["uvicorn", \
     "--host", "0.0.0.0", \
     "--port", "8080", \
     "--factory", \
     "arhiax_atk_service:_build_default_app"]
