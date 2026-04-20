# syntax=docker/dockerfile:1.7

# ---- Build stage ----
# We use python:3.12-slim (not alpine) because alpine's musl libc breaks
# wheels for numpy/scipy/pandas, which the v1.1+ correlator will need.
# Slim is a Debian-based image with just enough to install pip wheels.
FROM python:3.12-slim AS build

ARG VERSION=1.0.0

WORKDIR /build

# Install build deps only in the build stage. We use --no-install-recommends
# to keep the layer small, and we never apt-get update without an immediate
# install in the same RUN to avoid stale package lists in cached layers.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create a virtualenv we can copy whole into the runtime stage. This is
# the cleanest way to ship Python apps in distroless: one self-contained
# directory with the interpreter's site-packages.
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY main.py ./
COPY arhiax_correlator/ ./arhiax_correlator/

# Pre-compile to .pyc so the runtime image does not write to its FS on
# first import (matters because the chart enforces readOnlyRootFilesystem).
RUN python -m compileall -q /opt/venv /build

# ---- Runtime stage ----
# distroless/python3-debian12:nonroot ships Python 3.11 + the absolute
# minimum runtime. No shell, no pip, no apt. Around ~50 MB final image.
FROM gcr.io/distroless/python3-debian12:nonroot

ARG VERSION=1.0.0
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="arhiax-correlator" \
      org.opencontainers.image.description="ARHIAX Correlator — D-TCG+ cross-domain anomaly detection (v1.0.0 stub)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/arhiax/arhiax" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Sinergia Consulting Group S.A.S."

# Chart pins UID 10004 for the correlator. The chart's securityContext
# enforces this; we declare it for docker-run parity.
USER 10004:10004

# Copy the venv from the build stage. Path stays /opt/venv so PYTHONPATH
# resolution does not need any custom config.
COPY --from=build --chown=10004:10004 /opt/venv /opt/venv
COPY --from=build --chown=10004:10004 /build/main.py /app/main.py
COPY --from=build --chown=10004:10004 /build/arhiax_correlator /app/arhiax_correlator

# distroless's python3 entrypoint is /usr/bin/python3 from the base
# image, but we want OUR venv's python (so any future deps are picked
# up from /opt/venv/lib/python3.*). The base image's python is the
# correct one to invoke; the venv's site-packages is added via PYTHONPATH.
ENV PYTHONPATH=/opt/venv/lib/python3.11/site-packages:/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8100 9100

WORKDIR /app

# Distroless python entrypoint is already set to python3, so we only
# pass the script as CMD. This makes `docker run <image>` work directly.
ENTRYPOINT ["/usr/bin/python3", "/app/main.py"]
