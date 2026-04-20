# syntax=docker/dockerfile:1.7

# ---- Build stage ----
FROM golang:1.22-alpine AS build

ARG VERSION=1.0.0
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# CGO is OFF here too. We use modernc.org/sqlite (pure-Go SQLite, not
# mattn/go-sqlite3) precisely so the final binary stays statically linked
# and can run on distroless/static. The trade-off is ~10% slower writes
# vs the C bindings, which is irrelevant at our expected QPS for v1.0.0.
ENV CGO_ENABLED=0

WORKDIR /src

COPY go.mod go.sum* ./
RUN go mod download

COPY main.go ./
COPY internal/ ./internal/

RUN go build \
      -trimpath \
      -ldflags="-s -w \
        -X main.version=${VERSION} \
        -X main.commit=${COMMIT} \
        -X main.buildDate=${BUILD_DATE}" \
      -o /out/arhiax-evidence-store \
      ./

# ---- Runtime stage ----
FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=1.0.0
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="arhiax-evidence-store" \
      org.opencontainers.image.description="ARHIAX Evidence Store — append-only Merkle-chained decision log" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/arhiax/arhiax" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Sinergia Consulting Group S.A.S."

# Chart pins UID 10003 for the evidence store. The Helm chart's
# securityContext.runAsUser will enforce this; we declare it here so
# the binary can also run correctly under `docker run` without --user.
USER 10003:10003

COPY --from=build --chown=10003:10003 /out/arhiax-evidence-store /usr/local/bin/arhiax-evidence-store

# Data directory: the chart mounts a PVC at /var/lib/arhiax in sqlite mode.
# We pre-create it so the binary does not have to mkdir at startup
# (which would fail on a read-only root filesystem if /var/lib doesn't
# already exist with the right perms). Distroless ships with /var/lib,
# but /var/lib/arhiax does not exist; the chart's volumeMount creates
# it as the mount point, so this is documentation more than a real op.
# When running under docker without a volume, the binary will create
# the file in the user's home (set via WORKDIR fallback in main.go).

EXPOSE 8090 9091

ENTRYPOINT ["/usr/local/bin/arhiax-evidence-store"]
