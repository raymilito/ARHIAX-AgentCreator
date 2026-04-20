# syntax=docker/dockerfile:1.7

# ---- Build stage ----
FROM golang:1.22-alpine AS build

ARG VERSION=1.0.0
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src

# Cache module downloads
COPY go.mod go.sum* ./
RUN go mod download

# Copy source
COPY main.go ./
COPY internal/ ./internal/

# Static build: CGO off, trim paths, strip symbols, inject version
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
      -trimpath \
      -ldflags="-s -w \
        -X main.version=${VERSION} \
        -X main.commit=${COMMIT} \
        -X main.buildDate=${BUILD_DATE}" \
      -o /out/arhiax-gateway \
      ./

# ---- Runtime stage ----
FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=1.0.0
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="arhiax-gateway" \
      org.opencontainers.image.description="ARHIAX Gateway — policy enforcement point for agentic AI governance" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/arhiax/arhiax" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Sinergia Consulting Group S.A.S."

# Distroless nonroot uses UID 65532 by default.
# The Helm chart pins UID 10001 for the gateway, so we override explicitly.
# Distroless ships /etc/passwd with nonroot=65532; we use numeric UID directly
# since Kubernetes securityContext.runAsUser from the chart will enforce 10001.
USER 10001:10001

COPY --from=build --chown=10001:10001 /out/arhiax-gateway /usr/local/bin/arhiax-gateway

EXPOSE 8080 9090

ENTRYPOINT ["/usr/local/bin/arhiax-gateway"]
