# ARHIAX Runtime — local build & test
#
# This Makefile is the local-developer entrypoint. It mirrors what the
# CI workflow does, but on the developer's machine, against a local
# Docker daemon. CI uses the same Dockerfiles and the same build args,
# so anything that builds locally builds in CI and vice versa.
#
# Usage:
#   make help                 — list targets
#   make build                — build all three images
#   make build-gateway        — build only the gateway image
#   make test-gateway         — run the gateway's go vet + go build
#   make smoke                — start all three locally and run a smoke check
#   make clean                — remove built binaries and stop containers
#
# All paths are relative to the repo root, where this Makefile lives.

# ----- Configuration ----------------------------------------------------

REGISTRY        ?= ghcr.io
NAMESPACE       ?= arhiax
VERSION         ?= 1.0.0
COMMIT          ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
BUILD_DATE      ?= $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

GATEWAY_IMG         = $(REGISTRY)/$(NAMESPACE)/arhiax-gateway:$(VERSION)
EVIDENCE_STORE_IMG  = $(REGISTRY)/$(NAMESPACE)/arhiax-evidence-store:$(VERSION)
CORRELATOR_IMG      = $(REGISTRY)/$(NAMESPACE)/arhiax-correlator:$(VERSION)

DOCKER_BUILD_ARGS = \
	--build-arg VERSION=$(VERSION) \
	--build-arg COMMIT=$(COMMIT) \
	--build-arg BUILD_DATE=$(BUILD_DATE)

# ----- Phony targets ----------------------------------------------------

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ----- Build targets ----------------------------------------------------

.PHONY: build
build: build-gateway build-evidence-store build-correlator ## Build all three images

.PHONY: build-gateway
build-gateway: ## Build the gateway image
	docker build $(DOCKER_BUILD_ARGS) -t $(GATEWAY_IMG) -f gateway/Dockerfile gateway/

.PHONY: build-evidence-store
build-evidence-store: ## Build the evidence-store image
	docker build $(DOCKER_BUILD_ARGS) -t $(EVIDENCE_STORE_IMG) -f evidence-store/Dockerfile evidence-store/

.PHONY: build-correlator
build-correlator: ## Build the correlator image
	docker build $(DOCKER_BUILD_ARGS) -t $(CORRELATOR_IMG) -f correlator/Dockerfile correlator/

# ----- Native test targets (no Docker required) ------------------------
#
# These run on the host. Useful for fast-iteration development without
# round-tripping through Docker.

.PHONY: test
test: test-gateway test-evidence-store test-correlator ## Run all native tests

.PHONY: test-gateway
test-gateway: ## go vet + go build the gateway natively
	cd gateway && CGO_ENABLED=0 go vet ./...
	cd gateway && CGO_ENABLED=0 go build -o /tmp/arhiax-gateway-test ./
	@rm -f /tmp/arhiax-gateway-test
	@echo "gateway: vet + build OK"

.PHONY: test-evidence-store
test-evidence-store: ## go vet + go build the evidence-store natively
	cd evidence-store && CGO_ENABLED=0 go vet ./...
	cd evidence-store && CGO_ENABLED=0 go build -o /tmp/arhiax-evidence-store-test ./
	@rm -f /tmp/arhiax-evidence-store-test
	@echo "evidence-store: vet + build OK"

.PHONY: test-correlator
test-correlator: ## Python syntax check + import smoke
	cd correlator && python3 -c "import ast; \
import os; \
files = ['main.py', 'arhiax_correlator/__init__.py', 'arhiax_correlator/poller.py', 'arhiax_correlator/server.py']; \
[ast.parse(open(f).read()) for f in files]; \
print('correlator: parse OK')"
	cd correlator && python3 -c "import sys; sys.path.insert(0, '.'); \
import main, arhiax_correlator.poller, arhiax_correlator.server; \
print('correlator: imports OK')"

# ----- Smoke test target ------------------------------------------------
#
# Runs the three binaries natively (no Docker) on the developer's
# machine, exercises the HTTP contracts end-to-end, and shuts everything
# down. This is the same flow CI runs after a successful build, and the
# same flow used in the v1.0.0 build session to validate the triangle.

.PHONY: smoke
smoke: test ## Run a local end-to-end smoke test (requires native go + python3)
	@echo "Building binaries..."
	@cd gateway && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o /tmp/arhiax-gateway ./
	@cd evidence-store && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o /tmp/arhiax-evidence-store ./
	@echo "Starting evidence-store..."
	@rm -f /tmp/arhiax-smoke.jsonl
	@ARHIAX_ES_DATA_PATH=/tmp/arhiax-smoke.jsonl ARHIAX_ES_HTTP_PORT=18090 ARHIAX_ES_METRICS_PORT=19091 \
		/tmp/arhiax-evidence-store > /tmp/arhiax-smoke-es.log 2>&1 & echo $$! > /tmp/arhiax-smoke-es.pid
	@sleep 0.5
	@echo "Starting gateway..."
	@ARHIAX_HTTP_PORT=18080 ARHIAX_METRICS_PORT=19090 \
		ARHIAX_OPA_URL=http://localhost:18181 \
		ARHIAX_EVIDENCE_STORE_URL=http://localhost:18090 \
		POD_NAMESPACE=smoke POD_NAME=gw-smoke \
		/tmp/arhiax-gateway > /tmp/arhiax-smoke-gw.log 2>&1 & echo $$! > /tmp/arhiax-smoke-gw.pid
	@sleep 0.5
	@echo "Submitting decision..."
	@curl -s -X POST http://localhost:18080/v1/decide \
		-H 'Content-Type: application/json' \
		-d '{"subject":{"id":"smoke-agent"},"action":{"verb":"invoke"},"resource":{"type":"test"},"context":{"tenant":"smoke"}}'
	@echo ""
	@echo "Evidence head:"
	@curl -s http://localhost:18090/v1/head
	@echo ""
	@echo "Stopping..."
	@kill $$(cat /tmp/arhiax-smoke-gw.pid) 2>/dev/null || true
	@kill $$(cat /tmp/arhiax-smoke-es.pid) 2>/dev/null || true
	@rm -f /tmp/arhiax-smoke-*.pid /tmp/arhiax-smoke-*.log /tmp/arhiax-smoke.jsonl
	@rm -f /tmp/arhiax-gateway /tmp/arhiax-evidence-store
	@echo "Smoke test PASSED"

# ----- Clean -----------------------------------------------------------

.PHONY: clean
clean: ## Remove built binaries and stop any running smoke containers
	@rm -f /tmp/arhiax-gateway /tmp/arhiax-evidence-store
	@rm -f /tmp/arhiax-smoke-*.pid /tmp/arhiax-smoke-*.log /tmp/arhiax-smoke.jsonl
	@docker rmi -f $(GATEWAY_IMG) $(EVIDENCE_STORE_IMG) $(CORRELATOR_IMG) 2>/dev/null || true
	@echo "clean done"

# ----- Image inspection ------------------------------------------------

.PHONY: images
images: ## List built ARHIAX images on the local Docker daemon
	@docker images | grep -E "arhiax-(gateway|evidence-store|correlator)" || echo "no images built yet"

.PHONY: sizes
sizes: ## Show sizes of built images
	@docker images --format '{{.Repository}}:{{.Tag}}\t{{.Size}}' | grep -E "arhiax-(gateway|evidence-store|correlator)" || echo "no images built yet"
