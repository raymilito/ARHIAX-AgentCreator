.DEFAULT_GOAL := help
SHELL         := /bin/bash
PROJECT       := arhiax-agentcreator
SERVICES      := aim-service aut-service bbr-service creator-api evidence-store gateway hic-service

# ── Colores ───────────────────────────────────────────────────────────────────
CYAN  := \033[0;36m
GREEN := \033[0;32m
RESET := \033[0m

.PHONY: help up down restart logs ps build pull clean \
        test test-sdk test-services test-rego lint \
        verify-chain env-check certs certs-verify

help: ## Muestra esta ayuda
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-18s$(RESET) %s\n", $$1, $$2}'

# ── Stack ─────────────────────────────────────────────────────────────────────

up: ## Levanta el stack completo en modo daemon
	@echo -e "$(GREEN)▶ Levantando ARHIAX AgentCreator...$(RESET)"
	docker compose up -d
	@echo -e "$(GREEN)✓ Stack listo. Creator API: http://localhost:8300$(RESET)"

down: ## Detiene y elimina los contenedores
	docker compose down

restart: ## Reinicia todos los servicios
	docker compose restart

logs: ## Sigue los logs de todos los servicios (Ctrl+C para salir)
	docker compose logs -f

logs-%: ## Sigue los logs de un servicio específico (ej: make logs-gateway)
	docker compose logs -f $*

ps: ## Estado de los contenedores
	docker compose ps

build: ## Reconstruye las imágenes sin caché
	docker compose build --no-cache

pull: ## Descarga las imágenes base más recientes
	docker compose pull opa

# ── Tests ─────────────────────────────────────────────────────────────────────

test: test-services test-sdk ## Ejecuta todos los tests (servicios + SDK)

test-services: ## Ejecuta tests unitarios de los 7 servicios
	@echo -e "$(GREEN)▶ Tests de servicios...$(RESET)"
	@for svc in $(SERVICES); do \
		echo "  → $$svc"; \
		cd services/$$svc && \
		python -m pytest tests/ -v --tb=short -q 2>&1 | tail -5; \
		cd ../..; \
	done

test-sdk: ## Ejecuta tests unitarios del SDK Python
	@echo -e "$(GREEN)▶ Tests del SDK...$(RESET)"
	cd sdk/python && python -m pytest tests/ -v --tb=short

test-rego: ## Valida los bundles de políticas OPA con opa test
	@echo -e "$(GREEN)▶ Validando políticas Rego...$(RESET)"
	docker run --rm \
		-v "$(PWD)/runtime/bundles:/bundles:ro" \
		openpolicyagent/opa:0.68.0-rootless \
		test /bundles --format pretty

test-%: ## Ejecuta tests de un servicio específico (ej: make test-gateway)
	cd services/$* && python -m pytest tests/ -v --tb=short

lint: ## Ejecuta flake8 y mypy sobre todos los servicios y SDK
	@echo -e "$(GREEN)▶ Lint...$(RESET)"
	@for svc in $(SERVICES); do \
		echo "  → services/$$svc"; \
		cd services/$$svc && python -m flake8 main.py --max-line-length=100 --ignore=E501 2>&1 | head -5; \
		cd ../..; \
	done
	@echo "  → sdk/python"
	cd sdk/python && python -m flake8 arhiax/ --max-line-length=100 --ignore=E501

# ── Utilidades ────────────────────────────────────────────────────────────────

verify-chain: ## Verifica la integridad completa del ledger HMAC
	@echo -e "$(GREEN)▶ Verificando cadena HMAC del Evidence Store...$(RESET)"
	curl -s http://localhost:8090/v1/evidence/verify/chain | python -m json.tool

env-check: ## Verifica que todas las variables de entorno estén configuradas
	@echo -e "$(GREEN)▶ Verificando .env...$(RESET)"
	@test -f .env || (echo "ERROR: falta el archivo .env (copia .env.example)" && exit 1)
	@for var in AIM_HMAC_SECRET EVIDENCE_HMAC_SECRET ANTHROPIC_API_KEY; do \
		grep -q "^$$var=" .env && echo "  ✓ $$var" || echo "  ✗ $$var (FALTA)"; \
	done

create-agent: ## Crea un agente de prueba vía Creator API
	curl -s -X POST http://localhost:8300/v1/agents/create \
		-H "Content-Type: application/json" \
		-d '{"name":"AgentePrueba","department_id":"dept-test","supervisor_id":"supervisor-001","permitted_tools":["consultar_datos"]}' \
		| python -m json.tool

health: ## Verifica el health de todos los servicios
	@echo -e "$(GREEN)▶ Health checks...$(RESET)"
	@for port in 8080 8090 8200 8201 8202 8203 8300; do \
		status=$$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$$port/healthz 2>/dev/null); \
		[ "$$status" = "200" ] \
			&& echo "  ✓ :$$port OK" \
			|| echo "  ✗ :$$port NO RESPONDE ($$status)"; \
	done

certs: ## Genera CA interna y certificados TLS para todos los servicios
	@echo -e "$(GREEN)▶ Generando certificados TLS (requiere openssl)...$(RESET)"
	@bash scripts/generate-certs.sh

certs-verify: ## Verifica que los certificados existentes son válidos y no han expirado
	@echo -e "$(GREEN)▶ Verificando certificados...$(RESET)"
	@test -f certs/ca.crt || (echo "ERROR: ejecuta primero 'make certs'" && exit 1)
	@for svc in aim-service aut-service bbr-service creator-api evidence-store gateway hic-service; do \
		result=$$(openssl verify -CAfile certs/ca.crt certs/$$svc.crt 2>&1); \
		echo "$$result" | grep -q "OK" && echo "  ✓ $$svc.crt" || echo "  ✗ $$svc.crt INVÁLIDO"; \
		exp=$$(openssl x509 -enddate -noout -in certs/$$svc.crt 2>/dev/null | cut -d= -f2); \
		echo "      Expira: $$exp"; \
	done

clean: ## Elimina contenedores, volúmenes y datos locales
	@echo -e "$(GREEN)▶ Limpiando...$(RESET)"
	docker compose down -v --remove-orphans
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete 2>/dev/null; true
	find . -name ".pytest_cache" -type d -exec rm -rf {} + 2>/dev/null; true
	find . -name ".coverage" -delete 2>/dev/null; true
