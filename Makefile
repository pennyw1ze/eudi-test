# EUDI testbed
#
# Layout:
#   vendor/     official EU reference implementations (cloned, never patched)
#   gateway/    haproxy: one TLS origin in front of the whole stack
#   wallet-core/ software wallet (holder) on the official EUDI JVM libs, plus the
#               console UI that drives the flows and shows the protocol log

SHELL := /bin/bash

# Docker's socket is root-owned unless your user is in the `docker` group. Rather than
# fail on a permission error, fall back to sudo when the daemon is not reachable directly.
# Override explicitly if you need to: make up DOCKER="sudo docker"
DOCKER ?= $(shell docker info >/dev/null 2>&1 && echo docker || echo sudo docker)
COMPOSE := $(DOCKER) compose

# Kept in step with .env, used for the host-side source download.
STATUS_LIST_VERSION := $(shell grep -E '^STATUS_LIST_VERSION=' .env | cut -d= -f2)

ISSUER_REPO   := https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer.git
VERIFIER_REPO := https://github.com/eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-23220-4-kt.git

.DEFAULT_GOAL := help

## ---------------------------------------------------------------- setup

.PHONY: setup
setup: vendor statuslist-src certs ## fetch upstream sources and generate the gateway certificate

.PHONY: vendor
vendor: ## clone/update the official EU reference implementations into ./vendor
	@mkdir -p vendor
	@for spec in "eudi-srv-pid-issuer $(ISSUER_REPO)" "eudi-srv-web-verifier-endpoint-23220-4-kt $(VERIFIER_REPO)"; do \
	  set -- $$spec; dir=vendor/$$1; repo=$$2; \
	  if [ -d "$$dir/.git" ]; then \
	    echo "==> updating $$1"; git -C "$$dir" pull --quiet --ff-only || echo "    (pull skipped)"; \
	  else \
	    echo "==> cloning $$1"; git clone --depth 1 --quiet "$$repo" "$$dir"; \
	  fi; \
	done

.PHONY: statuslist-src
statuslist-src: config/status-list/app.zip config/status-list/get_status_list.py ## fetch the status list source archive on the host

config/status-list/app.zip:
	@echo "==> fetching eudi-srv-statuslist-py $(STATUS_LIST_VERSION)"
	@curl -sfL -o $@ \
	  https://github.com/eu-digital-identity-wallet/eudi-srv-statuslist-py/archive/refs/tags/$(STATUS_LIST_VERSION).zip
	@echo "    $@"

config/status-list/get_status_list.py: vendor/eudi-srv-pid-issuer/docker-compose/status-list/endpoints/get_status_list.py
	@cp $< $@

.PHONY: certs
certs: gateway/certs/localhost.tls.pem ## generate a self-signed certificate for the gateway

gateway/certs/localhost.tls.pem:
	@mkdir -p gateway/certs
	@echo "==> generating self-signed certificate for localhost"
	@openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
	  -keyout gateway/certs/localhost.tls.key \
	  -out    gateway/certs/localhost.tls.crt \
	  -subj   "/CN=localhost/O=EUDI Testbed" \
	  -addext "subjectAltName=DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1" 2>/dev/null
	@cat gateway/certs/localhost.tls.crt gateway/certs/localhost.tls.key > gateway/certs/localhost.tls.pem
	@echo "    gateway/certs/localhost.tls.pem"

## ---------------------------------------------------------------- stack

.PHONY: up
up: check-gateway ## start the full stack (issuer + verifier + gateway)
	$(COMPOSE) --profile issuer --profile verifier up -d --build
	@$(MAKE) --no-print-directory wait

.PHONY: up-issuer
up-issuer: check-gateway ## start only the issuer side + gateway
	$(COMPOSE) --profile issuer up -d --build

.PHONY: up-verifier
up-verifier: check-gateway ## start only the verifier side + gateway
	$(COMPOSE) --profile verifier up -d --build

.PHONY: check-gateway
check-gateway: ## verify every backend the gateway routes to is actually defined
	@defined=$$(grep -oE '^backend [a-z-]+' gateway/haproxy.cfg | awk '{print $$2}' | sort -u); \
	 referenced=$$(grep -oE '(use_backend|default_backend) [a-z-]+' gateway/haproxy.cfg | awk '{print $$2}' | sort -u); \
	 missing=$$(comm -13 <(echo "$$defined") <(echo "$$referenced")); \
	 if [ -n "$$missing" ]; then \
	   echo "gateway/haproxy.cfg routes to undefined backend(s): $$missing"; \
	   echo "haproxy refuses to start with a dangling use_backend, so fix this first."; \
	   exit 1; \
	 fi

.PHONY: down
down: ## stop the stack, keep volumes
	$(COMPOSE) --profile issuer --profile verifier down

.PHONY: clean
clean: ## stop the stack and delete volumes (postgres, status lists)
	$(COMPOSE) --profile issuer --profile verifier down -v

.PHONY: ps
ps: ## show container status
	$(COMPOSE) --profile issuer --profile verifier ps

.PHONY: logs
logs: ## tail logs of the stack (make logs S=pid-issuer for one service)
	$(COMPOSE) --profile issuer --profile verifier logs -f --tail=80 $(S)

.PHONY: wait
wait: ## block until issuer and verifier metadata answer through the gateway
	@echo "==> waiting for the stack to answer on https://localhost"
	@for i in $$(seq 1 90); do \
	  ok=1; \
	  curl -ksf https://localhost/pid-issuer/.well-known/openid-credential-issuer >/dev/null || ok=0; \
	  curl -ksf -o /dev/null https://localhost/verifier/utilities/validations/msoMdoc/deviceResponse -X POST || true; \
	  if [ $$ok = 1 ]; then echo "    issuer metadata OK"; exit 0; fi; \
	  sleep 2; \
	done; \
	echo "    timed out; check 'make logs'"; exit 1

## ---------------------------------------------------------------- checks

.PHONY: doctor
doctor: ## check host prerequisites and report what is missing
	@DOCKER="$(DOCKER)" bash scripts/doctor.sh

.PHONY: diag
diag: ## dump container states and logs to diag.txt for troubleshooting
	@echo "==> writing diag.txt"
	@{ \
	  echo "### compose ps"; \
	  $(COMPOSE) --profile issuer --profile verifier ps -a 2>&1; \
	  echo; echo "### images"; \
	  $(DOCKER) images 2>&1 | grep -E 'status-list|keycloak|pid-issuer|verifier|haproxy|postgres|REPOSITORY' ; \
	  for svc in gateway status-list keycloak postgres pid-issuer verifier-backend verifier-ui; do \
	    echo; echo "### logs: $$svc"; \
	    $(COMPOSE) --profile issuer --profile verifier logs --tail=40 $$svc 2>&1 | tail -45; \
	  done; \
	} > diag.txt 2>&1
	@echo "    diag.txt written ($$(wc -l < diag.txt) lines)"

.PHONY: issuer-log
issuer-log: ## capture recent pid-issuer + keycloak logs for diagnosing failures
	@$(COMPOSE) --profile issuer logs --tail=400 pid-issuer > issuer.log 2>&1
	@$(COMPOSE) --profile issuer logs --tail=400 keycloak > keycloak.log 2>&1
	@echo "    issuer.log ($$(wc -l < issuer.log) lines), keycloak.log ($$(wc -l < keycloak.log) lines)"

.PHONY: smoke
smoke: ## end-to-end check: issue a credential, then present it
	@bash scripts/smoke.sh

## ---------------------------------------------------------------- apps

.PHONY: testbed
testbed: ## run the wallet + console on the host (http://localhost:4000)
	@echo "Starting the testbed. This stays in the foreground — Ctrl+C stops it."
	@echo "Open http://localhost:4000 once you see 'listening' below."
	@echo
	cd wallet-core && ./gradlew run --console=plain -q

.PHONY: build
build: ## compile the wallet without running it
	cd wallet-core && ./gradlew --quiet build -x test

.PHONY: help
help: ## list targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk -F':.*?## ' '{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
