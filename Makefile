# PNC3 Secure Agent Tool Gateway
GO      ?= go
PYTHON  ?= python3
.DEFAULT_GOAL := help

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n",$$1,$$2}'

deps: ## Install Go modules and Python + dashboard deps
	$(GO) mod download
	$(PYTHON) -m pip install -r tools/requirements.txt
	cd web && npm install

web: ## Build the dashboard (embedded in the gateway binary)
	cd web && npm run build

build: web ## Build gateway, gatewayctl and bench
	mkdir -p bin
	$(GO) build -o bin/gateway ./cmd/gateway
	$(GO) build -o bin/gatewayctl ./cmd/gatewayctl
	$(GO) build -o bin/bench ./cmd/bench

build-fast: ## Build binaries without rebuilding the dashboard
	mkdir -p bin
	$(GO) build -o bin/gateway ./cmd/gateway
	$(GO) build -o bin/gatewayctl ./cmd/gatewayctl
	$(GO) build -o bin/bench ./cmd/bench

test: ## Run Go unit tests
	$(GO) test ./...

fuzz: ## Fuzz the canonicalizer for 30s
	$(GO) test ./internal/canon -run=xxx -fuzz=FuzzExpand -fuzztime=30s

run: build ## Build, then start the full local stack (tools + attacker + gateway)
	bash scripts/start_local.sh

stop: ## Stop the local stack
	bash scripts/stop_local.sh

bench: ## Run the benchmark across all three baselines (writes results/summary.json)
	bash scripts/run_bench.sh

demo: ## Run the scripted five-step attack demo
	$(PYTHON) demo/run_demo.py

token: ## Mint a dev agent token (AGENT=support-agent)
	./bin/gatewayctl token --agent $(or $(AGENT),support-agent)

verify: ## Verify the audit log chain
	./bin/gatewayctl audit verify

docker-up: ## Build and start everything in Docker
	docker compose up --build

docker-down: ## Stop and remove Docker stack
	docker compose down -v

clean: ## Remove build output and local state
	rm -rf bin state results logs web/dist web/node_modules

.PHONY: help deps web build build-fast test fuzz run stop bench demo token verify docker-up docker-down clean
