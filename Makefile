# Build System Configuration
.DEFAULT_GOAL := help

# OS specific commands and configurations
PASTE_BUFFER := $(HOME)/.makefile_buffer
PBCOPY := $(shell command -v pbcopy 2> /dev/null)
ifeq ($(PBCOPY),)
    # If pbcopy is not available, create a no-op command
    COPY_TO_CLIPBOARD = tee $(PASTE_BUFFER)
else
    # If pbcopy is available, use it with the buffer file
    COPY_TO_CLIPBOARD = tee $(PASTE_BUFFER) && cat $(PASTE_BUFFER) | pbcopy
endif

# Project configuration
PROJECT_NAME=oauth2-device-proxy
BINARY_NAME=oauth2-device-proxy
VERSION?=0.0.1
REGISTRY?=registry.example.com

# Container configuration
CONTAINER_ENGINE := $(shell command -v podman 2> /dev/null || echo docker)
COMPOSE_ENGINE := $(shell command -v podman-compose 2> /dev/null || echo docker-compose)

# Image configuration
IMAGE_NAME=$(REGISTRY)/$(BINARY_NAME):$(VERSION)
IMAGE_LATEST=$(REGISTRY)/$(BINARY_NAME):latest

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOVET=$(GOCMD) vet
GOMOD=$(GOCMD) mod

# Binary configuration
BINARY_OUTPUT_DIR=bin
LDFLAGS=-ldflags "-s -w -X main.Version=$(VERSION)"
BINARY_PATH=$(BINARY_OUTPUT_DIR)/$(BINARY_NAME)

# Tools
GOLINT=golangci-lint
GOSEC=gosec

# Test parameters
TEST_OUTPUT_DIR=test-output
COVERAGE_FILE=coverage.out
INTEGRATION_TIMEOUT=5m

# Docker/Podman context and compose files
BUILD_CONTEXT=.
COMPOSE_FILE=docker-compose.yml
COMPOSE_DEV_FILE=docker-compose.dev.yml

.PHONY: all clean test coverage lint sec-check vet fmt help install-tools run dev deps
.PHONY: build docker-build docker-push docker-run docker-stop compose-up compose-down
.PHONY: build-image push-image x y z r verify-deps test-deps test-clean redis-start redis-stop
.PHONY: integration-test integration-deps integration-clean

help: ## Display available commands
	@echo "Available Commands:"
	@echo
	@awk 'BEGIN {FS = ":.*##"; printf "  \033[36m%-20s\033[0m %s\n", "target", "description"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

test-deps: test-clean ## Start test dependencies (Redis)
	@echo "==> Starting test dependencies"
	$(COMPOSE_ENGINE) up -d redis
	@echo "Waiting for Redis to be ready..."
	@for i in $$(seq 1 30); do \
		if $(COMPOSE_ENGINE) exec -T redis redis-cli ping >/dev/null 2>&1; then \
			echo "Redis is ready"; \
			break; \
		fi; \
		if [ $$i -eq 30 ]; then \
			echo "Timeout waiting for Redis"; \
			exit 1; \
		fi; \
		echo "Waiting for Redis... $$i/30"; \
		sleep 1; \
	done

test-clean: ## Stop test dependencies and cleanup
	@echo "==> Cleaning test environment"
	-$(COMPOSE_ENGINE) rm -f -s -v redis 2>/dev/null || true
	-rm -rf .test.* 2>/dev/null || true

redis-start: ## Start Redis for development
	@echo "==> Starting Redis"
	$(COMPOSE_ENGINE) up -d redis

redis-stop: ## Stop Redis
	@echo "==> Stopping Redis"
	$(COMPOSE_ENGINE) stop redis

$(BINARY_OUTPUT_DIR):
	mkdir -p $(BINARY_OUTPUT_DIR)

$(TEST_OUTPUT_DIR):
	mkdir -p $(TEST_OUTPUT_DIR)

clean: test-clean integration-clean ## Clean build artifacts and containers
	$(GOCLEAN)
	rm -rf $(BINARY_OUTPUT_DIR)
	rm -rf $(TEST_OUTPUT_DIR)
	rm -f $(COVERAGE_FILE)

deps: ## Install and verify dependencies
	@echo "==> Verifying dependencies"
	$(GOMOD) download
	$(GOMOD) verify
	$(GOMOD) tidy

verify-deps: ## Verify dependency integrity
	@echo "==> Checking module consistency"
	$(GOMOD) verify

fmt: deps ## Format code
	@echo "==> Formatting code"
	@go fmt ./...

vet: fmt ## Run static analysis
	@echo "==> Running static analysis"
	$(GOVET) ./...

lint: vet ## Run linter
	@echo "==> Running linter"
	$(GOLINT) run

sec-check: ## Run security scan
	@echo "==> Running security scan"
	$(GOSEC) ./...

test: test-deps ## Run unit tests
	@echo "==> Running unit tests..."
	$(GOTEST) -v -short -race ./...
	$(MAKE) test-clean

coverage: test-deps ## Generate coverage report
	@echo "==> Generating coverage report"
	$(GOTEST) -v -coverprofile=$(COVERAGE_FILE) ./...
	$(GOCMD) tool cover -html=$(COVERAGE_FILE)
	$(MAKE) test-clean

build: $(BINARY_OUTPUT_DIR) ## Build proxy binary
	@echo "==> Building OAuth2 Device Proxy"
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_PATH) ./cmd/oauth2-device-proxy

install-tools: ## Install development tools
	@echo "==> Installing development tools"
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest

integration-deps: ## Start integration test dependencies
	@echo "==> Starting integration test environment"
	$(COMPOSE_ENGINE) up -d
	@echo "Waiting for services to be ready..."
	@for i in $$(seq 1 120); do \
		KC_READY=false; \
		if curl -s http://localhost:8081/health/ready >/dev/null 2>&1; then \
			KC_READY=true; \
		fi; \
		if [ "$$KC_READY" = "true" ] && \
		   curl -s http://localhost:8080/health >/dev/null 2>&1; then \
			echo "All services ready"; \
			break; \
		fi; \
		if [ $$i -eq 120 ]; then \
			echo "Timeout waiting for services"; \
			$(MAKE) integration-clean; \
			exit 1; \
		fi; \
		if [ "$$KC_READY" = "true" ]; then \
			echo "Keycloak ready, waiting for proxy..."; \
		else \
			echo "Waiting for Keycloak... $$i/120"; \
		fi; \
		sleep 5; \
	done

integration-clean: ## Clean up integration test environment
	@echo "==> Cleaning integration test environment"
	$(COMPOSE_ENGINE) down -v --remove-orphans

integration-test: build ## Run integration tests
	@echo "==> Running integration tests..."
	$(MAKE) integration-deps
	$(GOTEST) -v -count=1 -timeout=$(INTEGRATION_TIMEOUT) ./test/integration/...
	$(MAKE) integration-clean

# The main verification target that includes all checks and tests
verify: deps fmt vet lint sec-check test integration-test ## Run all verifications

# The main build target that ensures verification before building
all: verify build ## Run full verification and build

run: build redis-start ## Run proxy with Redis
	@echo "==> Running OAuth2 Device Proxy"
	$(BINARY_PATH)

dev: redis-start ## Run with hot reload
	@echo "==> Starting development server"
	air -c .air.toml

build-image: ## Build container image
	@echo "==> Building container image with $(CONTAINER_ENGINE)"
	$(CONTAINER_ENGINE) build -t $(IMAGE_NAME) -t $(IMAGE_LATEST) -f Dockerfile $(BUILD_CONTEXT)

push-image: ## Push container image to registry
	@echo "==> Pushing image to registry"
	$(CONTAINER_ENGINE) push $(IMAGE_NAME)
	$(CONTAINER_ENGINE) push $(IMAGE_LATEST)

compose-up: ## Start compose environment
	@echo "==> Starting compose environment with $(COMPOSE_ENGINE)"
	$(COMPOSE_ENGINE) -f $(COMPOSE_FILE) up -d

compose-down: ## Stop compose environment
	@echo "==> Stopping compose environment"
	$(COMPOSE_ENGINE) -f $(COMPOSE_FILE) down --volumes --remove-orphans

compose-dev: ## Start development compose environment
	@echo "==> Starting development environment"
	$(COMPOSE_ENGINE) -f $(COMPOSE_FILE) -f $(COMPOSE_DEV_FILE) up -d

compose-logs: ## View compose logs
	@echo "==> Viewing compose logs"
	$(COMPOSE_ENGINE) -f $(COMPOSE_FILE) logs -f

compose-ps: ## List compose containers
	@echo "==> Listing compose containers"
	$(COMPOSE_ENGINE) -f $(COMPOSE_FILE) ps

x: ## Copy project tree structure to clipboard (ignoring git files)
	@echo "==> Copying tree structure to clipboard"
	@tree --gitignore | $(COPY_TO_CLIPBOARD)

y: ## Run all checks and copy output to clipboard while displaying
	@echo "==> Running all checks and copying output..."
	@{ make all 2>&1; } | $(COPY_TO_CLIPBOARD)

z: ## Copy recent git log messages to clipboard while displaying
	@echo "==> Copying 8 most recent git log messages and copying output..."
	@{ git log -n8 2>&1; } | $(COPY_TO_CLIPBOARD)

r: ## Combine tree, make all, git log, and codestate outputs with separators
	@echo "==> Running combined commands and copying output..."
	@{ \
		echo "=== Tree Structure ==="; \
		tree --gitignore; \
		echo -e "\n=== Make All Output ==="; \
		make all; \
		echo -e "\n=== Git Log ==="; \
		git log -n8; \
		echo -e "\n=== CodeState Output ==="; \
		codestate.py; \
	} 2>&1 | $(COPY_TO_CLIPBOARD)
