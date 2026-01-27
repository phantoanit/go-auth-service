.PHONY: help build test lint clean run docker-build docker-push proto build-windows build-linux test-windows env-check env-list run-local run-dev run-staging run-prod

# Variables
auth-service := auth-service
DOCKER_REGISTRY ?= ghcr.io/vhvplatform
VERSION ?= $(shell git describe --tags --always --dirty)
GO_VERSION := 1.25

# Environment Management (Default: local)
ENV ?= local

# Detect OS for Windows-specific commands
ifeq ($(OS),Windows_NT)
    BINARY_EXT := .exe
    RM := del /Q
    RMDIR := rmdir /S /Q
    MKDIR := mkdir
    PATHSEP := \\
else
    BINARY_EXT :=
    RM := rm -f
    RMDIR := rm -rf
    MKDIR := mkdir -p
    PATHSEP := /
endif

help: ## Display this help screen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# =============================================================================
# Environment Management
# =============================================================================

env-check: ## Check if .env.{ENV} file exists
	@echo "Checking environment: $(ENV)"
	@if [ ! -f .env.$(ENV) ]; then \
		echo "Error: .env.$(ENV) not found!"; \
		echo "Available environment files:"; \
		ls -1 .env.* 2>/dev/null || echo "No .env files found"; \
		exit 1; \
	fi
	@echo "✓ Environment file found: .env.$(ENV)"

env-list: ## List all .env files
	@echo "Available environment files:"
	@ls -1 .env.* 2>/dev/null || echo "No .env files found"

# =============================================================================
# Build Commands
# =============================================================================

build: ## Build the service (platform-specific)
	@echo "Building $(auth-service)..."
	@go build -o bin/$(auth-service)$(BINARY_EXT) ./cmd/main.go
	@echo "Build complete!"

build-windows: ## Build for Windows
	@echo "Building $(auth-service) for Windows..."
	@set CGO_ENABLED=0
	@set GOOS=windows
	@set GOARCH=amd64
	@go build -ldflags="-s -w" -o bin/$(auth-service).exe ./cmd/main.go
	@echo "Windows build complete: bin/$(auth-service).exe"

build-linux: ## Build for Linux
	@echo "Building $(auth-service) for Linux..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/$(auth-service) ./cmd/main.go
	@echo "Linux build complete: bin/$(auth-service)"

test: ## Run tests
	@echo "Running tests..."
	@go test -v -race ./...

test-windows: ## Run Windows environment tests
	@echo "Running Windows environment tests..."
	@go test -v ./internal/tests

test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	@go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...
	@go tool cover -html=coverage.txt -o coverage.html
	@echo "Coverage report generated: coverage.html"

lint: ## Run linters
	@echo "Running linters..."
	@golangci-lint run ./...

fmt: ## Format code
# =============================================================================
# Run Commands (Environment-aware)
# =============================================================================

run: env-check ## Run with specific environment (usage: make run ENV=dev)
	@echo "Starting $(auth-service) with environment: $(ENV)"
	@APP_ENV=$(ENV) go run ./cmd/main.go

run-local: ## Run with .env.local
	@$(MAKE) run ENV=local

run-dev: ## Run with .env.dev
	@$(MAKE) run ENV=dev

run-staging: ## Run with .env.staging
	@$(MAKE) run ENV=staging

run-prod: ## Run with .env.production
	@$(MAKE) run ENV=production

vet: ## Run go vet
	@echo "Running go vet..."
	@go vet ./...

clean: ## Clean build artifacts
	@echo "Cleaning..."
ifeq ($(OS),Windows_NT)
	@if exist bin $(RMDIR) bin
	@if exist dist $(RMDIR) dist
	@if exist coverage.txt $(RM) coverage.txt
	@if exist coverage.html $(RM) coverage.html
	@if exist *.out $(RM) *.out
else
	@rm -rf bin/ dist/ coverage.* *.out
endif
	@go clean -testcache
	@echo "Clean complete!"

run: ## Run the service locally
	@echo "Running $(auth-service)..."
	@go run ./cmd/main.go

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy

proto: ## Generate protobuf files (if applicable)
	@if [ -d "proto" ]; then \
		echo "Generating protobuf files..."; \
		protoc --go_out=. --go_opt=paths=source_relative \
			--go-grpc_out=. --go-grpc_opt=paths=source_relative \
			proto/*.proto; \
	fi

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	@docker build -t $(DOCKER_REGISTRY)/$(auth-service):$(VERSION) .
	@docker tag $(DOCKER_REGISTRY)/$(auth-service):$(VERSION) $(DOCKER_REGISTRY)/$(auth-service):latest
	@echo "Docker image built: $(DOCKER_REGISTRY)/$(auth-service):$(VERSION)"

docker-push: docker-build ## Push Docker image
	@echo "Pushing Docker image..."
	@docker push $(DOCKER_REGISTRY)/$(auth-service):$(VERSION)
	@docker push $(DOCKER_REGISTRY)/$(auth-service):latest
	@echo "Docker image pushed!"

docker-run: ## Run Docker container locally
	@echo "Running Docker container..."
	@docker run --rm -p 8080:8080 -p 50051:50051 \
		--name $(auth-service) \
		$(DOCKER_REGISTRY)/$(auth-service):latest

install-tools: ## Install development tools
	@echo "Installing development tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@if [ -d "proto" ]; then \
		go install google.golang.org/protobuf/cmd/protoc-gen-go@latest; \
		go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest; \
	fi
	@echo "Tools installed!"

.DEFAULT_GOAL := help
