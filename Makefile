.PHONY: help build run clean test docker-build docker-run docker-push dev tidy

# Variables
APP_NAME=vaultwarden-api
DOCKER_IMAGE=yourusername/$(APP_NAME)
VERSION?=latest

help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

tidy: ## Tidy and download Go modules
	go mod tidy
	go mod download

build: tidy ## Build the application binary
	@echo "Building $(APP_NAME)..."
	CGO_ENABLED=0 go build -ldflags="-s -w" -o ./bin/$(APP_NAME) ./cmd/api
	@echo "Build complete: ./bin/$(APP_NAME)"

run: ## Run the application locally (requires .env file)
	@echo "Starting $(APP_NAME)..."
	@if [ ! -f .env ]; then \
		echo "Error: .env file not found. Copy .env.example to .env and configure it."; \
		exit 1; \
	fi
	@set -a && . ./.env && set +a && go run ./cmd/api/main.go

dev: ## Run in development mode with auto-reload (requires air: go install github.com/cosmtrek/air@latest)
	@if ! command -v air > /dev/null; then \
		echo "Installing air for hot reload..."; \
		go install github.com/cosmtrek/air@latest; \
	fi
	@if [ ! -f .env ]; then \
		echo "Error: .env file not found. Copy .env.example to .env and configure it."; \
		exit 1; \
	fi
	air

test: ## Run tests
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -rf ./bin
	rm -f coverage.out coverage.html
	go clean

docker-build: ## Build Docker image
	@echo "Building Docker image $(DOCKER_IMAGE):$(VERSION)..."
	docker build -t $(DOCKER_IMAGE):$(VERSION) .
	docker tag $(DOCKER_IMAGE):$(VERSION) $(DOCKER_IMAGE):latest
	@echo "Docker image built successfully"

docker-run: ## Run Docker container locally
	@if [ ! -f .env ]; then \
		echo "Error: .env file not found. Copy .env.example to .env and configure it."; \
		exit 1; \
	fi
	docker run --rm -it \
		--env-file .env \
		-p 8080:8080 \
		--name $(APP_NAME) \
		$(DOCKER_IMAGE):latest

docker-push: docker-build ## Push Docker image to registry
	@echo "Pushing Docker image $(DOCKER_IMAGE):$(VERSION)..."
	docker push $(DOCKER_IMAGE):$(VERSION)
	docker push $(DOCKER_IMAGE):latest
	@echo "Docker image pushed successfully"

docker-compose-up: ## Start services with docker-compose
	@if [ ! -f .env ]; then \
		echo "Error: .env file not found. Copy .env.example to .env and configure it."; \
		exit 1; \
	fi
	docker-compose up -d

docker-compose-down: ## Stop services with docker-compose
	docker-compose down

docker-compose-logs: ## View docker-compose logs
	docker-compose logs -f

generate-api-key: ## Generate a random API key
	@echo "Generated API key:"
	@openssl rand -base64 32
