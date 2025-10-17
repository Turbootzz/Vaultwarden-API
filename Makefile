.PHONY: help build run clean test docker-build docker-run docker-push docker-buildx-setup dev tidy

# Variables
APP_NAME=vaultwarden-api
DOCKER_IMAGE=turboot/$(APP_NAME)
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

docker-buildx-setup: ## Setup Docker buildx for cross-platform builds (one-time setup)
	@echo "Setting up Docker buildx..."
	@if ! docker buildx ls | grep -q multiarch; then \
		docker buildx create --name multiarch --use; \
		docker buildx inspect --bootstrap; \
		echo "Buildx setup complete!"; \
	else \
		echo "Buildx builder 'multiarch' already exists"; \
		docker buildx use multiarch; \
	fi

docker-build: docker-buildx-setup ## Build Docker image for AMD64 (production servers)
	@echo "Building Docker image for AMD64 platform: $(DOCKER_IMAGE):$(VERSION)..."
	docker buildx build \
		--platform linux/amd64 \
		--load \
		-t $(DOCKER_IMAGE):$(VERSION) \
		-t $(DOCKER_IMAGE):latest \
		.
	@echo "Docker image built successfully for AMD64"

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

docker-push: docker-buildx-setup ## Build for AMD64 and push Docker image to registry
	@echo "Building and pushing Docker image for AMD64: $(DOCKER_IMAGE):$(VERSION)..."
	docker buildx build \
		--platform linux/amd64 \
		--push \
		-t $(DOCKER_IMAGE):$(VERSION) \
		-t $(DOCKER_IMAGE):latest \
		.
	@echo "Docker image pushed successfully to $(DOCKER_IMAGE):$(VERSION) and $(DOCKER_IMAGE):latest"

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
