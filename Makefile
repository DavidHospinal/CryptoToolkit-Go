# ============================================================================
# CryptoToolkit-Go Makefile
# ============================================================================

.PHONY: build test run clean docker setup help

# Variables
APP_NAME=cryptotoolkit
BINARY_DIR=bin
DOCKER_IMAGE=cryptotoolkit-go
GO_VERSION=1.21

# Build commands
build:
@echo "🔨 Building CryptoToolkit..."
@mkdir -p $(BINARY_DIR)
@go build -o $(BINARY_DIR)/$(APP_NAME) cmd/cli/main.go
@echo "✅ Build complete: $(BINARY_DIR)/$(APP_NAME)"

build-all:
@echo "🔨 Building all binaries..."
@mkdir -p $(BINARY_DIR)
@go build -o $(BINARY_DIR)/$(APP_NAME) cmd/cli/main.go
@go build -o $(BINARY_DIR)/$(APP_NAME)-api cmd/api/main.go
@go build -o $(BINARY_DIR)/$(APP_NAME)-web cmd/web/main.go
@echo "✅ All builds complete"

# Test commands
test:
@echo "🧪 Running tests..."
@go test -v -race ./...
@echo "✅ Tests complete"

test-coverage:
@echo "📊 Running tests with coverage..."
@go test -coverprofile=coverage.out ./...
@go tool cover -html=coverage.out -o coverage.html
@echo "✅ Coverage report: coverage.html"

benchmark:
@echo "⚡ Running benchmarks..."
@go test -bench=. -benchmem ./...

# Development commands
run:
@echo "🚀 Running CLI..."
@go run cmd/cli/main.go

run-api:
@echo "🌐 Starting API server..."
@go run cmd/api/main.go

# Demo commands
demo-otp:
@echo "🔐 OTP Demo..."
@go run cmd/cli/main.go otp encrypt "Hello Blockchain!" --explain

demo-hash:
@echo "🔢 Hash Demo..."
@go run cmd/cli/main.go hash sha256 "blockchain" --explain

demo-break:
@echo "🚨 Security Demo..."
@go run cmd/cli/main.go otp demo-break "attack at dawn" "attack at dusk"

# Linting and formatting
lint:
@echo "🔍 Running linter..."
@golangci-lint run

fmt:
@echo "📝 Formatting code..."
@go fmt ./...
@goimports -w .

# Docker commands
docker-build:
@echo "🐳 Building Docker image..."
@docker build -t $(DOCKER_IMAGE) .
@echo "✅ Docker image built: $(DOCKER_IMAGE)"

docker-run:
@echo "🚀 Running in Docker..."
@docker run -it --rm -p 8080:8080 $(DOCKER_IMAGE)

# Dependencies
deps:
@echo "📦 Installing dependencies..."
@go mod download
@go mod tidy

deps-update:
@echo "🔄 Updating dependencies..."
@go get -u ./...
@go mod tidy

# Tools installation
install-tools:
@echo "🛠️ Installing development tools..."
@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
@go install golang.org/x/tools/cmd/goimports@latest
@go install github.com/swaggo/swag/cmd/swag@latest

# Clean commands
clean:
@echo "🧹 Cleaning..."
@rm -rf $(BINARY_DIR)
@rm -f coverage.out coverage.html
@echo "✅ Clean complete"

# Setup commands
setup: deps install-tools
@echo "⚙️ Setting up development environment..."
@echo "✅ Setup complete"

# Quick start
quickstart: setup build demo-otp demo-hash
@echo "🎉 CryptoToolkit is ready!"
@echo "Try: ./bin/$(APP_NAME) --help"

# Release
release:
@echo "🚀 Creating release build..."
@mkdir -p release
@GOOS=windows GOARCH=amd64 go build -o release/$(APP_NAME)-windows-amd64.exe cmd/cli/main.go
@GOOS=linux GOARCH=amd64 go build -o release/$(APP_NAME)-linux-amd64 cmd/cli/main.go
@GOOS=darwin GOARCH=amd64 go build -o release/$(APP_NAME)-darwin-amd64 cmd/cli/main.go
@echo "✅ Release builds complete in ./release/"

# Help
help:
@echo "CryptoToolkit-Go Development Commands:"
@echo ""
@echo "Build Commands:"
@echo "  make build          Build CLI application"
@echo "  make build-all      Build all applications (CLI, API, Web)"
@echo ""
@echo "Test Commands:"
@echo "  make test           Run all tests"
@echo "  make test-coverage  Run tests with coverage report"
@echo "  make benchmark      Run performance benchmarks"
@echo ""
@echo "Development Commands:"
@echo "  make run            Run CLI application"
@echo "  make run-api        Run API server"
@echo "  make fmt            Format code"
@echo "  make lint           Run linter"
@echo ""
@echo "Demo Commands:"
@echo "  make demo-otp       Demo OTP encryption"
@echo "  make demo-hash      Demo SHA-256 hashing"
@echo "  make demo-break     Demo OTP key reuse attack"
@echo ""
@echo "Docker Commands:"
@echo "  make docker-build   Build Docker image"
@echo "  make docker-run     Run in Docker container"
@echo ""
@echo "Utility Commands:"
@echo "  make setup          Setup development environment"
@echo "  make clean          Clean build artifacts"
@echo "  make quickstart     Setup + Build + Demo"
@echo "  make release        Create release builds"
