# BlackPoint CLI Build System
# Requires: Go 1.21+, Docker, Git 2.0+, Snyk

# Binary and version information
BINARY_NAME := blackpoint-cli
VERSION := $(shell git describe --tags --always --dirty)
BUILD_DATE := $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
GIT_COMMIT := $(shell git rev-parse HEAD)
GO_VERSION := $(shell go version)

# Build settings
COVERAGE_THRESHOLD := 80
DIST_DIR := dist
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64
DOCKER_REGISTRY := blackpoint
DOCKER_IMAGE := $(DOCKER_REGISTRY)/$(BINARY_NAME)

# Build flags with version information
BUILD_FLAGS := -ldflags "-X github.com/blackpoint/cli/pkg/common/version.Version=$(VERSION) \
	-X github.com/blackpoint/cli/pkg/common/version.BuildDate=$(BUILD_DATE) \
	-X github.com/blackpoint/cli/pkg/common/version.GitCommit=$(GIT_COMMIT) \
	-X github.com/blackpoint/cli/pkg/common/version.GoVersion=$(GO_VERSION)"

# Default target
.PHONY: all
all: clean deps build test scan package

# Dependency checking and validation
.PHONY: deps
deps:
	@echo "Validating development environment..."
	@which go >/dev/null || (echo "Error: Go is not installed" && exit 1)
	@which docker >/dev/null || (echo "Error: Docker is not installed" && exit 1)
	@which git >/dev/null || (echo "Error: Git is not installed" && exit 1)
	@which snyk >/dev/null || (echo "Error: Snyk is not installed" && exit 1)
	@go mod download
	@go mod verify

# Build target
.PHONY: build
build:
	@echo "Building $(BINARY_NAME) version $(VERSION)..."
	@mkdir -p $(DIST_DIR)
	@./scripts/build.sh validate_environment
	@for platform in $(PLATFORMS); do \
		GOOS=$$(echo $$platform | cut -d'/' -f1) \
		GOARCH=$$(echo $$platform | cut -d'/' -f2) \
		./scripts/build.sh build_binary "$(BUILD_FLAGS)" "$(DIST_DIR)/$(BINARY_NAME)-$$GOOS-$$GOARCH"; \
	done
	@echo "Build complete. Binaries available in $(DIST_DIR)"

# Test target with coverage
.PHONY: test
test:
	@echo "Running tests with coverage threshold $(COVERAGE_THRESHOLD)%..."
	@./scripts/test.sh run_unit_tests
	@./scripts/test.sh run_integration_tests
	@./scripts/test.sh validate_coverage $(COVERAGE_THRESHOLD)
	@echo "Tests completed successfully"

# Security scanning
.PHONY: scan
scan:
	@echo "Running security scan..."
	@snyk test --severity-threshold=high
	@snyk container test $(DOCKER_IMAGE):$(VERSION) --severity-threshold=high || true
	@echo "Security scan complete"

# Package target
.PHONY: package
package:
	@echo "Packaging $(BINARY_NAME) version $(VERSION)..."
	@for platform in $(PLATFORMS); do \
		GOOS=$$(echo $$platform | cut -d'/' -f1) \
		GOARCH=$$(echo $$platform | cut -d'/' -f2) \
		./scripts/package.sh package_binary "$(DIST_DIR)/$(BINARY_NAME)-$$GOOS-$$GOARCH" "$$GOOS" "$$GOARCH"; \
	done
	@./scripts/package.sh generate_checksums "$(DIST_DIR)"
	@./scripts/package.sh sign_packages "$(DIST_DIR)"
	@echo "Packaging complete"

# Docker build target
.PHONY: docker
docker:
	@echo "Building Docker image $(DOCKER_IMAGE):$(VERSION)..."
	docker build --no-cache \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		-t $(DOCKER_IMAGE):$(VERSION) \
		-t $(DOCKER_IMAGE):latest .
	@echo "Docker build complete"

# Release target
.PHONY: release
release:
	@echo "Preparing release $(VERSION)..."
	@[ "$(VERSION)" != "" ] || (echo "Error: Version tag required" && exit 1)
	@make test
	@make scan
	@make build
	@make package
	@make docker
	@echo "Release $(VERSION) prepared successfully"

# Clean target
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(DIST_DIR)
	@go clean -cache -testcache
	@echo "Clean complete"

# Help target
.PHONY: help
help:
	@echo "BlackPoint CLI Build System"
	@echo "Available targets:"
	@echo "  all        - Build, test, scan and package (default)"
	@echo "  build      - Build CLI binaries for all platforms"
	@echo "  test       - Run tests with coverage validation"
	@echo "  scan       - Run security vulnerability scan"
	@echo "  package    - Create distribution packages"
	@echo "  docker     - Build Docker image"
	@echo "  release    - Prepare release artifacts"
	@echo "  clean      - Remove build artifacts"
	@echo "  help       - Show this help message"