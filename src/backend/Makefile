# BlackPoint Security Integration Framework
# Backend Services Makefile
# Version: 1.0.0

# Environment variables
SHELL := /bin/bash
COMPONENTS := analyzer collector normalizer
REGISTRY ?= # AWS ECR registry URL must be set
GO_TEST_FLAGS := -v -race -timeout=30m -coverprofile=coverage.out
DOCKER_BUILDKIT := 1
MIN_COVERAGE := 80
MAX_SIZE_API := 50
MAX_SIZE_PROCESSOR := 100
MAX_SIZE_COLLECTOR := 75
PARALLEL_JOBS := 4
SCAN_SEVERITY := HIGH,CRITICAL

# Default target
.PHONY: all
all: clean build test scan validate-size

# Build all components with optimized settings
.PHONY: build
build:
	@echo "Building BlackPoint backend components..."
	@for component in $(COMPONENTS); do \
		echo "Building $$component..."; \
		DOCKER_BUILDKIT=1 ./scripts/build.sh build_image \
			--component=$$component \
			--registry=$(REGISTRY) \
			--parallel=$(PARALLEL_JOBS) || exit 1; \
	done

# Run comprehensive tests with coverage validation
.PHONY: test
test:
	@echo "Running tests with coverage validation..."
	@go test $(GO_TEST_FLAGS) ./...
	@coverage=$$(go tool cover -func=coverage.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	if [ $${coverage%.*} -lt $(MIN_COVERAGE) ]; then \
		echo "Test coverage $${coverage}% below minimum $(MIN_COVERAGE)%"; \
		exit 1; \
	fi

# Security scan of built images
.PHONY: scan
scan:
	@echo "Running security scans..."
	@for component in $(COMPONENTS); do \
		echo "Scanning $$component..."; \
		trivy image \
			--severity $(SCAN_SEVERITY) \
			--exit-code 1 \
			$(REGISTRY)/$$component:latest || exit 1; \
	done

# Validate container sizes
.PHONY: validate-size
validate-size:
	@echo "Validating container sizes..."
	@for component in $(COMPONENTS); do \
		echo "Checking $$component size..."; \
		case $$component in \
			"analyzer") max_size=$(MAX_SIZE_API);; \
			"processor") max_size=$(MAX_SIZE_PROCESSOR);; \
			"collector") max_size=$(MAX_SIZE_COLLECTOR);; \
		esac; \
		./scripts/build.sh validate_size \
			--component=$$component \
			--max-size=$$max_size || exit 1; \
	done

# Deploy components to Kubernetes
.PHONY: deploy
deploy:
	@echo "Deploying components..."
	@./scripts/deploy.sh deploy_all \
		--namespace=blackpoint-system \
		--components="$(COMPONENTS)" || exit 1
	@for component in $(COMPONENTS); do \
		./scripts/deploy.sh health_check \
			--component=$$component \
			--timeout=300s || exit 1; \
	done

# Deploy a single component
.PHONY: deploy-%
deploy-%:
	@echo "Deploying $*..."
	@./scripts/deploy.sh deploy_component \
		--component=$* \
		--namespace=blackpoint-system || exit 1
	@./scripts/deploy.sh health_check \
		--component=$* \
		--timeout=300s || exit 1

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -f coverage.out
	@rm -rf dist/
	@docker system prune -f

# Generate protobuf files
.PHONY: proto
proto:
	@echo "Generating protobuf files..."
	@protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/*.proto

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@gofmt -s -w .

# Run linters
.PHONY: lint
lint:
	@echo "Running linters..."
	@golangci-lint run --timeout=5m

# Generate documentation
.PHONY: docs
docs:
	@echo "Generating documentation..."
	@go doc -all > docs/API.md

# Help target
.PHONY: help
help:
	@echo "BlackPoint Security Integration Framework Makefile"
	@echo "Available targets:"
	@echo "  all            : Build, test, scan and validate all components"
	@echo "  build          : Build all components"
	@echo "  test           : Run tests with coverage validation"
	@echo "  scan           : Run security scans on images"
	@echo "  validate-size  : Validate container sizes"
	@echo "  deploy         : Deploy all components"
	@echo "  deploy-<comp>  : Deploy specific component"
	@echo "  clean          : Clean build artifacts"
	@echo "  proto          : Generate protobuf files"
	@echo "  fmt            : Format code"
	@echo "  lint           : Run linters"
	@echo "  docs           : Generate documentation"
	@echo "  help           : Show this help message"