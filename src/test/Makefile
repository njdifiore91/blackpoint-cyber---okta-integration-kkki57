# BlackPoint Security Integration Framework - Test Suite Makefile
# Version: 1.0.0

# Shell configuration
SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

# Test environment variables
TEST_NAMESPACE ?= blackpoint-test
TEST_TIMEOUT ?= 3600
LOG_FILE ?= /var/log/blackpoint/test-execution.log
TEST_PARALLELISM ?= 4
COVERAGE_THRESHOLD ?= 80
PERFORMANCE_THRESHOLD_BRONZE ?= 1000
PERFORMANCE_THRESHOLD_SILVER ?= 5000
PERFORMANCE_THRESHOLD_GOLD ?= 30000
ACCURACY_THRESHOLD ?= 80
PROMETHEUS_ENDPOINT ?= http://prometheus:9090

# Directory structure
TEST_ROOT := $(shell pwd)
TEST_DATA_DIR := $(TEST_ROOT)/test/data
TEST_CONFIG_DIR := $(TEST_ROOT)/test/configs
TEST_REPORT_DIR := $(TEST_ROOT)/test/reports
TEST_ARTIFACT_DIR := $(TEST_ROOT)/test/artifacts

# External tool versions
GO_VERSION := 1.21
DOCKER_VERSION := 20.0
K6_VERSION := 0.45.0

# Default target
.PHONY: all
all: verify-deps setup-env run-tests cleanup-env

# Dependency verification
.PHONY: verify-deps
verify-deps:
	@echo "Verifying dependencies..."
	@command -v go >/dev/null 2>&1 || { echo "Go $(GO_VERSION)+ is required"; exit 1; }
	@command -v docker >/dev/null 2>&1 || { echo "Docker $(DOCKER_VERSION)+ is required"; exit 1; }
	@command -v kubectl >/dev/null 2>&1 || { echo "kubectl is required"; exit 1; }
	@command -v k6 >/dev/null 2>&1 || { echo "k6 $(K6_VERSION)+ is required"; exit 1; }
	@curl -sf $(PROMETHEUS_ENDPOINT)/-/healthy >/dev/null || { echo "Prometheus is not accessible"; exit 1; }

# Environment setup
.PHONY: setup-env
setup-env: verify-deps
	@echo "Setting up test environment..."
	@mkdir -p $(TEST_DATA_DIR) $(TEST_CONFIG_DIR) $(TEST_REPORT_DIR) $(TEST_ARTIFACT_DIR)
	@chmod 755 $(TEST_ROOT)/scripts/*.sh
	@./scripts/setup_test_env.sh

# Test execution targets
.PHONY: run-tests
run-tests: unit-tests integration-tests performance-tests e2e-tests

.PHONY: unit-tests
unit-tests:
	@echo "Running unit tests..."
	@./scripts/run_tests.sh unit \
		--parallelism=$(TEST_PARALLELISM) \
		--coverage-threshold=$(COVERAGE_THRESHOLD) \
		--report-dir=$(TEST_REPORT_DIR)/unit

.PHONY: integration-tests
integration-tests:
	@echo "Running integration tests..."
	@./scripts/run_tests.sh integration \
		--timeout=$(TEST_TIMEOUT) \
		--accuracy-threshold=$(ACCURACY_THRESHOLD) \
		--report-dir=$(TEST_REPORT_DIR)/integration

.PHONY: performance-tests
performance-tests: setup-monitoring
	@echo "Running performance tests..."
	@./scripts/run_tests.sh performance \
		--bronze-threshold=$(PERFORMANCE_THRESHOLD_BRONZE) \
		--silver-threshold=$(PERFORMANCE_THRESHOLD_SILVER) \
		--gold-threshold=$(PERFORMANCE_THRESHOLD_GOLD) \
		--report-dir=$(TEST_REPORT_DIR)/performance

.PHONY: e2e-tests
e2e-tests:
	@echo "Running end-to-end tests..."
	@./scripts/run_tests.sh e2e \
		--timeout=$(TEST_TIMEOUT) \
		--report-dir=$(TEST_REPORT_DIR)/e2e

# Performance monitoring setup
.PHONY: setup-monitoring
setup-monitoring:
	@echo "Setting up performance monitoring..."
	@cat > $(TEST_CONFIG_DIR)/prometheus.yml << EOF
	global:
	  scrape_interval: 10s
	  evaluation_interval: 10s
	scrape_configs:
	  - job_name: 'blackpoint-tests'
	    static_configs:
	      - targets: ['localhost:8080']
	EOF
	@kubectl apply -f $(TEST_CONFIG_DIR)/prometheus.yml -n $(TEST_NAMESPACE)

# Parallel test execution
.PHONY: parallel-test
parallel-test:
	@echo "Running parallel tests..."
	@for i in $$(seq 1 $(TEST_PARALLELISM)); do \
		$(MAKE) run-tests \
			TEST_NAMESPACE=$(TEST_NAMESPACE)-$$i \
			TEST_REPORT_DIR=$(TEST_REPORT_DIR)/parallel/$$i & \
	done; \
	wait

# Performance validation
.PHONY: validate-performance
validate-performance:
	@echo "Validating performance results..."
	@./scripts/validate_performance.sh \
		--bronze-threshold=$(PERFORMANCE_THRESHOLD_BRONZE) \
		--silver-threshold=$(PERFORMANCE_THRESHOLD_SILVER) \
		--gold-threshold=$(PERFORMANCE_THRESHOLD_GOLD) \
		--report-dir=$(TEST_REPORT_DIR)/performance

# Environment cleanup
.PHONY: cleanup-env
cleanup-env:
	@echo "Cleaning up test environment..."
	@./scripts/cleanup_test_env.sh

# Report generation
.PHONY: generate-report
generate-report:
	@echo "Generating test reports..."
	@mkdir -p $(TEST_REPORT_DIR)/summary
	@./scripts/generate_report.sh \
		--input-dir=$(TEST_REPORT_DIR) \
		--output-dir=$(TEST_REPORT_DIR)/summary \
		--coverage-threshold=$(COVERAGE_THRESHOLD) \
		--accuracy-threshold=$(ACCURACY_THRESHOLD)

# Help target
.PHONY: help
help:
	@echo "BlackPoint Security Integration Framework Test Suite"
	@echo ""
	@echo "Available targets:"
	@echo "  all                  : Run complete test suite with setup and cleanup"
	@echo "  verify-deps          : Verify required dependencies"
	@echo "  setup-env            : Set up test environment"
	@echo "  run-tests            : Run all test suites"
	@echo "  unit-tests           : Run unit tests"
	@echo "  integration-tests    : Run integration tests"
	@echo "  performance-tests    : Run performance tests"
	@echo "  e2e-tests           : Run end-to-end tests"
	@echo "  parallel-test        : Run tests in parallel"
	@echo "  validate-performance : Validate performance results"
	@echo "  cleanup-env         : Clean up test environment"
	@echo "  generate-report     : Generate test summary report"

# Clean target
.PHONY: clean
clean:
	@echo "Cleaning test artifacts..."
	@rm -rf $(TEST_ARTIFACT_DIR)/* $(TEST_REPORT_DIR)/*
	@docker system prune -f --volumes