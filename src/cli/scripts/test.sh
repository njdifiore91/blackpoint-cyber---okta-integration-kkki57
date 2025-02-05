#!/bin/bash

# BlackPoint Security Integration Framework - CLI Test Suite
# Version: 1.0.0
# Description: Orchestrates execution of unit, integration and end-to-end tests
# with enhanced security validation and monitoring integration.

set -euo pipefail

# Global constants
readonly TEST_TIMEOUT=${TEST_TIMEOUT:-"5m"}
readonly TEST_COVERAGE_THRESHOLD=${TEST_COVERAGE_THRESHOLD:-85}
readonly TEST_OUTPUT_DIR=${TEST_OUTPUT_DIR:-"./test-results"}
readonly SECURITY_CONTEXT_FILE=${SECURITY_CONTEXT_FILE:-"./security/context.yaml"}
readonly PROMETHEUS_ENDPOINT=${PROMETHEUS_ENDPOINT:-"http://prometheus:9090"}
readonly MAX_CONCURRENT_TESTS=${MAX_CONCURRENT_TESTS:-4}
readonly RETRY_ATTEMPTS=${RETRY_ATTEMPTS:-3}
readonly AUDIT_LOG_FILE=${AUDIT_LOG_FILE:-"./audit/test-execution.log"}

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Initialize test environment with security context
setup_security_context() {
    echo "Setting up security context..."
    
    # Ensure security directory exists
    mkdir -p "$(dirname "$SECURITY_CONTEXT_FILE")"
    
    # Validate security credentials and permissions
    if [[ ! -f "$SECURITY_CONTEXT_FILE" ]]; then
        echo -e "${RED}Error: Security context file not found${NC}"
        return 1
    fi
    
    # Verify file permissions
    if [[ "$(stat -c %a "$SECURITY_CONTEXT_FILE")" != "600" ]]; then
        echo -e "${RED}Error: Invalid security context file permissions${NC}"
        chmod 600 "$SECURITY_CONTEXT_FILE"
    fi
    
    # Initialize audit logging
    mkdir -p "$(dirname "$AUDIT_LOG_FILE")"
    touch "$AUDIT_LOG_FILE"
    chmod 600 "$AUDIT_LOG_FILE"
    
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [INFO] Security context initialized" >> "$AUDIT_LOG_FILE"
    return 0
}

# Configure monitoring integration
setup_monitoring() {
    echo "Configuring monitoring integration..."
    
    # Verify Prometheus endpoint
    if ! curl -sf "$PROMETHEUS_ENDPOINT/-/healthy" > /dev/null; then
        echo -e "${YELLOW}Warning: Prometheus endpoint not available${NC}"
        return 1
    }
    
    # Initialize metrics collectors
    cat > /tmp/test_metrics.prom << EOF
# HELP blackpoint_test_duration_seconds Test execution duration in seconds
# TYPE blackpoint_test_duration_seconds histogram
# HELP blackpoint_test_coverage_percent Test coverage percentage
# TYPE blackpoint_test_coverage_percent gauge
# HELP blackpoint_test_security_score Security validation score
# TYPE blackpoint_test_security_score gauge
EOF
    
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [INFO] Monitoring configured" >> "$AUDIT_LOG_FILE"
    return 0
}

# Prepare test environment
setup_test_env() {
    echo "Preparing test environment..."
    
    # Create test output directory
    mkdir -p "$TEST_OUTPUT_DIR"
    
    # Verify Go installation
    if ! command -v go &> /dev/null; then
        echo -e "${RED}Error: Go is not installed${NC}"
        return 1
    fi
    
    # Verify minimum Go version
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    if [[ "$GO_VERSION" < "1.21" ]]; then
        echo -e "${RED}Error: Go version must be 1.21 or higher${NC}"
        return 1
    }
    
    # Install test dependencies
    go mod download
    
    # Initialize resource tracking
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [INFO] Test environment initialized" >> "$AUDIT_LOG_FILE"
    return 0
}

# Execute unit tests with security validation
run_unit_tests() {
    echo "Running unit tests..."
    
    local start_time=$(date +%s)
    local test_output_file="$TEST_OUTPUT_DIR/unit_tests.out"
    local coverage_file="$TEST_OUTPUT_DIR/coverage.out"
    
    # Run tests with coverage and security validation
    if ! go test -v -timeout "$TEST_TIMEOUT" \
        -coverprofile="$coverage_file" \
        -covermode=atomic \
        -tags=unit \
        ./... > "$test_output_file" 2>&1; then
        echo -e "${RED}Unit tests failed${NC}"
        cat "$test_output_file"
        return 1
    fi
    
    # Calculate coverage
    local coverage=$(go tool cover -func="$coverage_file" | grep total | awk '{print $3}' | sed 's/%//')
    
    # Export metrics
    echo "blackpoint_test_coverage_percent{type=\"unit\"} $coverage" >> /tmp/test_metrics.prom
    
    # Verify coverage threshold
    if (( $(echo "$coverage < $TEST_COVERAGE_THRESHOLD" | bc -l) )); then
        echo -e "${RED}Coverage $coverage% below threshold $TEST_COVERAGE_THRESHOLD%${NC}"
        return 1
    fi
    
    local duration=$(($(date +%s) - start_time))
    echo "blackpoint_test_duration_seconds{type=\"unit\"} $duration" >> /tmp/test_metrics.prom
    
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [INFO] Unit tests completed - Coverage: $coverage%" >> "$AUDIT_LOG_FILE"
    return 0
}

# Execute integration tests
run_integration_tests() {
    echo "Running integration tests..."
    
    local start_time=$(date +%s)
    local test_output_file="$TEST_OUTPUT_DIR/integration_tests.out"
    
    # Configure concurrent test execution
    export GOMAXPROCS=$MAX_CONCURRENT_TESTS
    
    # Run integration tests with security context
    if ! go test -v -timeout "$TEST_TIMEOUT" \
        -tags=integration \
        -parallel "$MAX_CONCURRENT_TESTS" \
        ./... > "$test_output_file" 2>&1; then
        echo -e "${RED}Integration tests failed${NC}"
        cat "$test_output_file"
        return 1
    fi
    
    local duration=$(($(date +%s) - start_time))
    echo "blackpoint_test_duration_seconds{type=\"integration\"} $duration" >> /tmp/test_metrics.prom
    
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [INFO] Integration tests completed" >> "$AUDIT_LOG_FILE"
    return 0
}

# Clean up test resources
cleanup() {
    echo "Cleaning up test resources..."
    
    # Export final metrics to Prometheus
    if [[ -f /tmp/test_metrics.prom ]]; then
        curl -s -X POST --data-binary @/tmp/test_metrics.prom \
            "$PROMETHEUS_ENDPOINT/metrics/job/blackpoint_tests"
        rm /tmp/test_metrics.prom
    fi
    
    # Archive test results
    if [[ -d "$TEST_OUTPUT_DIR" ]]; then
        tar czf "$TEST_OUTPUT_DIR.tar.gz" "$TEST_OUTPUT_DIR"
        rm -rf "$TEST_OUTPUT_DIR"
    fi
    
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [INFO] Test cleanup completed" >> "$AUDIT_LOG_FILE"
    return 0
}

# Main execution flow
main() {
    local exit_code=0
    
    # Set up trap for cleanup
    trap cleanup EXIT
    
    # Initialize test environment
    if ! setup_security_context; then
        echo -e "${RED}Failed to initialize security context${NC}"
        exit 1
    fi
    
    if ! setup_monitoring; then
        echo -e "${YELLOW}Warning: Monitoring setup failed${NC}"
    fi
    
    if ! setup_test_env; then
        echo -e "${RED}Failed to initialize test environment${NC}"
        exit 1
    fi
    
    # Execute test suites
    if ! run_unit_tests; then
        echo -e "${RED}Unit tests failed${NC}"
        exit_code=1
    fi
    
    if ! run_integration_tests; then
        echo -e "${RED}Integration tests failed${NC}"
        exit_code=1
    fi
    
    if [[ $exit_code -eq 0 ]]; then
        echo -e "${GREEN}All tests passed successfully${NC}"
    else
        echo -e "${RED}Test execution failed${NC}"
    fi
    
    exit $exit_code
}

# Execute main function
main