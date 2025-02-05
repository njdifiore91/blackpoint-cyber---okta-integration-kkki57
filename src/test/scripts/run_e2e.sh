#!/bin/bash

# BlackPoint Security Integration Framework - E2E Test Runner
# Version: 1.0.0
# Purpose: Execute end-to-end tests validating complete data flow across Bronze, Silver, and Gold tiers
# with enhanced performance metrics collection and concurrent client testing

# Set strict error handling
set -euo pipefail
IFS=$'\n\t'

# Source environment setup script
source "$(dirname "$0")/setup_test_env.sh"

# Global variables
readonly TEST_NAMESPACE="blackpoint-test"
readonly LOG_DIR="/var/log/blackpoint"
readonly TEST_TIMEOUT="30m"
readonly VERBOSE="true"
readonly CLEANUP_ON_FAILURE="true"

# Performance thresholds from technical specifications
readonly BRONZE_LATENCY_THRESHOLD=1
readonly SILVER_LATENCY_THRESHOLD=5
readonly GOLD_LATENCY_THRESHOLD=30
readonly MIN_EVENTS_PER_SECOND=1000
readonly MIN_ACCURACY_THRESHOLD=0.80
readonly MIN_SUCCESS_RATE=0.95

# Color codes for output formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# Initialize logging
init_logging() {
    mkdir -p "${LOG_DIR}"
    local log_file="${LOG_DIR}/e2e_test_$(date +%Y%m%d_%H%M%S).log"
    exec 1> >(tee -a "${log_file}")
    exec 2> >(tee -a "${log_file}" >&2)
}

# Log formatted messages
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo -e "${timestamp} [${level}] ${message}"
}

# Check prerequisites with enhanced version validation
check_prerequisites() {
    log_message "INFO" "Checking prerequisites..."

    # Verify Go installation
    if ! command -v go &> /dev/null; then
        log_message "ERROR" "Go is not installed"
        return 1
    fi
    local go_version=$(go version | awk '{print $3}' | cut -d. -f2)
    if [[ ${go_version} -lt 21 ]]; then
        log_message "ERROR" "Go version must be ≥1.21"
        return 1
    fi

    # Verify kubectl
    if ! command -v kubectl &> /dev/null; then
        log_message "ERROR" "kubectl is not installed"
        return 1
    fi
    if ! kubectl auth can-i get pods &> /dev/null; then
        log_message "ERROR" "Invalid kubectl configuration"
        return 1
    }

    # Verify Docker
    if ! command -v docker &> /dev/null; then
        log_message "ERROR" "Docker is not installed"
        return 1
    fi
    if ! docker info &> /dev/null; then
        log_message "ERROR" "Docker daemon not running"
        return 1
    }

    log_message "INFO" "Prerequisites check passed"
    return 0
}

# Setup test environment with enhanced resource validation
setup_environment() {
    log_message "INFO" "Setting up test environment..."

    # Setup Kubernetes resources
    if ! setup_kubernetes_resources; then
        log_message "ERROR" "Failed to setup Kubernetes resources"
        return 1
    fi

    # Setup storage resources
    if ! setup_storage_resources; then
        log_message "ERROR" "Failed to setup storage resources"
        return 1
    fi

    # Setup streaming resources
    if ! setup_streaming_resources; then
        log_message "ERROR" "Failed to setup streaming resources"
        return 1
    }

    # Wait for all resources to be ready
    local timeout=300
    local interval=5
    local elapsed=0
    
    while [[ ${elapsed} -lt ${timeout} ]]; do
        if kubectl wait --for=condition=ready pods -n "${TEST_NAMESPACE}" --all --timeout=10s &> /dev/null; then
            log_message "INFO" "All resources are ready"
            return 0
        fi
        sleep ${interval}
        elapsed=$((elapsed + interval))
    done

    log_message "ERROR" "Timeout waiting for resources to be ready"
    return 1
}

# Execute E2E tests with enhanced performance metrics collection
run_e2e_tests() {
    log_message "INFO" "Starting E2E test execution..."

    # Initialize metrics collectors
    local start_time=$(date +%s)
    local bronze_latencies=()
    local silver_latencies=()
    local gold_latencies=()
    local total_events=0
    local successful_events=0

    # Execute data flow tests
    log_message "INFO" "Executing data flow validation..."
    
    # Bronze tier testing
    log_message "INFO" "Testing Bronze tier processing..."
    local bronze_start=$(date +%s.%N)
    if ! go test ./test/e2e/data_flow_test.go -v -run TestBronzeTier -timeout "${TEST_TIMEOUT}"; then
        log_message "ERROR" "Bronze tier tests failed"
        return 1
    fi
    local bronze_end=$(date +%s.%N)
    local bronze_latency=$(echo "${bronze_end} - ${bronze_start}" | bc)
    bronze_latencies+=("${bronze_latency}")

    # Silver tier testing
    log_message "INFO" "Testing Silver tier processing..."
    local silver_start=$(date +%s.%N)
    if ! go test ./test/e2e/data_flow_test.go -v -run TestSilverTier -timeout "${TEST_TIMEOUT}"; then
        log_message "ERROR" "Silver tier tests failed"
        return 1
    fi
    local silver_end=$(date +%s.%N)
    local silver_latency=$(echo "${silver_end} - ${silver_start}" | bc)
    silver_latencies+=("${silver_latency}")

    # Gold tier testing
    log_message "INFO" "Testing Gold tier processing..."
    local gold_start=$(date +%s.%N)
    if ! go test ./test/e2e/data_flow_test.go -v -run TestGoldTier -timeout "${TEST_TIMEOUT}"; then
        log_message "ERROR" "Gold tier tests failed"
        return 1
    fi
    local gold_end=$(date +%s.%N)
    local gold_latency=$(echo "${gold_end} - ${gold_start}" | bc)
    gold_latencies+=("${gold_latency}")

    # Calculate and validate metrics
    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))
    
    # Calculate average latencies
    local avg_bronze_latency=$(echo "${bronze_latencies[@]}" | jq -n '[inputs] | add/length')
    local avg_silver_latency=$(echo "${silver_latencies[@]}" | jq -n '[inputs] | add/length')
    local avg_gold_latency=$(echo "${gold_latencies[@]}" | jq -n '[inputs] | add/length')

    # Validate latency requirements
    if (( $(echo "${avg_bronze_latency} > ${BRONZE_LATENCY_THRESHOLD}" | bc -l) )); then
        log_message "ERROR" "Bronze tier latency exceeded threshold: ${avg_bronze_latency}s > ${BRONZE_LATENCY_THRESHOLD}s"
        return 1
    fi
    if (( $(echo "${avg_silver_latency} > ${SILVER_LATENCY_THRESHOLD}" | bc -l) )); then
        log_message "ERROR" "Silver tier latency exceeded threshold: ${avg_silver_latency}s > ${SILVER_LATENCY_THRESHOLD}s"
        return 1
    fi
    if (( $(echo "${avg_gold_latency} > ${GOLD_LATENCY_THRESHOLD}" | bc -l) )); then
        log_message "ERROR" "Gold tier latency exceeded threshold: ${avg_gold_latency}s > ${GOLD_LATENCY_THRESHOLD}s"
        return 1
    fi

    # Generate test report
    generate_test_report "${total_duration}" "${avg_bronze_latency}" "${avg_silver_latency}" "${avg_gold_latency}"

    log_message "INFO" "E2E tests completed successfully"
    return 0
}

# Generate comprehensive test report
generate_test_report() {
    local duration=$1
    local bronze_latency=$2
    local silver_latency=$3
    local gold_latency=$4

    local report_file="${LOG_DIR}/e2e_test_report_$(date +%Y%m%d_%H%M%S).json"
    
    cat > "${report_file}" << EOF
{
    "test_execution": {
        "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
        "duration_seconds": ${duration},
        "status": "success"
    },
    "performance_metrics": {
        "latencies": {
            "bronze_tier": ${bronze_latency},
            "silver_tier": ${silver_latency},
            "gold_tier": ${gold_latency}
        },
        "thresholds_met": {
            "bronze_tier": $(( $(echo "${bronze_latency} <= ${BRONZE_LATENCY_THRESHOLD}" | bc -l) )),
            "silver_tier": $(( $(echo "${silver_latency} <= ${SILVER_LATENCY_THRESHOLD}" | bc -l) )),
            "gold_tier": $(( $(echo "${gold_latency} <= ${GOLD_LATENCY_THRESHOLD}" | bc -l) ))
        }
    }
}
EOF

    log_message "INFO" "Test report generated: ${report_file}"
}

# Cleanup resources
cleanup_resources() {
    local exit_code=$1
    
    if [[ "${CLEANUP_ON_FAILURE}" == "true" || ${exit_code} -eq 0 ]]; then
        log_message "INFO" "Cleaning up test resources..."
        
        # Archive test artifacts
        local archive_dir="${LOG_DIR}/archives/$(date +%Y%m%d_%H%M%S)"
        mkdir -p "${archive_dir}"
        cp -r "${LOG_DIR}"/*.{log,json} "${archive_dir}/" 2>/dev/null || true
        
        # Remove test namespace
        kubectl delete namespace "${TEST_NAMESPACE}" --timeout=5m || true
        
        log_message "INFO" "Cleanup completed"
    else
        log_message "WARN" "Skipping cleanup due to test failure and CLEANUP_ON_FAILURE=false"
    fi
}

# Main execution
main() {
    local exit_code=0

    # Initialize logging
    init_logging

    # Execute test phases
    if ! check_prerequisites; then
        log_message "ERROR" "Prerequisites check failed"
        exit_code=1
    elif ! setup_environment; then
        log_message "ERROR" "Environment setup failed"
        exit_code=1
    elif ! run_e2e_tests; then
        log_message "ERROR" "E2E tests failed"
        exit_code=1
    fi

    # Cleanup resources
    cleanup_resources ${exit_code}

    exit ${exit_code}
}

# Execute main if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi