#!/bin/bash

# BlackPoint Security Integration Framework - Performance Test Runner
# Version: 1.0.0
# Purpose: Execute comprehensive performance tests across all tiers with enhanced
# concurrent client testing and detailed metrics collection

# Exit on error, undefined variables, and propagate pipe failures
set -euo pipefail
trap 'error_handler $? $LINENO $BASH_COMMAND' ERR

# Import dependencies
source ./setup_test_env.sh
source ./generate_report.sh

# Global variables from specification
readonly TEST_CONFIG_PATH="${TEST_CONFIG_PATH:-../configs/performance.yaml}"
readonly OUTPUT_DIR="${OUTPUT_DIR:-/var/log/blackpoint/performance}"
readonly LOG_LEVEL="${LOG_LEVEL:-info}"
readonly MONITORING_ENDPOINT="${MONITORING_ENDPOINT:-http://localhost:9090}"
readonly TRACING_ENDPOINT="${TRACING_ENDPOINT:-http://localhost:9411}"
readonly MAX_CONCURRENT_CLIENTS="${MAX_CONCURRENT_CLIENTS:-150}"
readonly TEST_DURATION="${TEST_DURATION:-4h}"
readonly RESOURCE_MONITOR_INTERVAL="${RESOURCE_MONITOR_INTERVAL:-5s}"

# Performance thresholds from technical specification
readonly MIN_THROUGHPUT=1000          # >1000 events/second per client
readonly BRONZE_LATENCY_MS=1000       # <1s for Bronze tier
readonly SILVER_LATENCY_MS=5000       # <5s for Silver tier
readonly GOLD_LATENCY_MS=30000        # <30s for Gold tier
readonly MIN_ACCURACY=80              # 80% minimum accuracy
readonly TARGET_AVAILABILITY=99.9     # 99.9% uptime requirement

# Error handler function
error_handler() {
    local exit_code=$1
    local line_no=$2
    local command="$3"
    
    echo "Error occurred in script at line ${line_no}"
    echo "Command: ${command}"
    echo "Exit code: ${exit_code}"
    
    # Log error to monitoring system
    curl -X POST "${MONITORING_ENDPOINT}/api/v1/alerts" \
        -H "Content-Type: application/json" \
        -d "{\"severity\":\"error\",\"test\":\"performance\",\"line\":${line_no},\"exit_code\":${exit_code}}"
        
    cleanup
    exit "${exit_code}"
}

# Setup test environment with enhanced monitoring
setup_environment() {
    local config_path="$1"
    local monitoring_endpoint="$2"
    local tracing_endpoint="$3"
    
    echo "Setting up performance test environment..."
    
    # Validate tool versions
    go version | grep -q "go1.21" || { echo "Error: Go 1.21+ required"; exit 1; }
    k6 version | grep -q "v0.45.0" || { echo "Error: k6 0.45.0+ required"; exit 1; }
    
    # Create output directory structure
    mkdir -p "${OUTPUT_DIR}"/{data,metrics,reports,traces}
    
    # Initialize monitoring
    curl -X POST "${monitoring_endpoint}/api/v1/setup" \
        -H "Content-Type: application/json" \
        -d "{\"test_type\":\"performance\",\"duration\":\"${TEST_DURATION}\"}"
        
    # Initialize distributed tracing
    curl -X POST "${tracing_endpoint}/api/v1/setup" \
        -H "Content-Type: application/json" \
        -d "{\"sampling_rate\":1.0,\"service_name\":\"performance-test\"}"
        
    # Setup resource monitoring
    setup_resource_monitoring "${RESOURCE_MONITOR_INTERVAL}"
    
    echo "Environment setup completed"
    return 0
}

# Execute API benchmarks with enhanced metrics collection
run_api_benchmarks() {
    local concurrent_clients=$1
    local test_duration=$2
    local output_path=$3
    
    echo "Running API benchmarks with ${concurrent_clients} concurrent clients..."
    
    # Execute Bronze tier latency tests
    go test -bench=BenchmarkBronzeTierAPI \
        -benchtime="${test_duration}" \
        -cpu="${concurrent_clients}" \
        ../performance/benchmarks/api_bench.go \
        | tee "${output_path}/bronze_tier.log"
        
    # Validate Bronze tier latency
    grep -q "p95 < ${BRONZE_LATENCY_MS}ms" "${output_path}/bronze_tier.log" \
        || { echo "Error: Bronze tier latency exceeds threshold"; return 1; }
        
    # Execute Silver tier tests
    go test -bench=BenchmarkSilverTierAPI \
        -benchtime="${test_duration}" \
        -cpu="${concurrent_clients}" \
        ../performance/benchmarks/api_bench.go \
        | tee "${output_path}/silver_tier.log"
        
    # Validate Silver tier latency
    grep -q "p95 < ${SILVER_LATENCY_MS}ms" "${output_path}/silver_tier.log" \
        || { echo "Error: Silver tier latency exceeds threshold"; return 1; }
        
    # Execute Gold tier tests
    go test -bench=BenchmarkGoldTierAPI \
        -benchtime="${test_duration}" \
        -cpu="${concurrent_clients}" \
        ../performance/benchmarks/api_bench.go \
        | tee "${output_path}/gold_tier.log"
        
    # Validate Gold tier latency
    grep -q "p95 < ${GOLD_LATENCY_MS}ms" "${output_path}/gold_tier.log" \
        || { echo "Error: Gold tier latency exceeds threshold"; return 1; }
        
    echo "API benchmarks completed successfully"
    return 0
}

# Execute load tests with progressive scaling
run_load_tests() {
    local start_clients=$1
    local max_clients=$2
    local ramp_duration=$3
    local sustained_duration=$4
    
    echo "Running load tests with progressive scaling..."
    
    # Execute baseline single-client test
    k6 run \
        --vus=1 \
        --duration=5m \
        ../performance/load_tests/baseline.js \
        | tee "${OUTPUT_DIR}/baseline_load.log"
        
    # Progressive load testing
    for clients in $(seq "${start_clients}" 10 "${max_clients}"); do
        echo "Testing with ${clients} concurrent clients..."
        
        k6 run \
            --vus="${clients}" \
            --stage-duration="${ramp_duration}" \
            --duration="${sustained_duration}" \
            ../performance/load_tests/concurrent_load.js \
            | tee "${OUTPUT_DIR}/load_${clients}.log"
            
        # Validate throughput
        local throughput
        throughput=$(grep "events_per_second" "${OUTPUT_DIR}/load_${clients}.log" | awk '{print $2}')
        if (( $(echo "${throughput} < ${MIN_THROUGHPUT}" | bc -l) )); then
            echo "Error: Throughput below minimum requirement with ${clients} clients"
            return 1
        fi
        
        # Allow system stabilization
        sleep 30
    done
    
    echo "Load tests completed successfully"
    return 0
}

# Generate comprehensive performance reports
generate_reports() {
    local test_results_path=$1
    local output_format=$2
    local include_graphs=$3
    
    echo "Generating performance reports..."
    
    # Aggregate test results
    ./generate_report.sh \
        "${test_results_path}" \
        "${OUTPUT_DIR}/reports" \
        "production" \
        || { echo "Error: Report generation failed"; return 1; }
        
    # Generate performance graphs if requested
    if [[ "${include_graphs}" == "true" ]]; then
        generate_performance_graphs \
            "${test_results_path}" \
            "${OUTPUT_DIR}/reports/graphs"
    fi
    
    # Archive test artifacts
    tar -czf "${OUTPUT_DIR}/artifacts.tar.gz" \
        -C "${OUTPUT_DIR}" \
        data metrics reports traces
        
    echo "Report generation completed"
    return 0
}

# Cleanup resources and temporary files
cleanup() {
    echo "Cleaning up test resources..."
    
    # Stop monitoring tools
    curl -X POST "${MONITORING_ENDPOINT}/api/v1/cleanup"
    curl -X POST "${TRACING_ENDPOINT}/api/v1/cleanup"
    
    # Compress logs
    find "${OUTPUT_DIR}" -name "*.log" -exec gzip {} \;
    
    # Remove temporary files
    rm -rf "${OUTPUT_DIR}"/data/temp/*
    
    echo "Cleanup completed"
    return 0
}

# Main execution
main() {
    echo "Starting performance test suite..."
    
    # Setup test environment
    setup_environment \
        "${TEST_CONFIG_PATH}" \
        "${MONITORING_ENDPOINT}" \
        "${TRACING_ENDPOINT}" \
        || { echo "Error: Environment setup failed"; exit 1; }
        
    # Run API benchmarks
    run_api_benchmarks \
        "${MAX_CONCURRENT_CLIENTS}" \
        "${TEST_DURATION}" \
        "${OUTPUT_DIR}/data" \
        || { echo "Error: API benchmarks failed"; exit 1; }
        
    # Run load tests
    run_load_tests \
        10 \
        "${MAX_CONCURRENT_CLIENTS}" \
        "5m" \
        "15m" \
        || { echo "Error: Load tests failed"; exit 1; }
        
    # Generate reports
    generate_reports \
        "${OUTPUT_DIR}/data" \
        "json" \
        "true" \
        || { echo "Error: Report generation failed"; exit 1; }
        
    echo "Performance test suite completed successfully"
    return 0
}

# Execute main function
main "$@"