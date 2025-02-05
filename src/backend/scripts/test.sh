#!/bin/bash

# BlackPoint Security Integration Framework
# Comprehensive Test Suite Runner
# Version: 1.0.0

set -euo pipefail

# Environment variables
export TEST_TIMEOUT=${TEST_TIMEOUT:-"30m"}
export GO_TEST_FLAGS=${GO_TEST_FLAGS:-"-v -race -timeout=30m -parallel=4"}
export TEST_COVERAGE_THRESHOLD=${TEST_COVERAGE_THRESHOLD:-"80"}
export TEST_PACKAGES=${TEST_PACKAGES:-"./..."}
export PERFORMANCE_TEST_DURATION=${PERFORMANCE_TEST_DURATION:-"10m"}
export LOAD_TEST_CLIENTS=${LOAD_TEST_CLIENTS:-"100"}
export BRONZE_LATENCY_THRESHOLD=${BRONZE_LATENCY_THRESHOLD:-"1s"}
export SILVER_LATENCY_THRESHOLD=${SILVER_LATENCY_THRESHOLD:-"5s"}
export GOLD_LATENCY_THRESHOLD=${GOLD_LATENCY_THRESHOLD:-"30s"}
export EVENTS_PER_SECOND_THRESHOLD=${EVENTS_PER_SECOND_THRESHOLD:-"1000"}

# Test result directories
TEST_OUTPUT_DIR="test-results"
COVERAGE_DIR="${TEST_OUTPUT_DIR}/coverage"
PERFORMANCE_DIR="${TEST_OUTPUT_DIR}/performance"
SECURITY_DIR="${TEST_OUTPUT_DIR}/security"

# Initialize test environment
init_test_env() {
    echo "Initializing test environment..."
    mkdir -p "${TEST_OUTPUT_DIR}" "${COVERAGE_DIR}" "${PERFORMANCE_DIR}" "${SECURITY_DIR}"
    
    # Verify required tools
    command -v go >/dev/null 2>&1 || { echo "go is required but not installed"; exit 1; }
    command -v k6 >/dev/null 2>&1 || { echo "k6 is required but not installed"; exit 1; }
    command -v go-junit-report >/dev/null 2>&1 || { echo "go-junit-report is required but not installed"; exit 1; }
}

# Run unit tests with coverage
run_unit_tests() {
    echo "Running unit tests..."
    local test_output="${TEST_OUTPUT_DIR}/unit-tests.out"
    local coverage_output="${COVERAGE_DIR}/coverage.out"
    local junit_output="${TEST_OUTPUT_DIR}/unit-tests.xml"

    # Run tests with coverage
    go test ${GO_TEST_FLAGS} \
        -coverprofile="${coverage_output}" \
        -covermode=atomic \
        ${TEST_PACKAGES} 2>&1 | tee "${test_output}"

    # Generate JUnit report
    cat "${test_output}" | go-junit-report > "${junit_output}"

    # Check coverage threshold
    local coverage_percent=$(go tool cover -func="${coverage_output}" | grep total | awk '{print $3}' | sed 's/%//')
    if (( $(echo "${coverage_percent} < ${TEST_COVERAGE_THRESHOLD}" | bc -l) )); then
        echo "Test coverage ${coverage_percent}% is below threshold ${TEST_COVERAGE_THRESHOLD}%"
        return 1
    fi

    echo "Unit tests completed successfully with ${coverage_percent}% coverage"
    return 0
}

# Run integration tests
run_integration_tests() {
    echo "Running integration tests..."
    local test_output="${TEST_OUTPUT_DIR}/integration-tests.out"
    local junit_output="${TEST_OUTPUT_DIR}/integration-tests.xml"

    # Start required services
    docker-compose -f test/integration/docker-compose.yaml up -d

    # Wait for services to be ready
    sleep 10

    # Run integration tests
    go test ${GO_TEST_FLAGS} \
        -tags=integration \
        ./test/integration/... 2>&1 | tee "${test_output}"

    # Generate JUnit report
    cat "${test_output}" | go-junit-report > "${junit_output}"

    # Cleanup
    docker-compose -f test/integration/docker-compose.yaml down

    echo "Integration tests completed"
}

# Run performance tests
run_performance_tests() {
    echo "Running performance tests..."
    local results_file="${PERFORMANCE_DIR}/performance-results.json"

    # Run k6 performance tests
    k6 run \
        --out json="${results_file}" \
        --vus "${LOAD_TEST_CLIENTS}" \
        --duration "${PERFORMANCE_TEST_DURATION}" \
        test/performance/load-test.js

    # Validate latency requirements
    local bronze_latency=$(jq '.metrics.bronze_latency.avg' "${results_file}")
    local silver_latency=$(jq '.metrics.silver_latency.avg' "${results_file}")
    local gold_latency=$(jq '.metrics.gold_latency.avg' "${results_file}")
    local events_per_second=$(jq '.metrics.events_per_second.avg' "${results_file}")

    # Check latency thresholds
    if (( $(echo "${bronze_latency} > ${BRONZE_LATENCY_THRESHOLD}" | bc -l) )); then
        echo "Bronze tier latency ${bronze_latency}s exceeds threshold ${BRONZE_LATENCY_THRESHOLD}s"
        return 1
    fi
    if (( $(echo "${silver_latency} > ${SILVER_LATENCY_THRESHOLD}" | bc -l) )); then
        echo "Silver tier latency ${silver_latency}s exceeds threshold ${SILVER_LATENCY_THRESHOLD}s"
        return 1
    fi
    if (( $(echo "${gold_latency} > ${GOLD_LATENCY_THRESHOLD}" | bc -l) )); then
        echo "Gold tier latency ${gold_latency}s exceeds threshold ${GOLD_LATENCY_THRESHOLD}s"
        return 1
    fi
    if (( $(echo "${events_per_second} < ${EVENTS_PER_SECOND_THRESHOLD}" | bc -l) )); then
        echo "Events per second ${events_per_second} below threshold ${EVENTS_PER_SECOND_THRESHOLD}"
        return 1
    fi

    echo "Performance tests completed successfully"
}

# Run security tests
run_security_tests() {
    echo "Running security tests..."
    local test_output="${SECURITY_DIR}/security-tests.out"
    local junit_output="${SECURITY_DIR}/security-tests.xml"

    # Run security validation tests
    go test ${GO_TEST_FLAGS} \
        -tags=security \
        ./test/security/... 2>&1 | tee "${test_output}"

    # Generate JUnit report
    cat "${test_output}" | go-junit-report > "${junit_output}"

    echo "Security tests completed"
}

# Main test execution
main() {
    local exit_code=0

    # Initialize test environment
    init_test_env

    # Run test suites
    if ! run_unit_tests; then
        echo "Unit tests failed"
        exit_code=1
    fi

    if ! run_integration_tests; then
        echo "Integration tests failed"
        exit_code=1
    fi

    if ! run_performance_tests; then
        echo "Performance tests failed"
        exit_code=1
    fi

    if ! run_security_tests; then
        echo "Security tests failed"
        exit_code=1
    fi

    # Generate final test report
    echo "Generating test report..."
    {
        echo "Test Suite Results"
        echo "=================="
        echo "Unit Tests: $([ -f ${TEST_OUTPUT_DIR}/unit-tests.xml ] && echo 'PASSED' || echo 'FAILED')"
        echo "Integration Tests: $([ -f ${TEST_OUTPUT_DIR}/integration-tests.xml ] && echo 'PASSED' || echo 'FAILED')"
        echo "Performance Tests: $([ -f ${PERFORMANCE_DIR}/performance-results.json ] && echo 'PASSED' || echo 'FAILED')"
        echo "Security Tests: $([ -f ${SECURITY_DIR}/security-tests.xml ] && echo 'PASSED' || echo 'FAILED')"
    } > "${TEST_OUTPUT_DIR}/test-report.txt"

    exit ${exit_code}
}

# Execute main if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi