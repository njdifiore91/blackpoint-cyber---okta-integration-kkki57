#!/bin/bash

# BlackPoint Security Integration Framework - Security Test Suite
# Version: 1.0.0

set -euo pipefail

# Global constants
readonly TEST_CONFIG_PATH="../configs/security.yaml"
readonly TEST_TIMEOUT="30m"
readonly TEST_LOG_LEVEL="debug"
readonly TEST_CERT_DIR="../fixtures/certs"
readonly TEST_KMS_KEY_ID="arn:aws:kms:region:account:key/test-key"
readonly TEST_OAUTH_CONFIG="../configs/oauth_test.json"
readonly TEST_METRICS_PATH="../logs/security_metrics.json"

# Required tools
readonly REQUIRED_TOOLS=(
    "go"
    "openssl"
    "aws"
)

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# Test metrics
declare -A TEST_METRICS=(
    ["total_tests"]=0
    ["passed_tests"]=0
    ["failed_tests"]=0
    ["skipped_tests"]=0
)

# Setup test environment with enhanced validation
setup_test_environment() {
    local config_path="$1"
    local aws_profile="$2"

    echo -e "${YELLOW}Setting up test environment...${NC}"

    # Validate required tools
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${RED}Error: Required tool '$tool' not found${NC}"
            return 1
        fi
    done

    # Create test directories
    mkdir -p "$TEST_CERT_DIR" "../logs" "../tmp"

    # Generate test certificates
    if [[ ! -f "$TEST_CERT_DIR/test.key" ]]; then
        openssl req -x509 -newkey rsa:4096 -keyout "$TEST_CERT_DIR/test.key" \
            -out "$TEST_CERT_DIR/test.crt" -days 365 -nodes \
            -subj "/CN=test.blackpoint.security"
    fi

    # Configure AWS credentials
    if [[ -n "$aws_profile" ]]; then
        export AWS_PROFILE="$aws_profile"
    fi

    # Validate configuration file
    if [[ ! -f "$config_path" ]]; then
        echo -e "${RED}Error: Configuration file not found: $config_path${NC}"
        return 1
    fi

    # Set environment variables
    export BLACKPOINT_TEST_CONFIG="$config_path"
    export BLACKPOINT_TEST_TIMEOUT="$TEST_TIMEOUT"
    export BLACKPOINT_TEST_LOG_LEVEL="$TEST_LOG_LEVEL"
    export BLACKPOINT_TEST_CERT_DIR="$TEST_CERT_DIR"
    export BLACKPOINT_TEST_KMS_KEY_ID="$TEST_KMS_KEY_ID"

    echo -e "${GREEN}Test environment setup completed${NC}"
    return 0
}

# Run authentication and authorization tests
run_auth_tests() {
    local test_suite="$1"
    local parallel_tests="$2"

    echo -e "${YELLOW}Running authentication tests...${NC}"
    
    # Set test parameters
    local test_args=(
        "-timeout=$TEST_TIMEOUT"
        "-v"
        "-count=1"
    )

    if [[ "$parallel_tests" == "true" ]]; then
        test_args+=("-parallel=4")
    fi

    # Execute authentication test suite
    if go test "./test/security" \
        -run "^TestAuthenticationSuite$" \
        "${test_args[@]}" \
        -tags=integration; then
        
        ((TEST_METRICS["passed_tests"]++))
        echo -e "${GREEN}Authentication tests passed${NC}"
    else
        ((TEST_METRICS["failed_tests"]++))
        echo -e "${RED}Authentication tests failed${NC}"
        return 1
    fi
}

# Run encryption and data security tests
run_encryption_tests() {
    local test_suite="$1"
    local cert_path="$2"

    echo -e "${YELLOW}Running encryption tests...${NC}"

    # Validate certificate path
    if [[ ! -f "$cert_path" ]]; then
        echo -e "${RED}Error: Certificate not found: $cert_path${NC}"
        return 1
    fi

    # Execute encryption test suite
    if go test "./test/security" \
        -run "^TestTLSConfiguration$|^TestKMSEncryption$|^TestFieldLevelEncryption$" \
        -timeout="$TEST_TIMEOUT" \
        -v \
        -count=1; then
        
        ((TEST_METRICS["passed_tests"]++))
        echo -e "${GREEN}Encryption tests passed${NC}"
    else
        ((TEST_METRICS["failed_tests"]++))
        echo -e "${RED}Encryption tests failed${NC}"
        return 1
    fi
}

# Clean up test resources and environment
cleanup_test_environment() {
    local preserve_logs="$1"

    echo -e "${YELLOW}Cleaning up test environment...${NC}"

    # Archive test results
    if [[ -d "../logs" ]]; then
        local archive_name="security_test_results_$(date +%Y%m%d_%H%M%S).tar.gz"
        tar -czf "../logs/$archive_name" -C "../logs" .
    fi

    # Clean up temporary certificates
    if [[ -d "$TEST_CERT_DIR" && "$preserve_logs" != "true" ]]; then
        rm -rf "$TEST_CERT_DIR"
    fi

    # Clean up temporary files
    rm -rf "../tmp"

    # Generate test report
    generate_test_report

    echo -e "${GREEN}Cleanup completed${NC}"
}

# Generate test metrics report
generate_test_report() {
    local total=$((TEST_METRICS["total_tests"]))
    local passed=${TEST_METRICS["passed_tests"]}
    local failed=${TEST_METRICS["failed_tests"]}
    local skipped=${TEST_METRICS["skipped_tests"]}
    
    local pass_rate=0
    if (( total > 0 )); then
        pass_rate=$(( (passed * 100) / total ))
    fi

    # Create JSON report
    cat > "$TEST_METRICS_PATH" << EOF
{
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "metrics": {
        "total_tests": $total,
        "passed_tests": $passed,
        "failed_tests": $failed,
        "skipped_tests": $skipped,
        "pass_rate": $pass_rate
    },
    "environment": {
        "go_version": "$(go version | cut -d' ' -f3)",
        "test_duration": "$TEST_TIMEOUT",
        "config_path": "$TEST_CONFIG_PATH"
    }
}
EOF

    echo -e "\n${YELLOW}Test Summary:${NC}"
    echo -e "Total Tests: $total"
    echo -e "Passed: ${GREEN}$passed${NC}"
    echo -e "Failed: ${RED}$failed${NC}"
    echo -e "Skipped: ${YELLOW}$skipped${NC}"
    echo -e "Pass Rate: ${pass_rate}%"
}

# Main execution
main() {
    local config_path="${1:-$TEST_CONFIG_PATH}"
    local aws_profile="${2:-}"
    local preserve_logs="${3:-false}"

    # Initialize test metrics
    TEST_METRICS["total_tests"]=0
    
    # Setup test environment
    if ! setup_test_environment "$config_path" "$aws_profile"; then
        echo -e "${RED}Failed to setup test environment${NC}"
        exit 1
    fi

    # Run test suites
    ((TEST_METRICS["total_tests"]++))
    if ! run_auth_tests "authentication" "true"; then
        echo -e "${RED}Authentication tests failed${NC}"
    fi

    ((TEST_METRICS["total_tests"]++))
    if ! run_encryption_tests "encryption" "$TEST_CERT_DIR/test.crt"; then
        echo -e "${RED}Encryption tests failed${NC}"
    fi

    # Cleanup
    cleanup_test_environment "$preserve_logs"

    # Exit with failure if any tests failed
    if (( TEST_METRICS["failed_tests"] > 0 )); then
        echo -e "${RED}Security tests completed with failures${NC}"
        exit 1
    fi

    echo -e "${GREEN}All security tests completed successfully${NC}"
    exit 0
}

# Execute main function with provided arguments
main "$@"