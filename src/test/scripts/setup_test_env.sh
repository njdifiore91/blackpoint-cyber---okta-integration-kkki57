#!/bin/bash

# BlackPoint Security Integration Framework - Test Environment Setup Script
# Version: 1.0.0
# Purpose: Initialize and configure test environment with enhanced performance testing support

# Set strict error handling
set -euo pipefail
trap 'error_handler $? $LINENO $BASH_LINENO "$BASH_COMMAND" $(printf "::%s" ${FUNCNAME[@]:-})' ERR
trap cleanup EXIT

# Global variables
readonly TEST_ROOT=$(pwd)
readonly TEST_CONFIG="../configs/test.yaml"
readonly E2E_CONFIG="../configs/e2e.yaml"
readonly LOG_FILE="/var/log/blackpoint/test.log"
readonly MIN_RAM_GB=16
readonly MIN_DISK_GB=100
readonly REQUIRED_PORTS=(8080 8081 8082 8083 8084 8085 8086 8087 8088 8089 8090)

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# Error handler function
error_handler() {
    local exit_code=$1
    local line_no=$2
    local bash_lineno=$3
    local last_command=$4
    local func_trace=$5

    log_error "Error occurred in script at line ${line_no}"
    log_error "Last command executed: ${last_command}"
    log_error "Exit code: ${exit_code}"
    log_error "Function trace: ${func_trace}"

    cleanup
    exit "${exit_code}"
}

# Logging functions
log_info() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [INFO] $1" | tee -a "${LOG_FILE}"
}

log_error() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [ERROR] $1" | tee -a "${LOG_FILE}"
}

log_warning() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [WARN] $1" | tee -a "${LOG_FILE}"
}

# Initialize logging
init_logging() {
    local log_dir=$(dirname "${LOG_FILE}")
    mkdir -p "${log_dir}"
    touch "${LOG_FILE}"
    chmod 644 "${LOG_FILE}"

    # Set up log rotation
    cat > /etc/logrotate.d/blackpoint-test << EOF
${LOG_FILE} {
    size 100M
    rotate 5
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF
}

# Check dependencies with version validation
check_dependencies() {
    log_info "Checking dependencies..."

    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        return 1
    fi
    local docker_version=$(docker --version | cut -d ' ' -f3 | cut -d '.' -f1)
    if [[ ${docker_version} -lt 24 ]]; then
        log_error "Docker version must be >= 24.0"
        return 1
    fi

    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed"
        return 1
    fi
    local compose_version=$(docker-compose --version | cut -d ' ' -f3 | cut -d '.' -f1)
    if [[ ${compose_version} -lt 2 ]]; then
        log_error "Docker Compose version must be >= 2.20"
        return 1
    }

    # Check yq
    if ! command -v yq &> /dev/null; then
        log_error "yq is not installed"
        return 1
    fi
    local yq_version=$(yq --version | cut -d ' ' -f4 | cut -d '.' -f1)
    if [[ ${yq_version} -lt 4 ]]; then
        log_error "yq version must be >= 4.0"
        return 1
    }

    # Check system resources
    local total_ram_gb=$(free -g | awk '/^Mem:/{print $2}')
    if [[ ${total_ram_gb} -lt ${MIN_RAM_GB} ]]; then
        log_error "Insufficient RAM. Required: ${MIN_RAM_GB}GB, Available: ${total_ram_gb}GB"
        return 1
    }

    local free_disk_gb=$(df -BG "${TEST_ROOT}" | awk 'NR==2 {print $4}' | tr -d 'G')
    if [[ ${free_disk_gb} -lt ${MIN_DISK_GB} ]]; then
        log_error "Insufficient disk space. Required: ${MIN_DISK_GB}GB, Available: ${free_disk_gb}GB"
        return 1
    }

    # Check required ports
    for port in "${REQUIRED_PORTS[@]}"; do
        if netstat -tln | grep -q ":${port} "; then
            log_error "Port ${port} is already in use"
            return 1
        fi
    }

    # Verify kernel parameters
    local max_file_descriptors=$(ulimit -n)
    if [[ ${max_file_descriptors} -lt 65535 ]]; then
        log_error "Insufficient file descriptors. Required: 65535, Current: ${max_file_descriptors}"
        return 1
    }

    log_info "All dependencies checked successfully"
    return 0
}

# Setup directories with proper permissions
setup_directories() {
    log_info "Setting up test directories..."

    local dirs=(
        "data"
        "configs"
        "fixtures"
        "reports"
        "metrics"
        "artifacts/temp"
        "artifacts/concurrent"
    )

    for dir in "${dirs[@]}"; do
        local full_path="${TEST_ROOT}/test/${dir}"
        mkdir -p "${full_path}"
        
        # Set appropriate permissions
        if [[ ${dir} == "configs" ]]; then
            chmod 750 "${full_path}"
        else
            chmod 775 "${full_path}"
        fi
    done

    # Set ownership
    chown -R $(whoami):$(whoami) "${TEST_ROOT}/test"
    
    log_info "Directory setup completed"
    return 0
}

# Configure services with performance optimization
configure_services() {
    local test_config=$1
    local e2e_config=$2
    
    log_info "Configuring services..."

    # Load configurations
    if [[ ! -f ${test_config} ]] || [[ ! -f ${e2e_config} ]]; then
        log_error "Configuration files not found"
        return 1
    }

    # Configure Kafka
    cat > "${TEST_ROOT}/test/configs/kafka.properties" << EOF
num.partitions=8
default.replication.factor=3
min.insync.replicas=2
compression.type=lz4
log.retention.hours=24
EOF

    # Configure Redis
    cat > "${TEST_ROOT}/test/configs/redis.conf" << EOF
maxmemory 4gb
maxmemory-policy allkeys-lru
appendonly yes
EOF

    # Configure Prometheus
    cat > "${TEST_ROOT}/test/configs/prometheus.yml" << EOF
global:
  scrape_interval: 10s
  evaluation_interval: 10s
scrape_configs:
  - job_name: 'blackpoint'
    static_configs:
      - targets: ['localhost:8080']
EOF

    # Configure load balancer
    cat > "${TEST_ROOT}/test/configs/haproxy.cfg" << EOF
global
    maxconn 50000
defaults
    timeout connect 10s
    timeout client 30s
    timeout server 30s
EOF

    log_info "Service configuration completed"
    return 0
}

# Start and verify services
start_services() {
    log_info "Starting services..."

    # Pull required images
    docker-compose pull

    # Start core services
    docker-compose up -d kafka redis prometheus grafana

    # Wait for services to be healthy
    local services=("kafka" "redis" "prometheus" "grafana")
    for service in "${services[@]}"; do
        local retries=0
        while [[ ${retries} -lt 30 ]]; do
            if docker-compose ps "${service}" | grep -q "Up"; then
                break
            fi
            sleep 2
            ((retries++))
        done
        if [[ ${retries} -eq 30 ]]; then
            log_error "Service ${service} failed to start"
            return 1
        fi
    done

    # Initialize Kafka topics
    docker-compose exec -T kafka kafka-topics.sh --create \
        --topic bronze_events --partitions 8 --replication-factor 3

    log_info "Services started successfully"
    return 0
}

# Setup test data
setup_test_data() {
    log_info "Setting up test data..."

    # Load test fixtures
    cp -r "${TEST_ROOT}/test/fixtures/"* "${TEST_ROOT}/test/data/"

    # Generate performance test data
    for i in {1..100}; do
        cat > "${TEST_ROOT}/test/data/client_${i}.json" << EOF
{
    "client_id": "test-client-${i}",
    "events_per_second": 1000,
    "test_duration": "1h"
}
EOF
    done

    # Initialize baseline metrics
    cat > "${TEST_ROOT}/test/metrics/baseline.json" << EOF
{
    "bronze_latency": 0.8,
    "silver_latency": 4.0,
    "gold_latency": 25.0,
    "events_per_second": 1200
}
EOF

    log_info "Test data setup completed"
    return 0
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    docker-compose down -v &> /dev/null || true
    rm -rf "${TEST_ROOT}/test/artifacts/temp"/* || true
}

# Main execution
main() {
    log_info "Starting test environment setup..."

    # Initialize logging
    init_logging

    # Check dependencies
    check_dependencies || exit 2

    # Setup directories
    setup_directories || exit 6

    # Configure services
    configure_services "${TEST_CONFIG}" "${E2E_CONFIG}" || exit 3

    # Start services
    start_services || exit 4

    # Setup test data
    setup_test_data || exit 5

    log_info "Test environment setup completed successfully"
    return 0
}

# Execute main function
main "$@"