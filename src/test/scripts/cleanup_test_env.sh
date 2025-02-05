#!/bin/bash

# BlackPoint Security Integration Framework - Test Environment Cleanup Script
# Version: 1.0.0
# Purpose: Comprehensive cleanup of test environment resources with robust error handling

# External tool versions:
# - kubectl (latest)
# - aws-cli (2.0+)
# - docker (20.0+)

set -euo pipefail

# Global variables
TEST_NAMESPACE="blackpoint-test"
CLEANUP_TIMEOUT="300"
LOG_FILE="/var/log/blackpoint/test-cleanup.log"
RETRY_ATTEMPTS=3
PARALLEL_CLEANUP=true

# Load test configuration
if [ -f "src/test/configs/test.yaml" ]; then
    source src/test/configs/test.yaml
else
    echo "Error: Test configuration file not found"
    exit 1
fi

# Enhanced logging function
log_cleanup_status() {
    local component=$1
    local severity=$2
    local message=$3
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    echo "{\"timestamp\":\"$timestamp\",\"component\":\"$component\",\"severity\":\"$severity\",\"message\":\"$message\"}" >> "$LOG_FILE"
    
    if [ "$severity" = "ERROR" ]; then
        echo "ERROR: $component - $message" >&2
    else
        echo "INFO: $component - $message"
    fi
}

# Kubernetes resource cleanup
cleanup_kubernetes_resources() {
    log_cleanup_status "kubernetes" "INFO" "Starting Kubernetes resource cleanup"
    
    # Verify cluster access
    if ! kubectl cluster-info &>/dev/null; then
        log_cleanup_status "kubernetes" "ERROR" "Failed to access Kubernetes cluster"
        return 1
    }
    
    # Delete deployments with grace period
    kubectl delete deployments --namespace "$TEST_NAMESPACE" --all --timeout="${CLEANUP_TIMEOUT}s" --wait=true || \
        log_cleanup_status "kubernetes" "ERROR" "Failed to delete deployments"
    
    # Remove services and endpoints
    kubectl delete services --namespace "$TEST_NAMESPACE" --all || \
        log_cleanup_status "kubernetes" "ERROR" "Failed to delete services"
    
    # Clean up configmaps and secrets
    kubectl delete configmaps,secrets --namespace "$TEST_NAMESPACE" --all || \
        log_cleanup_status "kubernetes" "ERROR" "Failed to delete configmaps and secrets"
    
    # Remove PVCs and PVs
    kubectl delete pvc,pv --namespace "$TEST_NAMESPACE" --all || \
        log_cleanup_status "kubernetes" "ERROR" "Failed to delete persistent volumes"
    
    # Delete namespace with verification
    kubectl delete namespace "$TEST_NAMESPACE" --timeout="${CLEANUP_TIMEOUT}s" || \
        log_cleanup_status "kubernetes" "ERROR" "Failed to delete namespace"
    
    log_cleanup_status "kubernetes" "INFO" "Kubernetes resource cleanup completed"
    return 0
}

# Storage resource cleanup
cleanup_storage_resources() {
    log_cleanup_status "storage" "INFO" "Starting storage resource cleanup"
    
    # Clean up ChaosSearch indexes
    for index in $(aws chaossearch list-indices --prefix "test-" --query 'indices[*].name' --output text); do
        aws chaossearch delete-index --index-name "$index" || \
            log_cleanup_status "storage" "ERROR" "Failed to delete ChaosSearch index: $index"
    done
    
    # Clean up S3 test buckets
    for bucket in $(aws s3api list-buckets --query 'Buckets[?starts_with(Name, `blackpoint-test-`)].Name' --output text); do
        # Remove versioning first
        aws s3api delete-bucket-versioning --bucket "$bucket"
        # Delete all objects including versions
        aws s3 rm "s3://$bucket" --recursive --force || \
            log_cleanup_status "storage" "ERROR" "Failed to delete S3 bucket contents: $bucket"
        # Delete the bucket
        aws s3api delete-bucket --bucket "$bucket" || \
            log_cleanup_status "storage" "ERROR" "Failed to delete S3 bucket: $bucket"
    done
    
    log_cleanup_status "storage" "INFO" "Storage resource cleanup completed"
    return 0
}

# Streaming resource cleanup
cleanup_streaming_resources() {
    log_cleanup_status "streaming" "INFO" "Starting streaming resource cleanup"
    
    # Stop consumers gracefully
    kafka-consumer-groups --bootstrap-server localhost:9092 --list | grep "test-" | while read -r group; do
        kafka-consumer-groups --bootstrap-server localhost:9092 --group "$group" --reset-offsets --to-earliest --all-topics --execute || \
            log_cleanup_status "streaming" "ERROR" "Failed to reset consumer group: $group"
    done
    
    # Delete test topics
    kafka-topics --bootstrap-server localhost:9092 --list | grep "test-" | while read -r topic; do
        kafka-topics --bootstrap-server localhost:9092 --delete --topic "$topic" || \
            log_cleanup_status "streaming" "ERROR" "Failed to delete topic: $topic"
    done
    
    # Clean up schema registry
    curl -X DELETE "http://localhost:8081/subjects/test-*" || \
        log_cleanup_status "streaming" "ERROR" "Failed to clean up schema registry"
    
    log_cleanup_status "streaming" "INFO" "Streaming resource cleanup completed"
    return 0
}

# Monitoring resource cleanup
cleanup_monitoring() {
    log_cleanup_status "monitoring" "INFO" "Starting monitoring resource cleanup"
    
    # Clean up Prometheus rules and alerts
    curl -X DELETE "http://localhost:9090/api/v1/rules/test-*" || \
        log_cleanup_status "monitoring" "ERROR" "Failed to clean up Prometheus rules"
    
    # Remove Grafana dashboards
    curl -X DELETE "http://localhost:3000/api/dashboards/test-*" || \
        log_cleanup_status "monitoring" "ERROR" "Failed to clean up Grafana dashboards"
    
    # Clean up log aggregation
    rm -rf /var/log/blackpoint/test-* || \
        log_cleanup_status "monitoring" "ERROR" "Failed to clean up test logs"
    
    log_cleanup_status "monitoring" "INFO" "Monitoring resource cleanup completed"
    return 0
}

# Main cleanup orchestration
main() {
    log_cleanup_status "main" "INFO" "Starting test environment cleanup"
    
    local exit_code=0
    
    # Create cleanup functions array
    cleanup_functions=(
        cleanup_kubernetes_resources
        cleanup_storage_resources
        cleanup_streaming_resources
        cleanup_monitoring
    )
    
    if [ "$PARALLEL_CLEANUP" = true ]; then
        # Parallel execution
        for func in "${cleanup_functions[@]}"; do
            $func &
        done
        wait
    else
        # Sequential execution with retry
        for func in "${cleanup_functions[@]}"; do
            local attempts=0
            while [ $attempts -lt $RETRY_ATTEMPTS ]; do
                if $func; then
                    break
                fi
                attempts=$((attempts + 1))
                log_cleanup_status "main" "WARN" "Retry attempt $attempts for $func"
                sleep 5
            done
            if [ $attempts -eq $RETRY_ATTEMPTS ]; then
                log_cleanup_status "main" "ERROR" "Failed to execute $func after $RETRY_ATTEMPTS attempts"
                exit_code=1
            fi
        done
    fi
    
    if [ $exit_code -eq 0 ]; then
        log_cleanup_status "main" "INFO" "Test environment cleanup completed successfully"
    else
        log_cleanup_status "main" "ERROR" "Test environment cleanup completed with errors"
    fi
    
    return $exit_code
}

# Script execution
main "$@"