#!/bin/bash

# BlackPoint Security Integration Framework Deployment Script
# Version: 1.0.0

set -euo pipefail

# Global variables
NAMESPACE=${NAMESPACE:-"blackpoint-system"}
COMPONENTS=("collector" "normalizer" "analyzer")
DEPLOYMENT_ORDER=("collector" "normalizer" "analyzer")
RESOURCE_QUOTAS='{
  "cpu": "16",
  "memory": "32Gi",
  "pods": "30"
}'
SECURITY_CONTEXT='{
  "runAsNonRoot": true,
  "readOnlyRootFilesystem": true
}'

# Logging function with timestamp
log() {
    echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] $1"
}

# Error handling function
handle_error() {
    log "ERROR: $1"
    exit 1
}

# Validate cluster access and security configuration
validate_cluster_access() {
    log "Validating cluster access and security configuration..."
    
    # Check kubectl configuration
    kubectl cluster-info > /dev/null 2>&1 || handle_error "Failed to connect to Kubernetes cluster"
    
    # Verify RBAC permissions
    kubectl auth can-i create deployments --namespace="$NAMESPACE" > /dev/null 2>&1 || \
        handle_error "Insufficient permissions to create deployments"
    
    # Verify KMS encryption
    kubectl get secrets --namespace="$NAMESPACE" > /dev/null 2>&1 || \
        handle_error "Unable to access secrets - KMS encryption may not be configured"
}

# Deploy namespace with security configurations
deploy_namespace() {
    log "Deploying namespace: $NAMESPACE"
    
    # Create namespace if it doesn't exist
    kubectl get namespace "$NAMESPACE" > /dev/null 2>&1 || \
        kubectl create namespace "$NAMESPACE"
    
    # Apply resource quotas
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ResourceQuota
metadata:
  name: blackpoint-quota
  namespace: $NAMESPACE
spec:
  hard:
    cpu: "${RESOURCE_QUOTAS_CPU}"
    memory: "${RESOURCE_QUOTAS_MEMORY}"
    pods: "${RESOURCE_QUOTAS_PODS}"
EOF
}

# Deploy RBAC configurations
deploy_rbac() {
    log "Deploying RBAC configurations..."
    
    # Apply service accounts and roles
    kubectl apply -f ../deploy/kubernetes/rbac.yaml || \
        handle_error "Failed to deploy RBAC configurations"
}

# Deploy a specific component
deploy_component() {
    local component=$1
    log "Deploying component: $component"
    
    # Validate component dependencies
    case $component in
        "analyzer")
            kubectl rollout status deployment/normalizer -n "$NAMESPACE" || \
                handle_error "Normalizer dependency not ready"
            ;;
        "normalizer")
            kubectl rollout status deployment/collector -n "$NAMESPACE" || \
                handle_error "Collector dependency not ready"
            ;;
    esac
    
    # Apply deployment
    kubectl apply -f "../deploy/kubernetes/${component}-deployment.yaml" || \
        handle_error "Failed to deploy $component"
    
    # Wait for deployment
    kubectl rollout status deployment/"$component" -n "$NAMESPACE" --timeout=300s || \
        handle_error "$component deployment failed"
}

# Validate deployment status
validate_deployment() {
    log "Validating deployment status..."
    
    for component in "${COMPONENTS[@]}"; do
        # Check pod status
        local ready_pods=$(kubectl get deployment "$component" -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}')
        local desired_pods=$(kubectl get deployment "$component" -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
        
        if [ "$ready_pods" != "$desired_pods" ]; then
            handle_error "$component: Ready pods ($ready_pods) != Desired pods ($desired_pods)"
        fi
        
        # Verify health checks
        local unhealthy_pods=$(kubectl get pods -n "$NAMESPACE" -l "app=$component" \
            -o jsonpath='{.items[?(@.status.containerStatuses[*].ready==false)].metadata.name}')
        if [ -n "$unhealthy_pods" ]; then
            handle_error "$component has unhealthy pods: $unhealthy_pods"
        fi
    done
}

# Rollback deployment if needed
rollback_deployment() {
    local component=$1
    log "Rolling back deployment: $component"
    
    kubectl rollout undo deployment/"$component" -n "$NAMESPACE" || \
        handle_error "Failed to rollback $component"
    
    # Wait for rollback to complete
    kubectl rollout status deployment/"$component" -n "$NAMESPACE" --timeout=300s || \
        handle_error "Rollback failed for $component"
}

# Main deployment function
main() {
    log "Starting BlackPoint Security Integration Framework deployment"
    
    # Authenticate with AWS ECR
    aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin \
        "${AWS_ACCOUNT_ID}.dkr.ecr.us-west-2.amazonaws.com" || \
        handle_error "Failed to authenticate with ECR"
    
    # Validate cluster access
    validate_cluster_access
    
    # Deploy namespace and RBAC
    deploy_namespace
    deploy_rbac
    
    # Deploy components in order
    for component in "${DEPLOYMENT_ORDER[@]}"; do
        deploy_component "$component"
    done
    
    # Validate deployment
    validate_deployment
    
    log "Deployment completed successfully"
}

# Cleanup function
cleanup() {
    log "Performing cleanup..."
    # Add cleanup tasks if needed
}

# Set up trap for cleanup
trap cleanup EXIT

# Execute main function
main "$@"