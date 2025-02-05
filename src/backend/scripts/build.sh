#!/bin/bash

# BlackPoint Security Integration Framework
# Build script for backend microservices with multi-stage builds
# Version: 1.0.0

set -euo pipefail

# External tool versions
# docker v24.0.0+
# snyk v1.1183.0
# trivy v0.44.0
# git v2.40.0+

# Environment configuration
export DOCKER_BUILDKIT=1
export BUILDKIT_PROGRESS=plain
export COMPONENTS="analyzer collector normalizer"
export REGISTRY="${REGISTRY:-}"  # AWS ECR registry URL must be set
export VERSION="$(git describe --tags --always)"
export MAX_PARALLEL_BUILDS=3
export CACHE_DIR="/tmp/docker-cache"
export SECURITY_SCAN_LEVEL="HIGH"

# Size limits in bytes
declare -A SIZE_LIMITS=(
    ["analyzer"]=52428800    # 50MB
    ["collector"]=78643200   # 75MB
    ["normalizer"]=104857600 # 100MB
)

# Verify required tools
check_requirements() {
    local missing_tools=()
    
    for tool in docker git snyk trivy; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo "Error: Required tools not found: ${missing_tools[*]}"
        exit 1
    fi

    # Verify Docker BuildKit support
    if ! docker info 2>/dev/null | grep -q "BuildKit"; then
        echo "Error: Docker BuildKit not available"
        exit 1
    }
}

# Verify image size constraints
verify_size() {
    local image_name="$1"
    local component="$2"
    local size_limit="${SIZE_LIMITS[$component]}"
    
    local actual_size
    actual_size=$(docker image inspect "$image_name" --format='{{.Size}}')
    
    if [ "$actual_size" -gt "$size_limit" ]; then
        echo "Error: Image size ($actual_size bytes) exceeds limit ($size_limit bytes) for $component"
        return 1
    fi
    
    echo "Size verification passed for $component: $actual_size bytes"
    return 0
}

# Security scanning
security_scan() {
    local image_name="$1"
    local scan_failed=0
    
    echo "Running security scans for $image_name..."
    
    # Snyk container scan
    if ! snyk container test "$image_name" \
        --severity-threshold="$SECURITY_SCAN_LEVEL" \
        --file=Dockerfile; then
        echo "Snyk scan failed"
        scan_failed=1
    fi
    
    # Trivy vulnerability scan
    if ! trivy image \
        --severity "$SECURITY_SCAN_LEVEL,CRITICAL" \
        --no-progress \
        --exit-code 1 \
        "$image_name"; then
        echo "Trivy scan failed"
        scan_failed=1
    fi
    
    return $scan_failed
}

# Build single component
build_image() {
    local component="$1"
    local version_tag="$2"
    local cache_dir="$3"
    local build_failed=0
    
    echo "Building $component:$version_tag..."
    
    # Prepare build cache
    mkdir -p "$cache_dir/$component"
    
    # Build image with BuildKit cache
    if ! docker build \
        --build-arg SERVICE="$component" \
        --build-arg VERSION="$version_tag" \
        --cache-from "type=local,src=$cache_dir/$component" \
        --cache-to "type=local,dest=$cache_dir/$component" \
        --tag "$REGISTRY/$component:$version_tag" \
        --file Dockerfile \
        .; then
        echo "Build failed for $component"
        build_failed=1
    fi
    
    # Verify size constraints
    if [ $build_failed -eq 0 ]; then
        if ! verify_size "$REGISTRY/$component:$version_tag" "$component"; then
            build_failed=1
        fi
    fi
    
    # Security scanning
    if [ $build_failed -eq 0 ]; then
        if ! security_scan "$REGISTRY/$component:$version_tag"; then
            build_failed=1
        fi
    fi
    
    # Tag latest if build succeeded
    if [ $build_failed -eq 0 ]; then
        docker tag "$REGISTRY/$component:$version_tag" "$REGISTRY/$component:latest"
    fi
    
    return $build_failed
}

# Parallel build execution
build_all() {
    local -a pids=()
    local failed=0
    
    # Create semaphore for parallel build control
    local sem_name
    sem_name="build_semaphore_$$"
    
    # Initialize semaphore
    for ((i=1; i<=MAX_PARALLEL_BUILDS; i++)); do
        echo "$i" > "/dev/shm/sem_${sem_name}_$i"
    done
    
    for component in $COMPONENTS; do
        # Wait for available semaphore
        read -r sem_id < <(ls "/dev/shm/sem_${sem_name}_"* | head -n1)
        rm "$sem_id"
        
        # Start build in background
        build_image "$component" "$VERSION" "$CACHE_DIR" &
        pid=$!
        pids+=("$pid")
        
        # Store PID and semaphore mapping
        echo "$pid" > "$sem_id"
    done
    
    # Wait for all builds and collect results
    for pid in "${pids[@]}"; do
        if ! wait "$pid"; then
            failed=1
        fi
        # Release semaphore
        rm "/dev/shm/sem_${sem_name}_"*"$pid" 2>/dev/null || true
    done
    
    # Cleanup semaphores
    rm "/dev/shm/sem_${sem_name}_"* 2>/dev/null || true
    
    return $failed
}

# Main execution
main() {
    local exit_code=0
    
    echo "Starting build process for BlackPoint backend components..."
    echo "Version: $VERSION"
    
    # Verify requirements
    check_requirements
    
    # Prepare build environment
    mkdir -p "$CACHE_DIR"
    
    # Execute builds
    if ! build_all; then
        echo "One or more builds failed"
        exit_code=1
    fi
    
    # Cleanup
    rm -rf "$CACHE_DIR"
    
    echo "Build process completed with exit code $exit_code"
    return $exit_code
}

# Execute main if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi