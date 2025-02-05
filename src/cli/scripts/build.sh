#!/usr/bin/env bash

# BlackPoint Security CLI Build Script
# Requires: go 1.21+, git 2.0+, bash 4.0+
# Purpose: Builds the BlackPoint CLI binary with proper version information and platform-specific optimizations

set -euo pipefail
IFS=$'\n\t'

# Global variables
SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")
ROOT_DIR=$(cd "${SCRIPT_DIR}/../" && pwd)
BINARY_NAME="blackpoint-cli"
VERSION=$(git describe --tags --always --dirty)
BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
GIT_COMMIT=$(git rev-parse HEAD)
GO_VERSION=$(go version)
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCHITECTURE=$(uname -m)
BUILD_CACHE_DIR="${ROOT_DIR}/.build-cache"
LOG_FILE="${ROOT_DIR}/build.log"

# Verify all required build dependencies are available
verify_dependencies() {
    echo "Verifying build dependencies..."
    
    # Check Go installation
    if ! command -v go >/dev/null 2>&1; then
        echo "Error: Go is not installed" | tee -a "${LOG_FILE}"
        return 1
    fi
    
    # Verify minimum Go version
    GO_VERSION_FULL=$(go version | awk '{print $3}' | sed 's/go//')
    if [[ "${GO_VERSION_FULL%%.*}" -lt 1 ]] || [[ "${GO_VERSION_FULL#*.}" -lt 21 ]]; then
        echo "Error: Go version 1.21+ is required" | tee -a "${LOG_FILE}"
        return 1
    fi
    
    # Check Git installation
    if ! command -v git >/dev/null 2>&1; then
        echo "Error: Git is not installed" | tee -a "${LOG_FILE}"
        return 1
    fi
    
    return 0
}

# Set up build environment variables and configurations
set_build_env() {
    echo "Setting up build environment..."
    
    # Create build cache directory
    mkdir -p "${BUILD_CACHE_DIR}"
    
    # Set Go environment variables
    export GOPATH="${BUILD_CACHE_DIR}/go"
    export GOCACHE="${BUILD_CACHE_DIR}/gocache"
    export CGO_ENABLED=0
    export GOSUMDB=off
    
    # Platform-specific configurations
    case "${PLATFORM}" in
        linux)
            export GOARCH="${ARCHITECTURE}"
            export GOOS="linux"
            ;;
        darwin)
            export GOARCH="${ARCHITECTURE}"
            export GOOS="darwin"
            ;;
        *)
            echo "Error: Unsupported platform ${PLATFORM}" | tee -a "${LOG_FILE}"
            exit 1
            ;;
    esac
    
    echo "Build environment configured for ${GOOS}/${GOARCH}" | tee -a "${LOG_FILE}"
}

# Build the CLI binary with proper version information and optimizations
build_binary() {
    echo "Building BlackPoint CLI binary..."
    
    # Clean previous builds
    rm -f "${ROOT_DIR}/bin/${BINARY_NAME}"
    mkdir -p "${ROOT_DIR}/bin"
    
    # Set build flags
    BUILD_FLAGS=(
        "-trimpath"
        "-ldflags=-s -w"
        "-ldflags=-X 'github.com/blackpoint/cli/pkg/common.Version=${VERSION}'"
        "-ldflags=-X 'github.com/blackpoint/cli/pkg/common.GitCommit=${GIT_COMMIT}'"
        "-ldflags=-X 'github.com/blackpoint/cli/pkg/common.BuildDate=${BUILD_DATE}'"
        "-ldflags=-X 'github.com/blackpoint/cli/pkg/common.GoVersion=${GO_VERSION}'"
    )
    
    # Verify and tidy dependencies
    cd "${ROOT_DIR}"
    go mod tidy
    go mod verify
    
    # Build binary
    echo "Running go build with flags: ${BUILD_FLAGS[*]}" | tee -a "${LOG_FILE}"
    go build \
        "${BUILD_FLAGS[@]}" \
        -o "bin/${BINARY_NAME}" \
        ./cmd/blackpoint-cli
    
    # Generate checksums
    cd "${ROOT_DIR}/bin"
    sha256sum "${BINARY_NAME}" > "${BINARY_NAME}.sha256"
    
    # Set permissions
    chmod 755 "${BINARY_NAME}"
}

# Verify the built binary
verify_build() {
    echo "Verifying build..."
    
    local binary_path="${ROOT_DIR}/bin/${BINARY_NAME}"
    
    # Check binary existence
    if [[ ! -f "${binary_path}" ]]; then
        echo "Error: Binary not found at ${binary_path}" | tee -a "${LOG_FILE}"
        return 1
    fi
    
    # Verify permissions
    if [[ ! -x "${binary_path}" ]]; then
        echo "Error: Binary is not executable" | tee -a "${LOG_FILE}"
        return 1
    }
    
    # Verify checksum
    cd "${ROOT_DIR}/bin"
    if ! sha256sum -c "${BINARY_NAME}.sha256"; then
        echo "Error: Checksum verification failed" | tee -a "${LOG_FILE}"
        return 1
    }
    
    # Test binary
    if ! "${binary_path}" version >/dev/null 2>&1; then
        echo "Error: Binary verification failed" | tee -a "${LOG_FILE}"
        return 1
    }
    
    echo "Build verification completed successfully" | tee -a "${LOG_FILE}"
    return 0
}

# Main execution
main() {
    # Initialize log file
    echo "Build started at $(date -u)" > "${LOG_FILE}"
    
    # Execute build steps
    verify_dependencies || exit 1
    set_build_env
    build_binary
    verify_build || exit 1
    
    echo "Build completed successfully at $(date -u)" | tee -a "${LOG_FILE}"
    echo "Binary location: ${ROOT_DIR}/bin/${BINARY_NAME}"
    return 0
}

# Execute main function
main "$@"