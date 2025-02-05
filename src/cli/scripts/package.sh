#!/bin/bash

# BlackPoint CLI Packaging Script
# Builds and packages the BlackPoint CLI tool for distribution
# Version: 1.0.0

set -euo pipefail
IFS=$'\n\t'

# Script location and directories
SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")
ROOT_DIR=$(cd "${SCRIPT_DIR}/../" && pwd)
DIST_DIR="${ROOT_DIR}/dist"
TEMP_DIR=$(mktemp -d)
trap 'rm -rf ${TEMP_DIR}' EXIT

# Build configuration
BINARY_NAME="blackpoint-cli"
PACKAGE_VERSION=$(git describe --tags --always --dirty)
DOCKER_REGISTRY="blackpoint"
PROXY_SETTINGS="${HTTP_PROXY:-}"
AIR_GAP_MODE="${AIR_GAP:-false}"
CUSTOM_CA_CERT="${CA_CERT_PATH:-}"

# Supported platforms
PLATFORMS=("linux/amd64" "linux/arm64" "darwin/amd64" "darwin/arm64" "windows/amd64")

set_package_env() {
    # Verify required tools
    command -v docker >/dev/null 2>&1 || { echo "docker is required but not installed"; exit 1; }
    command -v goreleaser >/dev/null 2>&1 || { echo "goreleaser is required but not installed"; exit 1; }
    command -v gpg >/dev/null 2>&1 || { echo "gpg is required but not installed"; exit 1; }

    # Create distribution directory
    mkdir -p "${DIST_DIR}"

    # Configure proxy if specified
    if [ -n "${PROXY_SETTINGS}" ]; then
        export DOCKER_BUILD_ARGS="--build-arg HTTP_PROXY=${PROXY_SETTINGS} --build-arg HTTPS_PROXY=${PROXY_SETTINGS}"
    fi

    # Configure custom CA certificate
    if [ -n "${CUSTOM_CA_CERT}" ]; then
        if [ -f "${CUSTOM_CA_CERT}" ]; then
            cp "${CUSTOM_CA_CERT}" "${TEMP_DIR}/ca.crt"
            export DOCKER_BUILD_ARGS="${DOCKER_BUILD_ARGS:-} --build-arg CA_CERT=/ca.crt"
        else
            echo "Warning: Custom CA certificate file not found: ${CUSTOM_CA_CERT}"
        fi
    fi

    # Set up GPG for package signing
    if gpg --list-secret-keys | grep -q "BlackPoint Security"; then
        export SIGN_PACKAGES=true
    else
        echo "Warning: GPG signing key not found, packages will not be signed"
        export SIGN_PACKAGES=false
    fi
}

build_archives() {
    echo "Building archives for all platforms..."
    
    for platform in "${PLATFORMS[@]}"; do
        os=${platform%/*}
        arch=${platform#*/}
        
        echo "Building for ${platform}..."
        
        # Set platform-specific variables
        binary_ext=""
        archive_ext=".tar.gz"
        if [ "${os}" = "windows" ]; then
            binary_ext=".exe"
            archive_ext=".zip"
        fi

        # Build binary with reproducible settings
        GOOS=${os} GOARCH=${arch} CGO_ENABLED=0 \
            go build -trimpath -ldflags "-s -w \
                -X github.com/blackpoint/cli/pkg/common.Version=${PACKAGE_VERSION} \
                -X github.com/blackpoint/cli/pkg/common.GitCommit=$(git rev-parse HEAD) \
                -X github.com/blackpoint/cli/pkg/common.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            -o "${TEMP_DIR}/${BINARY_NAME}${binary_ext}" \
            "${ROOT_DIR}/cmd/cli"

        # Create archive
        pushd "${TEMP_DIR}" >/dev/null
        if [ "${archive_ext}" = ".zip" ]; then
            zip -X -r "${DIST_DIR}/${BINARY_NAME}-${PACKAGE_VERSION}-${os}-${arch}.zip" "${BINARY_NAME}${binary_ext}"
        else
            tar --sort=name --owner=0 --group=0 --mtime="@$(git log -1 --format=%ct)" \
                -czf "${DIST_DIR}/${BINARY_NAME}-${PACKAGE_VERSION}-${os}-${arch}.tar.gz" \
                "${BINARY_NAME}${binary_ext}"
        fi
        popd >/dev/null

        # Generate checksums
        pushd "${DIST_DIR}" >/dev/null
        sha256sum "${BINARY_NAME}-${PACKAGE_VERSION}-${os}-${arch}${archive_ext}" > \
            "${BINARY_NAME}-${PACKAGE_VERSION}-${os}-${arch}${archive_ext}.sha256"
        sha512sum "${BINARY_NAME}-${PACKAGE_VERSION}-${os}-${arch}${archive_ext}" > \
            "${BINARY_NAME}-${PACKAGE_VERSION}-${os}-${arch}${archive_ext}.sha512"
        popd >/dev/null

        # Sign archives if GPG key is available
        if [ "${SIGN_PACKAGES}" = "true" ]; then
            gpg --detach-sign --armor "${DIST_DIR}/${BINARY_NAME}-${PACKAGE_VERSION}-${os}-${arch}${archive_ext}"
        fi
    done
}

build_packages() {
    echo "Building OS packages..."

    # Build DEB package
    if command -v dpkg-deb >/dev/null 2>&1; then
        echo "Building DEB package..."
        
        # Create package structure
        pkg_root="${TEMP_DIR}/deb"
        mkdir -p "${pkg_root}/DEBIAN" "${pkg_root}/usr/local/bin"
        
        # Copy binary
        cp "${TEMP_DIR}/${BINARY_NAME}" "${pkg_root}/usr/local/bin/"
        
        # Create control file
        cat > "${pkg_root}/DEBIAN/control" <<EOF
Package: ${BINARY_NAME}
Version: ${PACKAGE_VERSION}
Section: utils
Priority: optional
Architecture: amd64
Maintainer: BlackPoint Security <support@blackpoint.com>
Description: BlackPoint Security CLI Tool
 Command line interface for BlackPoint Security Integration Framework
EOF

        # Build package
        dpkg-deb --build "${pkg_root}" "${DIST_DIR}/${BINARY_NAME}-${PACKAGE_VERSION}.deb"
        
        # Sign package if GPG key is available
        if [ "${SIGN_PACKAGES}" = "true" ]; then
            dpkg-sig --sign builder "${DIST_DIR}/${BINARY_NAME}-${PACKAGE_VERSION}.deb"
        fi
    fi

    # Build RPM package
    if command -v rpmbuild >/dev/null 2>&1; then
        echo "Building RPM package..."
        
        # Create RPM build structure
        rpm_root="${TEMP_DIR}/rpm"
        mkdir -p "${rpm_root}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
        
        # Create spec file
        cat > "${rpm_root}/SPECS/${BINARY_NAME}.spec" <<EOF
Name: ${BINARY_NAME}
Version: ${PACKAGE_VERSION}
Release: 1
Summary: BlackPoint Security CLI Tool
License: Proprietary
BuildArch: x86_64

%description
Command line interface for BlackPoint Security Integration Framework

%install
mkdir -p %{buildroot}/usr/local/bin
cp ${TEMP_DIR}/${BINARY_NAME} %{buildroot}/usr/local/bin/

%files
/usr/local/bin/${BINARY_NAME}
EOF

        # Build RPM
        rpmbuild --define "_topdir ${rpm_root}" -bb "${rpm_root}/SPECS/${BINARY_NAME}.spec"
        
        # Copy and sign RPM
        cp "${rpm_root}/RPMS/x86_64/${BINARY_NAME}-${PACKAGE_VERSION}-1.x86_64.rpm" "${DIST_DIR}/"
        if [ "${SIGN_PACKAGES}" = "true" ]; then
            rpm --addsign "${DIST_DIR}/${BINARY_NAME}-${PACKAGE_VERSION}-1.x86_64.rpm"
        fi
    fi
}

build_container() {
    echo "Building container images..."

    # Build multi-arch container images
    docker buildx create --use --name multiarch-builder || true
    
    build_args="${DOCKER_BUILD_ARGS:-}"
    if [ "${AIR_GAP_MODE}" = "true" ]; then
        build_args="${build_args} --build-arg AIR_GAP=true"
    fi

    # Build and push container images
    docker buildx build \
        --platform linux/amd64,linux/arm64 \
        --build-arg VERSION="${PACKAGE_VERSION}" \
        ${build_args} \
        --tag "${DOCKER_REGISTRY}/${BINARY_NAME}:${PACKAGE_VERSION}" \
        --tag "${DOCKER_REGISTRY}/${BINARY_NAME}:latest" \
        --push \
        "${ROOT_DIR}"

    # Sign container images if cosign is available
    if command -v cosign >/dev/null 2>&1 && [ "${SIGN_PACKAGES}" = "true" ]; then
        cosign sign "${DOCKER_REGISTRY}/${BINARY_NAME}:${PACKAGE_VERSION}"
        cosign sign "${DOCKER_REGISTRY}/${BINARY_NAME}:latest"
    fi
}

verify_packages() {
    echo "Verifying packages..."

    # Verify archive checksums
    for platform in "${PLATFORMS[@]}"; do
        os=${platform%/*}
        arch=${platform#*/}
        archive_ext=".tar.gz"
        [ "${os}" = "windows" ] && archive_ext=".zip"
        
        echo "Verifying ${os}/${arch} archive..."
        pushd "${DIST_DIR}" >/dev/null
        sha256sum -c "${BINARY_NAME}-${PACKAGE_VERSION}-${os}-${arch}${archive_ext}.sha256"
        sha512sum -c "${BINARY_NAME}-${PACKAGE_VERSION}-${os}-${arch}${archive_ext}.sha512"
        
        # Verify signatures if packages were signed
        if [ "${SIGN_PACKAGES}" = "true" ]; then
            gpg --verify "${BINARY_NAME}-${PACKAGE_VERSION}-${os}-${arch}${archive_ext}.asc" \
                "${BINARY_NAME}-${PACKAGE_VERSION}-${os}-${arch}${archive_ext}"
        fi
        popd >/dev/null
    done

    # Verify package signatures
    if [ "${SIGN_PACKAGES}" = "true" ]; then
        if [ -f "${DIST_DIR}/${BINARY_NAME}-${PACKAGE_VERSION}.deb" ]; then
            dpkg-sig --verify "${DIST_DIR}/${BINARY_NAME}-${PACKAGE_VERSION}.deb"
        fi
        
        if [ -f "${DIST_DIR}/${BINARY_NAME}-${PACKAGE_VERSION}-1.x86_64.rpm" ]; then
            rpm -K "${DIST_DIR}/${BINARY_NAME}-${PACKAGE_VERSION}-1.x86_64.rpm"
        fi
    fi

    # Verify container images
    if command -v cosign >/dev/null 2>&1 && [ "${SIGN_PACKAGES}" = "true" ]; then
        cosign verify "${DOCKER_REGISTRY}/${BINARY_NAME}:${PACKAGE_VERSION}"
        cosign verify "${DOCKER_REGISTRY}/${BINARY_NAME}:latest"
    fi
}

main() {
    echo "Starting BlackPoint CLI packaging process..."
    
    set_package_env
    build_archives
    build_packages
    build_container
    verify_packages
    
    echo "Packaging complete. Artifacts available in ${DIST_DIR}"
    return 0
}

# Execute main function
main "$@"