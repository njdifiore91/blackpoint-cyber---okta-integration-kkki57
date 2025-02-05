#!/bin/bash
# BlackPoint Security CLI Installation Script
# Version: 1.0.0
# Requires: bash 4.0+
# Description: Enterprise-grade installation script for the BlackPoint CLI tool

set -euo pipefail
IFS=$'\n\t'

# Script directory and root path resolution
SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")
ROOT_DIR=$(cd "${SCRIPT_DIR}/../" && pwd)

# Global configuration
BINARY_NAME="blackpoint-cli"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="${HOME}/.blackpoint"
COMPLETION_DIR="/etc/bash_completion.d"
MAN_DIR="/usr/local/share/man/man1"
LOG_DIR="${CONFIG_DIR}/logs"
BACKUP_DIR="${CONFIG_DIR}/backups"
INSTALL_LOG="${LOG_DIR}/install.log"
MIN_BASH_VERSION="4.0"
REQUIRED_SPACE="100M"

# Logging functions
log() {
    local level=$1
    shift
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*"
    echo "$message" | tee -a "$INSTALL_LOG"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@" >&2; }
log_error() { log "ERROR" "$@" >&2; }

# Error handling
cleanup_on_error() {
    log_error "Installation failed - initiating cleanup"
    
    # Restore binary backup if exists
    if [[ -f "${BACKUP_DIR}/bin/${BINARY_NAME}.bak" ]]; then
        log_info "Restoring binary backup"
        mv "${BACKUP_DIR}/bin/${BINARY_NAME}.bak" "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    # Restore config backup if exists
    if [[ -f "${BACKUP_DIR}/config/config.yaml.bak" ]]; then
        log_info "Restoring configuration backup"
        mv "${BACKUP_DIR}/config/config.yaml.bak" "${CONFIG_DIR}/config.yaml"
    fi

    # Remove installed components
    rm -f "${INSTALL_DIR}/${BINARY_NAME}"
    rm -f "${COMPLETION_DIR}/${BINARY_NAME}"
    rm -f "${MAN_DIR}/${BINARY_NAME}.1.gz"

    log_info "Cleanup completed"
    exit 1
}

trap cleanup_on_error ERR

check_prerequisites() {
    log_info "Checking installation prerequisites"

    # Check bash version
    if [[ "${BASH_VERSION%%.*}" -lt "${MIN_BASH_VERSION%%.*}" ]]; then
        log_error "Bash version ${MIN_BASH_VERSION} or higher required"
        return 1
    }

    # Check for root/sudo privileges
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run with sudo or as root"
        return 1
    }

    # Check required commands
    local required_commands=("cp" "mkdir" "chmod" "chown" "ln" "rm" "id" "mandb" "gzip" "tar" "curl" "sha256sum")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_error "Required command not found: $cmd"
            return 1
        fi
    done

    # Check available disk space
    local available_space
    available_space=$(df -BM "${INSTALL_DIR}" | awk 'NR==2 {print $4}')
    if [[ "${available_space%M}" -lt "${REQUIRED_SPACE%M}" ]]; then
        log_error "Insufficient disk space. Required: ${REQUIRED_SPACE}, Available: ${available_space}"
        return 1
    }

    # Create required directories
    mkdir -p "${CONFIG_DIR}" "${LOG_DIR}" "${BACKUP_DIR}/bin" "${BACKUP_DIR}/config"
    chmod 700 "${CONFIG_DIR}" "${LOG_DIR}" "${BACKUP_DIR}"

    return 0
}

install_binary() {
    log_info "Installing BlackPoint CLI binary"

    # Backup existing binary
    if [[ -f "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
        log_info "Backing up existing binary"
        cp "${INSTALL_DIR}/${BINARY_NAME}" "${BACKUP_DIR}/bin/${BINARY_NAME}.bak"
    fi

    # Install new binary
    cp "${ROOT_DIR}/bin/${BINARY_NAME}" "${INSTALL_DIR}/"
    chmod 755 "${INSTALL_DIR}/${BINARY_NAME}"
    chown root:root "${INSTALL_DIR}/${BINARY_NAME}"

    # Verify installation
    if ! "${INSTALL_DIR}/${BINARY_NAME}" version >/dev/null 2>&1; then
        log_error "Binary verification failed"
        return 1
    fi

    log_info "Binary installation completed"
    return 0
}

install_config() {
    log_info "Setting up configuration"

    # Backup existing config
    if [[ -f "${CONFIG_DIR}/config.yaml" ]]; then
        log_info "Backing up existing configuration"
        cp "${CONFIG_DIR}/config.yaml" "${BACKUP_DIR}/config/config.yaml.bak"
    fi

    # Install new config
    cp "${ROOT_DIR}/configs/config.yaml.example" "${CONFIG_DIR}/config.yaml"
    chmod 600 "${CONFIG_DIR}/config.yaml"
    chown "$(id -u):$(id -g)" "${CONFIG_DIR}/config.yaml"

    log_info "Configuration setup completed"
    return 0
}

install_completions() {
    log_info "Installing shell completions"

    # Generate and install bash completion
    "${INSTALL_DIR}/${BINARY_NAME}" completion bash > "${COMPLETION_DIR}/${BINARY_NAME}"
    chmod 644 "${COMPLETION_DIR}/${BINARY_NAME}"
    chown root:root "${COMPLETION_DIR}/${BINARY_NAME}"

    # Install zsh completion if available
    if [[ -d "${HOME}/.zsh/completion" ]]; then
        "${INSTALL_DIR}/${BINARY_NAME}" completion zsh > "${HOME}/.zsh/completion/_${BINARY_NAME}"
        chmod 644 "${HOME}/.zsh/completion/_${BINARY_NAME}"
    fi

    # Install fish completion if available
    if [[ -d "/usr/share/fish/completions" ]]; then
        "${INSTALL_DIR}/${BINARY_NAME}" completion fish > "/usr/share/fish/completions/${BINARY_NAME}.fish"
        chmod 644 "/usr/share/fish/completions/${BINARY_NAME}.fish"
    fi

    log_info "Shell completions installed"
    return 0
}

install_man_pages() {
    log_info "Installing man pages"

    # Generate and install man page
    "${INSTALL_DIR}/${BINARY_NAME}" man > "${MAN_DIR}/${BINARY_NAME}.1"
    gzip -f "${MAN_DIR}/${BINARY_NAME}.1"
    chmod 644 "${MAN_DIR}/${BINARY_NAME}.1.gz"
    chown root:root "${MAN_DIR}/${BINARY_NAME}.1.gz"

    # Update man database
    mandb >/dev/null 2>&1

    log_info "Man pages installed"
    return 0
}

verify_installation() {
    log_info "Verifying installation"

    # Check binary
    if ! "${INSTALL_DIR}/${BINARY_NAME}" version >/dev/null 2>&1; then
        log_error "Binary verification failed"
        return 1
    fi

    # Check config
    if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
        log_error "Configuration file missing"
        return 1
    fi

    # Check completions
    if [[ ! -f "${COMPLETION_DIR}/${BINARY_NAME}" ]]; then
        log_error "Bash completion missing"
        return 1
    fi

    # Check man pages
    if [[ ! -f "${MAN_DIR}/${BINARY_NAME}.1.gz" ]]; then
        log_error "Man page missing"
        return 1
    fi

    log_info "Installation verified successfully"
    return 0
}

main() {
    # Initialize logging
    mkdir -p "$(dirname "$INSTALL_LOG")"
    touch "$INSTALL_LOG"
    chmod 600 "$INSTALL_LOG"

    log_info "Starting BlackPoint CLI installation"

    # Installation steps
    check_prerequisites || exit 1
    install_binary || exit 1
    install_config || exit 1
    install_completions || exit 1
    install_man_pages || exit 1
    verify_installation || exit 1

    log_info "Installation completed successfully"
    echo "BlackPoint CLI has been installed successfully. Run 'blackpoint-cli --help' for usage information."
    return 0
}

main "$@"