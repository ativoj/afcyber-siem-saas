#!/bin/bash
#===============================================================================
# AfCyber SIEM - VM Image Build Automation Script
#
# This script is a comprehensive wrapper for Packer to automate the building,
# validation, and distribution of the AfCyber SIEM platform VM images.
#
# Author: AfCyber Labs
# License: Apache-2.0
# Version: 1.0.0
#===============================================================================

# --- Script Configuration ---
set -e
set -o pipefail

# --- Global Variables & Constants ---
readonly SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly LOG_DIR="${SCRIPT_DIR}/logs"
readonly LOG_FILE="${LOG_DIR}/build-$(date +%Y%m%d-%H%M%S).log"
readonly PACKER_CONFIG="packer-config.pkr.hcl"
readonly BUILD_DIR="${SCRIPT_DIR}/builds"
readonly MANIFEST_FILE="${BUILD_DIR}/manifest.json"
readonly CHECKSUM_FILE="${BUILD_DIR}/SHA256SUMS"

# --- Color Codes for Output ---
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# --- Helper Functions ---

# Log messages to console and log file
log() {
    local level=$1
    local message=$2
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    mkdir -p "$LOG_DIR"
    
    case $level in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
        "STEP")
            echo -e "\n${BLUE}>>> Step: $message${NC}"
            ;;
    esac
    
    echo "$timestamp [$level] $message" | tee -a "$LOG_FILE"
}

# Display error and exit
error_exit() {
    log "ERROR" "$1"
    log "ERROR" "Build failed. Check the log file for details: ${LOG_FILE}"
    exit 1
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Print the help message
print_help() {
    cat << EOF
AfCyber SIEM VM Image Builder - v1.0.0

A wrapper script to build production-ready VM images using Packer.

Usage: ./${SCRIPT_NAME} [OPTIONS]

Options:
  --all               Build images for all supported platforms (VMware, VirtualBox, QEMU). Default.
  --vmware            Build only the VMware image (vmdk/ova).
  --virtualbox        Build only the VirtualBox image (vdi/ova).
  --qemu              Build only the QEMU image (qcow2).
  --verify            Verify the checksums of the built artifacts after the build.
  --upload            (Placeholder) Upload artifacts to a repository after a successful build.
  --clean             Clean up the build directory and logs.
  --help, -h          Display this help message and exit.

Example:
  ./${SCRIPT_NAME} --virtualbox --verify
EOF
}

# --- Core Functions ---

# Validate that all required tools are installed
validate_prerequisites() {
    log "STEP" "Validating prerequisites..."
    local missing_tools=0
    
    local tools=( "packer:HashiCorp Packer" "ansible:Ansible" )
    
    if [[ "$BUILD_VMWARE" == "true" ]]; then
        tools+=( "vmrun:VMware Workstation/Fusion" )
    fi
    if [[ "$BUILD_VIRTUALBOX" == "true" ]]; then
        tools+=( "VBoxManage:Oracle VirtualBox" )
    fi
    if [[ "$BUILD_QEMU" == "true" ]]; then
        tools+=( "qemu-system-x86_64:QEMU" )
    fi

    for tool_info in "${tools[@]}"; do
        local tool="${tool_info%%:*}"
        local name="${tool_info#*:}"
        if ! command_exists "$tool"; then
            log "ERROR" "Prerequisite missing: ${name} ('${tool}' command not found)."
            missing_tools=$((missing_tools + 1))
        else
            log "INFO" "${name} found."
        fi
    done

    if [[ $missing_tools -gt 0 ]]; then
        error_exit "Please install the missing prerequisite(s) and try again."
    fi
    
    log "INFO" "All prerequisites are satisfied."
}

# Run the Packer build process
run_packer_build() {
    log "STEP" "Starting Packer build process..."
    
    if [ ! -f "$PACKER_CONFIG" ]; then
        error_exit "Packer configuration file not found: ${PACKER_CONFIG}"
    fi

    local packer_only_args=""
    local build_targets=()

    if [[ "$BUILD_VMWARE" == "true" ]]; then
        build_targets+=("vmware-iso.afcyber-siem")
    fi
    if [[ "$BUILD_VIRTUALBOX" == "true" ]]; then
        build_targets+=("virtualbox-iso.afcyber-siem")
    fi
    if [[ "$BUILD_QEMU" == "true" ]]; then
        build_targets+=("qemu.afcyber-siem")
    fi
    
    if [[ ${#build_targets[@]} -gt 0 ]]; then
        packer_only_args="-only=$(IFS=,; echo "${build_targets[*]}")"
    else
        error_exit "No build targets specified. Use --all or select a specific platform."
    fi

    log "INFO" "Initializing Packer plugins..."
    packer init . | tee -a "$LOG_FILE"

    log "INFO" "Validating Packer template..."
    packer validate . | tee -a "$LOG_FILE"

    log "INFO" "Executing Packer build for targets: ${build_targets[*]}"
    log "INFO" "Detailed build output is being logged to: ${LOG_FILE}"
    
    # Force Packer to use a specific color profile for consistent logging
    export PACKER_LOG=1
    packer build -color=false -on-error=cleanup ${packer_only_args} . 2>&1 | tee -a "$LOG_FILE"
    
    if [ ${PIPESTATUS[0]} -ne 0 ]; then
        error_exit "Packer build failed."
    fi

    log "INFO" "Packer build completed successfully."
}

# Generate SHA256 checksums for all artifacts
generate_checksums() {
    log "STEP" "Generating SHA256 checksums..."
    
    if [ ! -d "$BUILD_DIR" ]; then
        log "WARN" "Build directory not found. Skipping checksum generation."
        return
    fi
    
    cd "$BUILD_DIR"
    
    # Find all image files and generate checksums
    find . -type f \( -name "*.ova" -o -name "*.vmdk" -o -name "*.vdi" -o -name "*.qcow2" \) -exec sha256sum {} + > "${CHECKSUM_FILE}.tmp"
    
    if [ -s "${CHECKSUM_FILE}.tmp" ]; then
        mv "${CHECKSUM_FILE}.tmp" "$CHECKSUM_FILE"
        log "INFO" "Checksums generated and saved to ${CHECKSUM_FILE}"
        cat "$CHECKSUM_FILE" | tee -a "$LOG_FILE"
    else
        log "WARN" "No build artifacts found to generate checksums for."
        rm -f "${CHECKSUM_FILE}.tmp"
    fi
    
    cd "$SCRIPT_DIR"
}

# Verify the integrity of build artifacts using the checksum file
verify_checksums() {
    log "STEP" "Verifying artifact checksums..."
    
    if [ ! -f "$CHECKSUM_FILE" ]; then
        error_exit "Checksum file not found: ${CHECKSUM_FILE}. Cannot verify artifacts."
    fi
    
    cd "$BUILD_DIR"
    
    if sha256sum -c "$CHECKSUM_FILE" | tee -a "$LOG_FILE"; then
        log "INFO" "Checksum verification successful. All artifacts are intact."
    else
        error_exit "Checksum verification failed! Some artifacts may be corrupt."
    fi
    
    cd "$SCRIPT_DIR"
}

# Placeholder for uploading artifacts
upload_artifacts() {
    log "STEP" "Uploading artifacts (Placeholder)..."
    log "INFO" "This is a placeholder for your artifact distribution logic."
    log "INFO" "You can implement uploading to S3, Artifactory, etc. here."
    
    # Example using AWS CLI for S3
    # if command_exists aws; then
    #   log "INFO" "Uploading to S3 bucket 'my-artifact-bucket'..."
    #   aws s3 cp "${BUILD_DIR}" s3://my-artifact-bucket/afcyber-siem/ --recursive --exclude "*" --include "*.ova" --include "*.qcow2"
    #   aws s3 cp "${CHECKSUM_FILE}" s3://my-artifact-bucket/afcyber-siem/
    # else
    #   log "WARN" "AWS CLI not found. Skipping S3 upload."
    # fi
}

# Clean up build artifacts and logs
clean_build_dir() {
    log "STEP" "Cleaning build directory and logs..."
    
    if [ -d "$BUILD_DIR" ]; then
        read -p "Are you sure you want to delete all build artifacts in '${BUILD_DIR}'? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log "INFO" "Removing build directory: ${BUILD_DIR}"
            rm -rf "$BUILD_DIR"
            log "INFO" "Removing Packer cache..."
            rm -rf packer_cache
        fi
    else
        log "INFO" "Build directory not found. Nothing to clean."
    fi

    if [ -d "$LOG_DIR" ]; then
        read -p "Are you sure you want to delete all log files in '${LOG_DIR}'? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log "INFO" "Removing log directory: ${LOG_DIR}"
            rm -rf "$LOG_DIR"
        fi
    fi
    
    log "INFO" "Cleanup complete."
}

# Display a summary of the build process
show_summary() {
    log "STEP" "Build Summary"
    
    if [ -f "$MANIFEST_FILE" ]; then
        log "INFO" "Build artifacts created:"
        jq -r '.builds[-1].files[].name' "$MANIFEST_FILE" | while read -r line; do
            echo -e "  - ${BUILD_DIR}/${line}" | tee -a "$LOG_FILE"
        done
    else
        log "WARN" "Manifest file not found. Cannot display artifact list."
    fi
    
    if [ -f "$CHECKSUM_FILE" ]; then
        log "INFO" "Checksum file created at: ${CHECKSUM_FILE}"
    fi

    log "INFO" "The entire build process has been logged to: ${LOG_FILE}"
    log "INFO" "Build process finished successfully!"
}

# --- Main Execution ---

main() {
    # --- Default argument values ---
    BUILD_VMWARE=false
    BUILD_VIRTUALBOX=false
    BUILD_QEMU=false
    DO_VERIFY=false
    DO_UPLOAD=false
    DO_CLEAN=false

    # --- Argument Parsing ---
    if [ $# -eq 0 ]; then
        BUILD_VMWARE=true
        BUILD_VIRTUALBOX=true
        BUILD_QEMU=true
    fi

    while [[ $# -gt 0 ]]; do
        case $1 in
            --all)
                BUILD_VMWARE=true
                BUILD_VIRTUALBOX=true
                BUILD_QEMU=true
                shift
                ;;
            --vmware)
                BUILD_VMWARE=true
                shift
                ;;
            --virtualbox)
                BUILD_VIRTUALBOX=true
                shift
                ;;
            --qemu)
                BUILD_QEMU=true
                shift
                ;;
            --verify)
                DO_VERIFY=true
                shift
                ;;
            --upload)
                DO_UPLOAD=true
                shift
                ;;
            --clean)
                DO_CLEAN=true
                shift
                ;;
            -h|--help)
                print_help
                exit 0
                ;;
            *)
                error_exit "Unknown option: $1. Use --help for usage information."
                ;;
        esac
    done

    # --- Execution Flow ---
    
    # Start logging
    log "INFO" "Starting AfCyber SIEM VM Image Builder..."
    
    if [[ "$DO_CLEAN" == "true" ]]; then
        clean_build_dir
        exit 0
    fi

    validate_prerequisites
    run_packer_build
    generate_checksums
    show_summary

    if [[ "$DO_VERIFY" == "true" ]]; then
        verify_checksums
    fi

    if [[ "$DO_UPLOAD" == "true" ]]; then
        upload_artifacts
    fi

    log "INFO" "Script finished."
}

# --- Run the main function ---
main "$@"
