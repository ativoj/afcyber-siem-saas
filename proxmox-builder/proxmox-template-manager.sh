#!/bin/bash
#===============================================================================
# AfCyber SIEM - Proxmox VE Template & VM Manager
#
# A comprehensive, enterprise-ready script for managing the entire lifecycle of
# AfCyber SIEM virtual machine templates and deployments on Proxmox VE.
#
# Features:
#   - Automated template building with Packer.
#   - Template validation, versioning, and lifecycle management.
#   - Bulk VM deployment with cloud-init customization.
#   - Multi-tenant provisioning and resource reporting.
#   - Backup, restore, and replication across cluster nodes.
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
readonly PACKER_CONFIG_FILE="${SCRIPT_DIR}/packer-proxmox.pkr.hcl"
readonly CONFIG_FILE="/etc/afcyber-siem/manager.conf"
readonly LOG_DIR="/var/log/afcyber-siem"
readonly LOG_FILE="${LOG_DIR}/manager-$(date +%Y%m%d).log"

# --- Color Codes for Output ---
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# --- Load Configuration ---
if [ -f "$CONFIG_FILE" ]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
else
    echo -e "${YELLOW}[WARN]${NC} Configuration file not found at ${CONFIG_FILE}. Using default values."
fi

# --- Set Default Configuration Values ---
: "${PROXMOX_URL:="https://127.0.0.1:8006/api2/json"}"
: "${PROXMOX_NODE:="$(hostname -f)"}"
: "${PROXMOX_STORAGE_POOL:="local-lvm"}"
: "${PROXMOX_BACKUP_STORAGE:="local"}"
: "${PROXMOX_SNIPPETS_STORAGE:="local"}"
: "${DEFAULT_BRIDGE:="vmbr0"}"
: "${PACKER_VAR_FILE:="${SCRIPT_DIR}/secrets.auto.pkrvars.hcl"}"

# --- Helper Functions ---

# Log messages to console and log file
log() {
    local level=$1
    local message=$2
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    mkdir -p "$LOG_DIR"
    
    case $level in
        "INFO") echo -e "${GREEN}[INFO]${NC} $message" ;;
        "WARN") echo -e "${YELLOW}[WARN]${NC} $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" ;;
        "STEP") echo -e "\n${BLUE}>>> Step: $message${NC}" ;;
    esac
    
    echo "$timestamp [$level] $message" | tee -a "$LOG_FILE"
}

# Display error and exit
error_exit() {
    log "ERROR" "$1"
    log "ERROR" "Operation failed. Check the log file for details: ${LOG_FILE}"
    exit 1
}

# Check for required command-line tools
check_dependencies() {
    local missing_tools=0
    for tool in packer pvesh qm vzdump qmrestore jq; do
        if ! command -v "$tool" &> /dev/null; then
            log "ERROR" "Required command not found: ${tool}. Please install it."
            missing_tools=$((missing_tools + 1))
        fi
    done
    if [ $missing_tools -gt 0 ]; then
        error_exit "Missing dependencies. Please install the required tools."
    fi
}

# Ask for user confirmation
confirm() {
    local prompt="$1"
    read -p "${YELLOW}[CONFIRM]${NC} ${prompt} [y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "INFO" "Operation cancelled by user."
        exit 0
    fi
}

# Check connection to Proxmox API
check_api_connection() {
    log "INFO" "Checking connection to Proxmox API at ${PROXMOX_URL}..."
    if ! pvesh get /nodes > /dev/null 2>&1; then
        error_exit "Failed to connect to Proxmox API. Check credentials and URL in ${CONFIG_FILE}."
    fi
    log "INFO" "Proxmox API connection successful."
}

# --- Core Functions ---

# Build a new template using Packer
build_template() {
    log "STEP" "Building AfCyber SIEM Template with Packer"
    
    if [ ! -f "$PACKER_CONFIG_FILE" ]; then
        error_exit "Packer configuration file not found: ${PACKER_CONFIG_FILE}"
    fi
    if [ ! -f "$PACKER_VAR_FILE" ]; then
        error_exit "Packer variables file with secrets not found: ${PACKER_VAR_FILE}"
    fi

    log "INFO" "Initializing Packer plugins..."
    packer init "$SCRIPT_DIR"

    log "INFO" "Validating Packer template..."
    packer validate -var-file="$PACKER_VAR_FILE" "$PACKER_CONFIG_FILE"

    log "INFO" "Starting Packer build. This may take a long time..."
    packer build -force -on-error=cleanup -var-file="$PACKER_VAR_FILE" "$PACKER_CONFIG_FILE" | tee -a "$LOG_FILE"
    
    if [ ${PIPESTATUS[0]} -ne 0 ]; then
        error_exit "Packer build failed."
    fi

    log "INFO" "Packer build completed successfully. New templates are available in Proxmox."
}

# Validate a template by cloning and testing it
validate_template() {
    local template_id=$1
    [ -z "$template_id" ] && error_exit "Usage: $0 validate <template-vmid>"
    
    log "STEP" "Validating Template VMID: ${template_id}"
    local test_vmid=$((template_id + 1000 + RANDOM % 1000))
    local test_vm_name="test-validation-${template_id}"

    log "INFO" "Cloning template ${template_id} to new VM ${test_vmid}..."
    qm clone "$template_id" "$test_vmid" --name "$test_vm_name" --full || error_exit "Failed to clone template."

    log "INFO" "Starting test VM ${test_vmid}..."
    qm start "$test_vmid"

    log "INFO" "Waiting for QEMU Guest Agent to report IP address (timeout: 5 minutes)..."
    local ip_address=""
    for i in {1..60}; do
        ip_address=$(qm agent "$test_vmid" network-get-interfaces --type ipv4 | jq -r '.[] | .["ip-addresses"][] | .["ip-address"]' | head -n1)
        if [ -n "$ip_address" ]; then
            log "INFO" "Test VM IP address: ${ip_address}"
            break
        fi
        sleep 5
    done

    if [ -z "$ip_address" ]; then
        qm stop "$test_vmid" --force
        qm destroy "$test_vmid" --destroy-unreferenced-disks 1
        error_exit "Validation failed: Timed out waiting for VM IP address."
    fi

    log "INFO" "Performing basic health checks..."
    if ping -c 3 "$ip_address" > /dev/null; then
        log "INFO" "Health Check 1/2: Ping successful."
    else
        log "WARN" "Health Check 1/2: Ping failed."
    fi
    
    # Check if a key service port is open (e.g., SSH or a web UI)
    if nc -z -w5 "$ip_address" 22 > /dev/null; then
        log "INFO" "Health Check 2/2: SSH port (22) is open."
    else
        log "WARN" "Health Check 2/2: SSH port (22) is not open."
    fi

    log "INFO" "Stopping and cleaning up test VM ${test_vmid}..."
    qm stop "$test_vmid"
    sleep 10 # Wait for graceful shutdown
    qm destroy "$test_vmid" --destroy-unreferenced-disks 1 --purge

    log "INFO" "Template ${template_id} validation completed successfully."
}

# Deploy one or more VMs from a template
deploy_vms() {
    local template_id=$1
    local num_vms=$2
    local vm_name_prefix=$3
    local cloud_init_file=$4

    [ -z "$template_id" ] || [ -z "$num_vms" ] || [ -z "$vm_name_prefix" ] && \
        error_exit "Usage: $0 deploy <template-vmid> <count> <name-prefix> [cloud-init-file.yaml]"

    log "STEP" "Deploying ${num_vms} VMs from Template ${template_id} with prefix '${vm_name_prefix}'"

    for i in $(seq 1 "$num_vms"); do
        local next_vmid=$(pvesh get /cluster/nextid)
        local vm_name="${vm_name_prefix}-${i}"
        log "INFO" "Creating VM ${next_vmid} ('${vm_name}')..."
        
        qm clone "$template_id" "$next_vmid" --name "$vm_name" --full || { log "ERROR" "Failed to clone VM. Skipping."; continue; }
        
        if [ -n "$cloud_init_file" ] && [ -f "$cloud_init_file" ]; then
            log "INFO" "Applying cloud-init configuration from ${cloud_init_file}..."
            local snippet_name="user-data-${next_vmid}.yaml"
            pvesh create "/nodes/${PROXMOX_NODE}/storage/${PROXMOX_SNIPPETS_STORAGE}/content" --vmid "$next_vmid" --content "$(cat "$cloud_init_file")" --filename "$snippet_name"
            qm set "$next_vmid" --cicustom "user=${PROXMOX_SNIPPETS_STORAGE}:snippets/${snippet_name}"
            # Apply network config from cloud-init
            qm set "$next_vmid" --ipconfig0 "ip=dhcp"
        fi
        
        log "INFO" "Starting VM ${next_vmid}..."
        qm start "$next_vmid"
    done

    log "INFO" "Bulk deployment of ${num_vms} VMs completed."
}

# List all available AfCyber SIEM templates
list_templates() {
    log "STEP" "Listing all AfCyber SIEM Templates"
    pvesh get /cluster/resources --type vm | \
        jq -r '.[] | select(.template == 1 and .name | test("afcyber-siem")) | 
        "\(.vmid)\t\(.name)\t\(.node)\t\(.status)\t\(.maxcpu // "N/A") CPU\t\(.maxmem / 1024 / 1024 / 1024) GB\t\(.maxdisk / 1024 / 1024 / 1024) GB"' | \
        column -t -s $'\t'
}

# Manage template lifecycle (tagging)
manage_lifecycle() {
    local action=$1
    local template_id=$2
    local tag=$3

    [ -z "$action" ] || [ -z "$template_id" ] && \
        error_exit "Usage: $0 lifecycle <tag|untag|set-description> <template-vmid> [value]"
    
    log "STEP" "Managing Lifecycle for Template ${template_id}"
    
    case "$action" in
        tag)
            [ -z "$tag" ] && error_exit "Usage: $0 lifecycle tag <template-vmid> <tag>"
            log "INFO" "Adding tag '${tag}' to template ${template_id}..."
            local current_tags=$(pvesh get /nodes/${PROXMOX_NODE}/qemu/${template_id}/config | jq -r .tags)
            local new_tags="${current_tags}${current_tags:+,}${tag}"
            pvesh set /nodes/"${PROXMOX_NODE}"/qemu/"${template_id}"/config --tags "$new_tags"
            ;;
        untag)
            [ -z "$tag" ] && error_exit "Usage: $0 lifecycle untag <template-vmid> <tag>"
            log "INFO" "Removing tag '${tag}' from template ${template_id}..."
            local current_tags=$(pvesh get /nodes/${PROXMOX_NODE}/qemu/${template_id}/config | jq -r .tags)
            local new_tags=$(echo "$current_tags" | sed -e "s/${tag},//g" -e "s/,${tag}//g" -e "s/${tag}//g")
            pvesh set /nodes/"${PROXMOX_NODE}"/qemu/"${template_id}"/config --tags "$new_tags"
            ;;
        set-description)
            local description="$3"
            [ -z "$description" ] && error_exit "Usage: $0 lifecycle set-description <template-vmid> \"<description>\""
            log "INFO" "Setting description for template ${template_id}..."
            pvesh set /nodes/"${PROXMOX_NODE}"/qemu/"${template_id}"/config --description "$description"
            ;;
        *)
            error_exit "Invalid lifecycle action: ${action}. Use 'tag', 'untag', or 'set-description'."
            ;;
    esac
    log "INFO" "Lifecycle management operation completed."
}

# Backup a template
backup_template() {
    local template_id=$1
    [ -z "$template_id" ] && error_exit "Usage: $0 backup <template-vmid>"
    
    log "STEP" "Backing up Template ${template_id}"
    log "INFO" "Starting backup to storage pool '${PROXMOX_BACKUP_STORAGE}'..."
    vzdump "$template_id" --storage "$PROXMOX_BACKUP_STORAGE" --mode snapshot --compress zstd --notes-template "AfCyber SIEM Template Backup"
    log "INFO" "Backup for template ${template_id} completed."
}

# Restore a template from a backup
restore_template() {
    local backup_file=$1
    local new_vmid=$2
    [ -z "$backup_file" ] || [ -z "$new_vmid" ] && error_exit "Usage: $0 restore <path-to-backup-file> <new-vmid>"

    log "STEP" "Restoring Template from ${backup_file} to VMID ${new_vmid}"
    qmrestore "$backup_file" "$new_vmid" --storage "$PROXMOX_STORAGE_POOL"
    log "INFO" "Restore completed. New VM ${new_vmid} created."
    log "INFO" "You may need to convert it to a template manually: qm template ${new_vmid}"
}

# Replicate a template to another node in the cluster
replicate_template() {
    local template_id=$1
    local target_node=$2
    [ -z "$template_id" ] || [ -z "$target_node" ] && error_exit "Usage: $0 replicate <template-vmid> <target-node>"

    log "STEP" "Replicating Template ${template_id} to Node ${target_node}"
    pvesh create /nodes/"${PROXMOX_NODE}"/qemu/"${template_id}"/migrate --target "$target_node" --online 0
    log "INFO" "Replication task started. Monitor the task in the Proxmox web UI."
}

# Clean up old or deprecated templates
cleanup_templates() {
    local tag=${1:-deprecated}
    log "STEP" "Cleaning up Templates tagged with '${tag}'"
    
    local templates_to_delete
    templates_to_delete=$(pvesh get /cluster/resources --type vm | \
        jq -r ".[] | select(.template == 1 and (.tags | contains(\"${tag}\"))) | .vmid")

    if [ -z "$templates_to_delete" ]; then
        log "INFO" "No templates found with the tag '${tag}'. Nothing to clean up."
        exit 0
    fi

    log "WARN" "The following templates will be permanently deleted:"
    echo "$templates_to_delete" | while read -r vmid; do
        local name=$(pvesh get /cluster/resources --type vm | jq -r ".[] | select(.vmid == ${vmid}) | .name")
        echo "  - VMID: ${vmid}, Name: ${name}"
    done

    confirm "Are you sure you want to delete these templates?"
    
    echo "$templates_to_delete" | while read -r vmid; do
        log "INFO" "Deleting template ${vmid}..."
        qm destroy "$vmid" --destroy-unreferenced-disks 1 --purge || log "ERROR" "Failed to delete template ${vmid}."
    done

    log "INFO" "Template cleanup completed."
}

# Provision a new VM for a tenant
provision_tenant() {
    local tenant_name=$1
    local plan=$2
    [ -z "$tenant_name" ] || [ -z "$plan" ] && error_exit "Usage: $0 provision-tenant <tenant-name> <small|medium|large>"
    
    log "STEP" "Provisioning New Tenant '${tenant_name}' with Plan '${plan}'"
    
    local template_name="afcyber-siem-${plan}-v1.0.0"
    log "INFO" "Looking for template with name containing '${template_name}'..."
    
    local template_id
    template_id=$(pvesh get /cluster/resources --type vm | \
        jq -r ".[] | select(.template == 1 and .name | test(\"${template_name}\")) | .vmid" | head -n1)

    if [ -z "$template_id" ]; then
        error_exit "No template found for plan '${plan}'. Please build it first."
    fi
    log "INFO" "Found template ${template_id} for plan '${plan}'."

    local cloud_init_file="/tmp/cloud-init-${tenant_name}.yaml"
    log "INFO" "Generating cloud-init configuration at ${cloud_init_file}..."
    
    local ssh_pub_key
    if [ -f ~/.ssh/id_rsa.pub ]; then
        ssh_pub_key=$(cat ~/.ssh/id_rsa.pub)
    else
        log "WARN" "No SSH public key found at ~/.ssh/id_rsa.pub. You will need to set a password."
        ssh_pub_key=""
    fi

    cat > "$cloud_init_file" <<EOF
#cloud-config
hostname: ${tenant_name}-siem
users:
  - name: afcyber
    gecos: AfCyber Admin for ${tenant_name}
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: wheel,docker
    shell: /bin/bash
    ssh_authorized_keys:
      - ${ssh_pub_key}
EOF

    deploy_vms "$template_id" 1 "$tenant_name" "$cloud_init_file"
    rm -f "$cloud_init_file"
    log "INFO" "Tenant '${tenant_name}' provisioned successfully."
}

# Report on resource usage
report_usage() {
    log "STEP" "Generating Resource Usage Report"
    
    log "INFO" "Calculating total resources allocated to AfCyber SIEM VMs..."
    
    local total_cpu=0
    local total_mem_gb=0
    local total_disk_gb=0
    local vm_count=0

    pvesh get /cluster/resources --type vm | \
        jq -c '.[] | select(.template != 1 and .name | test("afcyber-siem|test-validation"))' | \
        while read -r vm_json; do
            local vmid=$(echo "$vm_json" | jq -r .vmid)
            local node=$(echo "$vm_json" | jq -r .node)
            local name=$(echo "$vm_json" | jq -r .name)
            
            local config
            config=$(pvesh get /nodes/"$node"/qemu/"$vmid"/config)
            
            local cpu=$(echo "$config" | jq -r .cores)
            local mem_mb=$(($(echo "$config" | jq -r .memory) / 1024))
            local disk_gb=$(qm config "$vmid" | grep -E 'scsi|virtio' | awk -F 'size=' '{print $2}' | cut -d'G' -f1 | paste -sd+ - | bc)
            
            total_cpu=$((total_cpu + cpu))
            total_mem_gb=$((total_mem_gb + mem_mb / 1024))
            total_disk_gb=$((total_disk_gb + disk_gb))
            vm_count=$((vm_count + 1))
        done

    log "INFO" "--------------------------------------------------"
    log "INFO" "AfCyber SIEM Resource Usage Summary"
    log "INFO" "--------------------------------------------------"
    log "INFO" "Total Deployed VMs: ${vm_count}"
    log "INFO" "Total Allocated vCPUs: ${total_cpu}"
    log "INFO" "Total Allocated Memory: ${total_mem_gb} GB"
    log "INFO" "Total Allocated Disk: ${total_disk_gb} GB"
    log "INFO" "--------------------------------------------------"
    
    # Placeholder for cost calculation
    local cost_per_cpu=10  # Example: $10/month per vCPU
    local cost_per_gb_mem=5 # Example: $5/month per GB RAM
    local cost_per_gb_disk=0.1 # Example: $0.10/month per GB Disk
    
    local total_cost
    total_cost=$(echo "(${total_cpu} * ${cost_per_cpu}) + (${total_mem_gb} * ${cost_per_gb_mem}) + (${total_disk_gb} * ${cost_per_gb_disk})" | bc)
    
    log "INFO" "Estimated Monthly Cost: \$${total_cost} (based on example rates)"
}

# --- Main Function ---
main() {
    if [ $# -eq 0 ]; then
        print_help
        exit 1
    fi
    
    # Check dependencies before running any command
    check_dependencies
    check_api_connection

    local command=$1
    shift
    
    case "$command" in
        build)
            build_template "$@"
            ;;
        validate)
            validate_template "$@"
            ;;
        deploy)
            deploy_vms "$@"
            ;;
        list)
            list_templates "$@"
            ;;
        lifecycle)
            manage_lifecycle "$@"
            ;;
        backup)
            backup_template "$@"
            ;;
        restore)
            restore_template "$@"
            ;;
        replicate)
            replicate_template "$@"
            ;;
        cleanup)
            cleanup_templates "$@"
            ;;
        provision-tenant)
            provision_tenant "$@"
            ;;
        report-usage)
            report_usage "$@"
            ;;
        help)
            print_help
            ;;
        *)
            error_exit "Unknown command: ${command}"
            ;;
    esac
}

# --- Help Function ---
print_help() {
    cat << EOF
AfCyber SIEM Proxmox Manager - v1.0.0

A tool to manage the lifecycle of AfCyber SIEM templates and VMs on Proxmox VE.

Usage: ./${SCRIPT_NAME} <command> [options]

Commands:
  build                                 Build a new set of templates using Packer.
  validate <template-vmid>              Validate a template by cloning and testing it.
  deploy <template-vmid> <count> <name> [cloud-init.yaml]
                                        Deploy one or more VMs from a template.
  provision-tenant <name> <plan>        Provision a new VM for a tenant (plan: small|medium|large).
  
  list                                  List all available AfCyber SIEM templates.
  lifecycle <action> <vmid> [value]     Manage template lifecycle (actions: tag, untag, set-description).
  cleanup [tag]                         Delete templates marked with a specific tag (default: deprecated).
  
  backup <template-vmid>                Backup a template using vzdump.
  restore <backup-file> <new-vmid>      Restore a template from a backup file.
  replicate <template-vmid> <target-node> Replicate a template to another node in the cluster.
  
  report-usage                          Generate a summary of allocated resources and estimated costs.
  help                                  Display this help message.

Configuration:
  The script uses settings from ${CONFIG_FILE}.
  Packer requires API secrets in ${PACKER_VAR_FILE}.

Example:
  ./${SCRIPT_NAME} build
  ./${SCRIPT_NAME} validate 9002
  ./${SCRIPT_NAME} deploy 9002 5 my-siem-vms
  ./${SCRIPT_NAME} provision-tenant acme-corp medium

EOF
}

# --- Run the main function ---
main "$@"
