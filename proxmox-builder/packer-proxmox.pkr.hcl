# AfCyber SIEM - Multi-Tenant SaaS Platform
# Packer Configuration for Proxmox VE
#
# This Packer configuration automates the creation of a production-ready
# Proxmox VM template with the entire AfCyber SIEM platform pre-installed.
# It is designed for enterprise environments with a focus on security,
# performance, and automation.
#
# Author: AfCyber Labs
# License: Apache-2.0
# Version: 1.0.0

#===============================================================================
# Packer Block: Required Plugins
#===============================================================================
packer {
  required_version = ">= 1.8.0"
  required_plugins {
    proxmox = {
      version = ">= 1.1.3"
      source  = "github.com/hashicorp/proxmox"
    }
    ansible = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/ansible"
    }
    shell = {
      version = ">= 0.0.0"
      source  = "github.com/hashicorp/shell"
    }
  }
}

#===============================================================================
# Local Variables: Centralized Configuration
#===============================================================================
locals {
  # OS and Kickstart Configuration
  os_name           = "AlmaLinux"
  os_version        = "9.3"
  iso_url           = "https://repo.almalinux.org/almalinux/9/isos/x86_64/AlmaLinux-9.3-x86_64-minimal.iso"
  iso_checksum      = "sha256:73721349b39eb53b65402927e16f14545b89a87d3a4b64d1c67d121c2503253b"
  kickstart_file    = "http/ks.cfg"

  # SSH credentials for Packer to connect to the VM during the build
  ssh_username = "packer"
  ssh_password = "a_very_secure_packer_password" # This is temporary for the build process only
  ssh_timeout  = "30m"

  # Application and script paths within the VM
  app_dir        = "/opt/afcyber-siem-saas"
  scripts_dir    = "/tmp/scripts"
  config_dir     = "/tmp/config"
  project_source = "../" # Relative path to the root of the afcyber-siem-saas project
}

#===============================================================================
# Input Variables: User-configurable settings for different environments
#===============================================================================
variable "proxmox_url" {
  type        = string
  description = "The URL of the Proxmox API (e.g., https://pve.example.com:8006/api2/json)."
  sensitive   = true
}

variable "proxmox_token_id" {
  type        = string
  description = "The Proxmox API Token ID (e.g., user@pam!tokenid)."
  sensitive   = true
}

variable "proxmox_token_secret" {
  type        = string
  description = "The secret for the Proxmox API Token."
  sensitive   = true
}

variable "proxmox_node" {
  type        = string
  description = "The Proxmox node where the VM will be built."
}

variable "proxmox_insecure_skip_tls_verify" {
  type        = bool
  description = "If true, the Proxmox server's TLS certificate will not be verified."
  default     = true
}

variable "network_bridge" {
  type        = string
  description = "The Proxmox network bridge to connect the VM to (e.g., vmbr0)."
  default     = "vmbr0"
}

variable "storage_pool" {
  type        = string
  description = "The Proxmox storage pool for the VM disk (e.g., local-lvm)."
  default     = "local-lvm"
}

variable "iso_storage_pool" {
  type        = string
  description = "The Proxmox storage pool where the OS ISO is stored (e.g., local)."
  default     = "local"
}

#===============================================================================
# Source Blocks: Define builders for different template variants
#===============================================================================

# --- Base Source Configuration (Inherited by all variants) ---
source "hcl" "almalinux-base" {
  # Proxmox API Connection
  proxmox_url                = var.proxmox_url
  token_id                   = var.proxmox_token_id
  token_secret               = var.proxmox_token_secret
  insecure_skip_tls_verify   = var.proxmox_insecure_skip_tls_verify
  node                       = var.proxmox_node

  # OS and ISO Configuration
  iso_url                    = local.iso_url
  iso_checksum               = local.iso_checksum
  iso_storage_pool           = var.iso_storage_pool
  unmount_iso                = true

  # Boot and SSH Configuration
  boot_command = [
    "<up><wait><tab> ",
    "inst.ks=http://{{ .HTTPIP }}:{{ .HTTPPort }}/${local.kickstart_file}",
    " inst.sshd<enter>"
  ]
  boot_wait                  = "10s"
  ssh_username               = local.ssh_username
  ssh_password               = local.ssh_password
  ssh_timeout                = local.ssh_timeout
  ssh_handshake_attempts     = "30"
  ssh_pty                    = true

  # Proxmox-specific VM Optimizations
  os                         = "l26" # Linux 6.x Kernel
  qemu_agent                 = true  # Enable QEMU Guest Agent for better management
  scsi_controller            = "virtio-scsi-pci" # High-performance SCSI controller
  network_adapters {
    model  = "virtio"
    bridge = var.network_bridge
  }
  disks {
    type           = "scsi"
    storage_pool   = var.storage_pool
    disk_size      = "10G" # Base size, will be overridden by specific variants
    format         = "qcow2"
    cache          = "writeback"
    discard        = true # Enable TRIM/discard for better SSD performance
  }
  
  # Disable ballooning for stable performance on memory-intensive SIEM workloads
  balloon_size = 0
}

# --- Small Template Variant ---
source "proxmox-iso" "afcyber-siem-small" {
  source = source.hcl.almalinux-base
  
  # VM Identification
  vm_id   = 9001
  vm_name = "afcyber-siem-small-template"
  
  # Resource Allocation
  cores   = 8
  sockets = 1
  memory  = 16384 # 16 GB
  disks {
    disk_size = "250G"
  }
  
  # Template Configuration
  template_name        = "afcyber-siem-small-v1.0.0"
  template_description = <<EOT
AfCyber SIEM - Small Template (v1.0.0)
- 8 vCPU, 16 GB RAM, 250 GB Disk
- Suitable for development, testing, or small deployments (<500 EPS).
- Built on ${local.os_name} ${local.os_version}
- Built at: ${timestamp()}
EOT
}

# --- Medium Template Variant ---
source "proxmox-iso" "afcyber-siem-medium" {
  source = source.hcl.almalinux-base
  
  # VM Identification
  vm_id   = 9002
  vm_name = "afcyber-siem-medium-template"
  
  # Resource Allocation
  cores   = 16
  sockets = 1
  memory  = 32768 # 32 GB
  disks {
    disk_size = "500G"
  }
  
  # Template Configuration
  template_name        = "afcyber-siem-medium-v1.0.0"
  template_description = <<EOT
AfCyber SIEM - Medium Template (v1.0.0)
- 16 vCPU, 32 GB RAM, 500 GB Disk
- Recommended for most production deployments (up to 5,000 EPS).
- Built on ${local.os_name} ${local.os_version}
- Built at: ${timestamp()}
EOT
}

# --- Large Template Variant ---
source "proxmox-iso" "afcyber-siem-large" {
  source = source.hcl.almalinux-base
  
  # VM Identification
  vm_id   = 9003
  vm_name = "afcyber-siem-large-template"
  
  # Resource Allocation
  cores   = 32
  sockets = 1
  memory  = 65536 # 64 GB
  disks {
    disk_size = "1T"
  }
  
  # Template Configuration
  template_name        = "afcyber-siem-large-v1.0.0"
  template_description = <<EOT
AfCyber SIEM - Large Template (v1.0.0)
- 32 vCPU, 64 GB RAM, 1 TB Disk
- For large-scale enterprise deployments or MSSPs (>10,000 EPS).
- Built on ${local.os_name} ${local.os_version}
- Built at: ${timestamp()}
EOT
}

#===============================================================================
# Build Block: Defines the provisioning and post-processing steps
#===============================================================================
build {
  # Build all defined sources in a single run
  sources = [
    "source.proxmox-iso.afcyber-siem-small",
    "source.proxmox-iso.afcyber-siem-medium",
    "source.proxmox-iso.afcyber-siem-large"
  ]

  # --- Provisioners (executed in order inside the VM) ---

  # 1. Upload all necessary files and scripts
  provisioner "file" {
    source      = local.project_source
    destination = "/tmp/afcyber-siem-saas"
  }

  provisioner "file" {
    source      = "scripts/"
    destination = local.scripts_dir
  }

  provisioner "file" {
    source      = "config/"
    destination = local.config_dir
  }

  # 2. Execute the main setup script to install the entire stack
  provisioner "shell" {
    environment_vars = [
      "APP_DIR=${local.app_dir}",
      "DEBIAN_FRONTEND=noninteractive"
    ]
    execute_command = "echo '${local.ssh_password}' | sudo -S -E bash -eux '{{ .Path }}'"
    script          = "scripts/00-main-setup.sh"
  }

  # 3. Apply security hardening using Ansible
  provisioner "ansible" {
    playbook_file   = "ansible/security-hardening.yml"
    extra_arguments = [
      "--extra-vars", "ansible_user=${local.ssh_username} ansible_password=${local.ssh_password}",
      "--ssh-extra-args", "-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"
    ]
  }

  # 4. Run final cleanup script to reduce template size
  provisioner "shell" {
    execute_command = "echo '${local.ssh_password}' | sudo -S -E bash -eux '{{ .Path }}'"
    script          = "scripts/99-cleanup.sh"
    expect_disconnect = true # The cleanup script will shut down the VM
  }

  # --- Post-Processors (executed after the VM is shut down) ---

  # 1. Convert the final VM into a Proxmox Template
  # This is handled by the Proxmox builder itself, which will be the last step.
  # The builder will automatically convert the VM to a template.

  # 2. Generate a manifest file with build artifact details
  post-processor "manifest" {
    output     = "builds/proxmox-manifest.json"
    strip_path = true
    custom_data = {
      build_node = var.proxmox_node
      build_time = timestamp()
    }
  }

  # 3. (Optional) Trigger a backup of the new template via Proxmox API
  # This demonstrates integration with backup systems.
  post-processor "shell-local" {
    inline = [
      "echo 'Build complete for VM ID {{ .VMID }} named {{ .VMName }}.'",
      "echo 'Triggering backup of the new template via Proxmox API... (placeholder)'",
      "# Example command using pvesh (Proxmox shell):",
      "# pvesh create /nodes/${var.proxmox_node}/vzdump --vmid {{ .VMID }} --mode snapshot --compress zstd --storage <your-backup-storage>",
      "echo 'A backup can be triggered using a script here.'"
    ]
  }
}
