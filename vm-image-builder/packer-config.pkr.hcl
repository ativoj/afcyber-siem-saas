# AfCyber SIEM - Multi-Tenant SaaS Platform
# Packer Configuration for Building a Production-Ready VM Image
#
# This Packer configuration automates the creation of a distributable VM image
# with the entire AfCyber SIEM platform pre-installed and configured on Alma Linux.
#
# Author: AfCyber Labs
# License: Apache-2.0
# Version: 1.0.0

packer {
  required_version = ">= 1.8.0"
  required_plugins {
    virtualbox = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/virtualbox"
    }
    vmware = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/vmware"
    }
    qemu = {
      version = ">= 2.0.0"
      source  = "github.com/hashicorp/qemu"
    }
    ansible = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/ansible"
    }
  }
}

#-------------------------------------------------------------------------------
# Local Variables - Centralized configuration for the VM image
#-------------------------------------------------------------------------------
locals {
  # VM and OS configuration
  vm_name           = "afcyber-siem-saas-v1.0.0"
  hostname          = "afcyber-siem"
  domain            = "local"
  os_version        = "9.3"
  iso_url           = "https://repo.almalinux.org/almalinux/9/isos/x86_64/AlmaLinux-9.3-x86_64-minimal.iso"
  iso_checksum      = "sha256:73721349b39eb53b65402927e16f14545b89a87d3a4b64d1c67d121c2503253b"
  kickstart_file    = "http/ks.cfg"
  output_directory  = "builds"

  # VM hardware specifications
  cpu_cores   = 16
  memory_mb   = 32768 # 32 GB
  disk_size_mb = 512000 # 500 GB

  # SSH configuration for Packer to connect to the VM
  ssh_username = "packer"
  ssh_password = "a_very_secure_packer_password"
  ssh_timeout  = "20m"

  # Application and deployment configuration
  app_dir        = "/opt/afcyber-siem-saas"
  scripts_dir    = "/tmp/scripts"
  config_dir     = "/tmp/config"
  project_source = "../" # Relative path to the root of the afcyber-siem-saas project

  # Versioning for key components
  docker_version         = "24.0.5"
  docker_compose_version = "2.20.3"
  k3s_version            = "v1.27.4+k3s1"
}

#-------------------------------------------------------------------------------
# Source Blocks - Define builders for different virtualization platforms
#-------------------------------------------------------------------------------

# Common source configuration to be inherited by all builders
source "hcl" "almalinux-base" {
  # Boot configuration for automated Kickstart installation
  boot_command = [
    "<up><wait><tab> ",
    "inst.ks=http://{{ .HTTPIP }}:{{ .HTTPPort }}/${local.kickstart_file}",
    " inst.sshd<enter>"
  ]
  boot_wait         = "10s"
  http_directory    = "http"
  shutdown_command  = "sudo /sbin/halt -p"
  shutdown_timeout  = "15m"

  # SSH configuration for Packer
  ssh_username         = local.ssh_username
  ssh_password         = local.ssh_password
  ssh_timeout          = local.ssh_timeout
  ssh_handshake_attempts = "20"
  ssh_pty              = true

  # ISO configuration
  iso_url      = local.iso_url
  iso_checksum = local.iso_checksum

  # VM hardware configuration
  cpus     = local.cpu_cores
  memory   = local.memory_mb
  disk_size = local.disk_size_mb
}

# VMware Builder
source "vmware-iso" "afcyber-siem" {
  source = source.hcl.almalinux-base
  vm_name              = local.vm_name
  output_directory     = "${local.output_directory}/vmware"
  guest_os_type        = "almalinux-64"
  disk_adapter_type    = "pvscsi"
  network_adapter_type = "vmxnet3"
  tools_upload_flavor  = "linux"
  headless             = true
}

# VirtualBox Builder
source "virtualbox-iso" "afcyber-siem" {
  source = source.hcl.almalinux-base
  vm_name              = local.vm_name
  output_directory     = "${local.output_directory}/virtualbox"
  guest_os_type        = "RedHat_64"
  hard_drive_interface = "sata"
  iso_interface        = "sata"
  vboxmanage = [
    ["modifyvm", "{{.Name}}", "--nat-localhostreachable1", "on"],
    ["modifyvm", "{{.Name}}", "--nic-type1", "virtio"],
    ["modifyvm", "{{.Name}}", "--vram", "32"],
    ["modifyvm", "{{.Name}}", "--graphicscontroller", "vmsvga"],
  ]
  headless = true
}

# QEMU Builder
source "qemu" "afcyber-siem" {
  source = source.hcl.almalinux-base
  vm_name          = local.vm_name
  output_directory = "${local.output_directory}/qemu"
  disk_interface   = "virtio-scsi"
  net_device       = "virtio-net"
  accelerator      = "kvm"
  qemu_binary      = "/usr/bin/qemu-system-x86_64"
  format           = "qcow2"
  headless         = true
}

#-------------------------------------------------------------------------------
# Build Block - Defines the provisioning process
#-------------------------------------------------------------------------------

build {
  # Define which sources to build
  sources = [
    "source.vmware-iso.afcyber-siem",
    "source.virtualbox-iso.afcyber-siem",
    "source.qemu.afcyber-siem"
  ]

  # Provisioners are executed in order
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

  # Execute the main setup script
  provisioner "shell" {
    environment_vars = [
      "APP_DIR=${local.app_dir}",
      "SCRIPTS_DIR=${local.scripts_dir}",
      "CONFIG_DIR=${local.config_dir}",
      "HOSTNAME=${local.hostname}",
      "DOMAIN=${local.domain}",
      "DOCKER_VERSION=${local.docker_version}",
      "DOCKER_COMPOSE_VERSION=${local.docker_compose_version}",
      "K3S_VERSION=${local.k3s_version}",
      "DEBIAN_FRONTEND=noninteractive"
    ]
    execute_command = "echo '${local.ssh_password}' | sudo -S -E bash -eux '{{ .Path }}'"
    script          = "scripts/00-main-setup.sh"
  }

  # Security Hardening using Ansible
  provisioner "ansible" {
    playbook_file = "ansible/security-hardening.yml"
    extra_arguments = [
      "--extra-vars", "ansible_user=${local.ssh_username} ansible_password=${local.ssh_password}",
      "--ssh-extra-args", "-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"
    ]
  }

  # Final cleanup script
  provisioner "shell" {
    execute_command = "echo '${local.ssh_password}' | sudo -S -E bash -eux '{{ .Path }}'"
    script          = "scripts/99-cleanup.sh"
  }

  # Generate a manifest file with build artifacts
  post-processor "manifest" {
    output     = "manifest.json"
    strip_path = true
  }
}
