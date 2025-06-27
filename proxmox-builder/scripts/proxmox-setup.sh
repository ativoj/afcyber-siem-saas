#!/bin/bash -eux
#===============================================================================
# AfCyber SIEM - Proxmox VE Setup Script
#
# This script is executed by Packer inside the VM to install and configure the
# entire AfCyber SIEM platform, specifically optimized for deployment as a
# Proxmox VE template.
#
# Features:
# - Proxmox Guest Agent installation for host integration.
# - Cloud-init optimizations for seamless cloning and customization.
# - Storage and performance tuning for KVM virtualized environments.
# - Pre-baking of all application components and container images.
# - Comprehensive cleanup for creating a minimal and secure template.
#
# Author: AfCyber Labs
# License: Apache-2.0
#===============================================================================

# --- Helper Functions ---
log() {
    echo "==> ${1}: ${2}"
}

error_exit() {
    log "ERROR" "$1"
    exit 1
}

section_header() {
    log "INFO" "======================================================================"
    log "INFO" "$1"
    log "INFO" "======================================================================"
}

# --- Initial System Configuration ---
section_header "Step 1: Initial System Configuration & Package Installation"

log "INFO" "Updating system packages and installing essentials..."
dnf -y update || error_exit "Failed to update system packages"
dnf -y install epel-release || error_exit "Failed to install EPEL repository"
dnf -y install curl wget git vim htop net-tools unzip jq policycoreutils-python-utils setools-console firewalld chrony logrotate openssl python3-pip || error_exit "Failed to install essential packages"

# --- Proxmox Guest Agent & Cloud-Init Setup ---
section_header "Step 2: Proxmox Integration (Guest Agent & Cloud-Init)"

log "INFO" "Installing Proxmox QEMU Guest Agent..."
dnf -y install qemu-guest-agent || error_exit "Failed to install qemu-guest-agent"
systemctl enable --now qemu-guest-agent
log "INFO" "QEMU Guest Agent enabled. VM can now be gracefully managed by Proxmox."

log "INFO" "Installing and configuring Cloud-Init for Proxmox..."
dnf -y install cloud-init cloud-utils-growpart || error_exit "Failed to install cloud-init"
log "INFO" "Configuring cloud-init to use Proxmox datasource..."
cat > /etc/cloud/cloud.cfg.d/99-proxmox.cfg << EOF
# Proxmox Cloud-Init Datasource Configuration
# This ensures cloud-init uses the ConfigDrive provided by Proxmox VE.
datasource_list: [ NoCloud, ConfigDrive, OpenStack, Ec2, Azure, GCP ]
datasource:
  ConfigDrive:
    dsmode: local
system_info:
  distro: almalinux
  default_user:
    name: afcyber
    gecos: AfCyber Admin
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: [wheel, docker]
    shell: /bin/bash
    lock_passwd: true
# Grow the root partition on first boot if the disk is resized in Proxmox
growpart:
  mode: auto
  devices: ['/']
# Disable network configuration by cloud-init if NetworkManager is preferred
# but allow it for Proxmox to inject network settings.
network:
  config: disabled
EOF
systemctl enable cloud-init
log "INFO" "Cloud-init configured. The template will be customizable on clone."

# --- Storage & Performance Tuning for Virtualized Environment ---
section_header "Step 3: Storage and Performance Tuning for Proxmox KVM"

log "INFO" "Applying kernel performance settings for KVM..."
cat > /etc/sysctl.d/99-proxmox-kvm.conf << EOF
# Use KVM's paravirtualized clock for better timekeeping
kernel.sched_clock = paravirt
# Reduce swappiness for database and SIEM workloads
vm.swappiness = 10
# Increase file descriptor limits
fs.file-max = 1048576
# For Elasticsearch: Increase virtual memory map count
vm.max_map_count = 262144
# Network tuning for high throughput
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 4096
EOF
sysctl --system
log "INFO" "Kernel parameters tuned for virtualization."

log "INFO" "Optimizing I/O scheduler for virtual disks..."
# For virtual environments, 'none' (noop) or 'mq-deadline' is often best.
# This can be set via udev rules for persistence.
cat > /etc/udev/rules.d/60-io-schedulers.rules << EOF
ACTION=="add|change", KERNEL=="sd[a-z]|vd[a-z]", ATTR{queue/scheduler}="none"
EOF
log "INFO" "I/O scheduler set to 'none' for virtual disks."

log "INFO" "Enabling periodic TRIM for thin-provisioned storage (LVM-thin/ZFS)..."
systemctl enable fstrim.timer
log "INFO" "fstrim.timer enabled. Unused blocks will be discarded weekly."

# --- Container Runtime Installation (Docker & K3s) ---
section_header "Step 4: Install and Optimize Container Runtimes"

log "INFO" "Installing Docker..."
dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
dnf -y install docker-ce docker-ce-cli containerd.io || error_exit "Failed to install Docker"
systemctl enable --now docker

log "INFO" "Installing Docker Compose..."
curl -L "https://github.com/docker/compose/releases/download/v2.20.3/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

log "INFO" "Installing Kubernetes (K3s)..."
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--docker" sh - || error_exit "Failed to install K3s"
mkdir -p /root/.kube
cp /etc/rancher/k3s/k3s.yaml /root/.kube/config
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
log "INFO" "K3s installed. Waiting for node to become ready..."
timeout 120 bash -c 'until kubectl get nodes | grep -q " Ready "; do sleep 5; done' || error_exit "K3s node did not become ready in time"

# --- Application Deployment ---
section_header "Step 5: Deploy AfCyber SIEM Application Stack"

log "INFO" "Moving application files to /opt/afcyber-siem-saas..."
mv /tmp/afcyber-siem-saas /opt/afcyber-siem-saas
chown -R root:root /opt/afcyber-siem-saas
chmod -R 750 /opt/afcyber-siem-saas

log "INFO" "Creating data directories..."
mkdir -p /var/lib/afcyber-siem/{postgres,elasticsearch,wazuh,graylog,thehive,opencti,misp,velociraptor,redis,kafka,ml-models}
chown -R 1000:1000 /var/lib/afcyber-siem # Common user ID for containers
chmod -R 770 /var/lib/afcyber-siem

log "INFO" "Generating production .env file with secrets..."
ENV_FILE_PATH="/opt/afcyber-siem-saas/.env"
cp "/opt/afcyber-siem-saas/.env.example" "${ENV_FILE_PATH}"
# Replace placeholders with securely generated random values
sed -i "s/change_this_to_a_random_string_at_least_32_chars/$(openssl rand -base64 32)/g" "${ENV_FILE_PATH}"
sed -i "s/change_this_to_another_random_string_at_least_32_chars/$(openssl rand -base64 32)/g" "${ENV_FILE_PATH}"
sed -i "s/change_this_to_a_secure_password/$(openssl rand -base64 24)/g" "${ENV_FILE_PATH}"
sed -i "s/change_this_to_a_random_string_at_least_64_chars/$(openssl rand -base64 64)/g" "${ENV_FILE_PATH}"
sed -i "s/8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918/$(echo -n "$(openssl rand -base64 24)" | sha256sum | cut -d' ' -f1)/g" "${ENV_FILE_PATH}"
log "INFO" "Production .env file created."

log "INFO" "Pre-pulling all required Docker images to bake into the template..."
cd /opt/afcyber-siem-saas
/usr/local/bin/docker-compose pull || error_exit "Failed to pull Docker images"
log "INFO" "All Docker images have been pulled successfully."

# --- Proxmox Monitoring Integration ---
section_header "Step 6: Install Advanced Monitoring Agents"

log "INFO" "Installing Prometheus Node Exporter for advanced metrics..."
dnf -y install prometheus-node-exporter || error_exit "Failed to install Prometheus Node Exporter"
systemctl enable --now prometheus-node-exporter
# Open firewall port for Prometheus scraping
firewall-cmd --permanent --add-port=9100/tcp
firewall-cmd --reload
log "INFO" "Node Exporter installed. Metrics available on port 9100."

# --- Final Template Preparation & Cleanup ---
section_header "Step 7: Finalizing Template for Distribution"

log "INFO" "Cleaning DNF cache..."
dnf clean all

log "INFO" "Removing temporary files..."
rm -rf /tmp/*
rm -rf /var/tmp/*

log "INFO" "Cleaning cloud-init state..."
cloud-init clean --logs --seed

log "INFO" "Removing Packer's temporary SSH key..."
rm -f /root/.ssh/authorized_keys
rm -f /home/packer/.ssh/authorized_keys

log "INFO" "Clearing shell history..."
cat /dev/null > /root/.bash_history && history -c
if [ -f /home/packer/.bash_history ]; then
    cat /dev/null > /home/packer/.bash_history && history -c
fi

log "INFO" "Resetting machine-id..."
truncate -s 0 /etc/machine-id
rm /var/lib/dbus/machine-id
ln -s /etc/machine-id /var/lib/dbus/machine-id

log "INFO" "Removing SSH host keys (will be regenerated on first boot)..."
rm -f /etc/ssh/ssh_host_*

log "INFO" "Trimming filesystem to reduce template size..."
fstrim -av

log "INFO" "Zeroing out free space to improve compression..."
dd if=/dev/zero of=/zero bs=1M || echo "dd exit code $? is suppressed"
rm -f /zero
# Sync to ensure all data is written to disk
sync
sync
sync

log "INFO" "Proxmox template setup complete. The VM is ready to be shut down and converted."
