#!/bin/bash -eux
#===============================================================================
# AfCyber SIEM - Main Setup Script for Packer
#
# This script is executed by Packer inside the VM to install and configure
# the entire AfCyber SIEM platform. It's designed to be idempotent and
# robust for automated image creation.
#
# Author: AfCyber Labs
# License: Apache-2.0
#===============================================================================

#-------------------------------------------------------------------------------
# Helper Functions
#-------------------------------------------------------------------------------

# Log messages to console and log file
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "$timestamp [$level] $message" | tee -a /var/log/packer-setup.log
}

# Display error and exit
error_exit() {
    log "ERROR" "$1"
    exit 1
}

# Display section header
section_header() {
    local title=$1
    echo ""
    echo "================================================================================"
    echo " $title"
    echo "================================================================================"
    echo ""
    log "INFO" "Starting section: $title"
}

# Generate a random password
generate_password() {
    openssl rand -base64 32 | tr -d '=+/' | head -c 32
}

#-------------------------------------------------------------------------------
# Initial System Setup
#-------------------------------------------------------------------------------
section_header "1. Initial System Setup"

log "INFO" "Updating system packages..."
dnf -y update || error_exit "Failed to update system packages"

log "INFO" "Installing essential packages..."
dnf -y install epel-release || error_exit "Failed to install EPEL repository"
dnf -y install curl wget git vim htop net-tools unzip jq yum-utils policycoreutils-python-utils setools-console firewalld chrony logrotate openssl python3-pip || error_exit "Failed to install essential packages"

log "INFO" "Setting hostname to ${HOSTNAME}.${DOMAIN}"
hostnamectl set-hostname "${HOSTNAME}.${DOMAIN}"

log "INFO" "Configuring time synchronization..."
systemctl enable --now chronyd
chronyc makestep

#-------------------------------------------------------------------------------
# Security Configuration
#-------------------------------------------------------------------------------
section_header "2. Security Configuration"

log "INFO" "Configuring firewall (firewalld)..."
systemctl enable --now firewalld
# Ports for Web UIs, APIs, and services
PORTS=(22 80 443 3000 5601 9000 9001 8080 8889)
# Ports for data ingestion
INGEST_PORTS=(514/udp 1514/tcp 1515/tcp 12201/udp 8000/tcp)

for port in "${PORTS[@]}"; do
    log "INFO" "Opening TCP port $port..."
    firewall-cmd --permanent --add-port=$port/tcp
done

for port in "${INGEST_PORTS[@]}"; do
    log "INFO" "Opening ingestion port $port..."
    firewall-cmd --permanent --add-port=$port
done

firewall-cmd --reload || error_exit "Failed to reload firewall"
log "INFO" "Firewall configured successfully."

log "INFO" "Configuring SELinux for containers..."
if sestatus | grep -q "SELinux status: *enabled"; then
    setsebool -P container_manage_cgroup on
    setsebool -P container_use_devices on
    # Allow containers to connect to network
    setsebool -P container_can_network_connect on
    # Allow containers to write to shared volumes
    semanage fcontext -a -t container_file_t "${APP_DIR}(/.*)?"
    restorecon -Rv "${APP_DIR}"
    log "INFO" "SELinux policies for containers applied."
else
    log "WARN" "SELinux is not enabled. It is highly recommended for production environments."
fi

#-------------------------------------------------------------------------------
# Install Docker, Docker Compose, and Kubernetes (K3s)
#-------------------------------------------------------------------------------
section_header "3. Install Core Containerization Tools"

log "INFO" "Installing Docker v${DOCKER_VERSION}..."
dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
dnf -y install docker-ce-${DOCKER_VERSION} docker-ce-cli-${DOCKER_VERSION} containerd.io || error_exit "Failed to install Docker"
systemctl enable --now docker

log "INFO" "Installing Docker Compose v${DOCKER_COMPOSE_VERSION}..."
curl -L "https://github.com/docker/compose/releases/download/v${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose

log "INFO" "Installing Kubernetes (K3s) v${K3S_VERSION}..."
curl -sfL https://get.k3s.io > /tmp/k3s-install.sh
chmod +x /tmp/k3s-install.sh
INSTALL_K3S_VERSION="${K3S_VERSION}" INSTALL_K3S_EXEC="--disable traefik --docker" /tmp/k3s-install.sh || error_exit "Failed to install K3s"
mkdir -p /root/.kube
cp /etc/rancher/k3s/k3s.yaml /root/.kube/config
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
log "INFO" "K3s installed successfully. Waiting for node to be ready..."
timeout 120 bash -c 'until kubectl get nodes | grep -q " Ready "; do sleep 5; done' || error_exit "K3s node did not become ready in time"

#-------------------------------------------------------------------------------
# Application Setup
#-------------------------------------------------------------------------------
section_header "4. AfCyber SIEM Application Setup"

log "INFO" "Moving application files to ${APP_DIR}..."
mv /tmp/afcyber-siem-saas "${APP_DIR}"
chown -R root:root "${APP_DIR}"
chmod -R 750 "${APP_DIR}"

log "INFO" "Creating data directories..."
mkdir -p /var/lib/afcyber-siem/{postgres,elasticsearch,wazuh,graylog,thehive,opencti,misp,velociraptor,redis,kafka,ml-models,backups}
chown -R 1000:1000 /var/lib/afcyber-siem # Common user ID for containers
chmod -R 770 /var/lib/afcyber-siem

log "INFO" "Generating production .env file..."
ENV_FILE_PATH="${APP_DIR}/.env"
cp "${APP_DIR}/.env.example" "${ENV_FILE_PATH}"

# Generate and replace secrets in .env file
sed -i "s/change_this_to_a_random_string_at_least_32_chars/$(generate_password)/g" "${ENV_FILE_PATH}"
sed -i "s/change_this_to_another_random_string_at_least_32_chars/$(generate_password)/g" "${ENV_FILE_PATH}"
sed -i "s/change_this_to_a_secure_password/$(generate_password)/g" "${ENV_FILE_PATH}"
sed -i "s/change_this_to_a_random_string_at_least_64_chars/$(generate_password 64)/g" "${ENV_FILE_PATH}"
sed -i "s/8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918/$(echo -n "$(generate_password)" | sha256sum | cut -d' ' -f1)/g" "${ENV_FILE_PATH}"
sed -i "s/change_this_to_a_32_character_random_key/$(generate_password)/g" "${ENV_FILE_PATH}"
sed -i "s/change_this_after_initial_setup/$(generate_password)/g" "${ENV_FILE_PATH}"
sed -i "s/minioadmin/$(generate_password 12)/g" "${ENV_FILE_PATH}"
log "INFO" "Production .env file created with generated secrets."

log "INFO" "Pre-pulling all required Docker images..."
cd "${APP_DIR}"
docker-compose pull || error_exit "Failed to pull Docker images"
log "INFO" "All Docker images have been pulled and are included in the VM image."

#-------------------------------------------------------------------------------
# System Performance Tuning
#-------------------------------------------------------------------------------
section_header "5. System Performance Tuning"

log "INFO" "Applying kernel performance settings..."
cat > /etc/sysctl.d/99-afcyber-siem.conf << EOF
# Increase system-wide file descriptor limit
fs.file-max = 2097152
# For Elasticsearch: Increase virtual memory map count
vm.max_map_count = 262144
# For performance: reduce swappiness
vm.swappiness = 10
# For network performance
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 4096
EOF
sysctl --system
log "INFO" "Kernel parameters tuned."

log "INFO" "Setting system limits for open files..."
cat > /etc/security/limits.d/99-afcyber-siem.conf << EOF
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 65536
* hard nproc 65536
EOF
log "INFO" "System limits configured."

#-------------------------------------------------------------------------------
# First-Boot and Auto-Start Configuration
#-------------------------------------------------------------------------------
section_header "6. First-Boot and Auto-Start Configuration"

log "INFO" "Creating first-boot setup script..."
cat > /usr/local/bin/afcyber-siem-first-boot.sh << 'EOF'
#!/bin/bash
LOG_FILE="/var/log/afcyber-siem-first-boot.log"
log() { echo "$(date) - $1" | tee -a "$LOG_FILE"; }

log "Starting AfCyber SIEM first-boot setup..."

# Regenerate SSH host keys
log "Regenerating SSH host keys..."
rm -f /etc/ssh/ssh_host_*
ssh-keygen -A
systemctl restart sshd

# Initialize databases and services if needed
# This is a placeholder for any tasks that need to run once the system has its final identity
log "Running initial database migrations..."
cd /opt/afcyber-siem-saas/backend
# npm run migration:run >> "$LOG_FILE" 2>&1

log "First-boot setup complete."

# Disable this service so it doesn't run again
systemctl disable afcyber-siem-first-boot.service
rm -f /etc/systemd/system/afcyber-siem-first-boot.service
EOF
chmod +x /usr/local/bin/afcyber-siem-first-boot.sh

log "INFO" "Creating first-boot systemd service..."
cat > /etc/systemd/system/afcyber-siem-first-boot.service << EOF
[Unit]
Description=AfCyber SIEM First-Boot Setup
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/afcyber-siem-first-boot.sh
RemainAfterExit=true
StandardOutput=journal+console

[Install]
WantedBy=multi-user.target
EOF
systemctl enable afcyber-siem-first-boot.service

log "INFO" "Creating main application startup service..."
cat > /etc/systemd/system/afcyber-siem.service << EOF
[Unit]
Description=AfCyber SIEM Platform Service
After=docker.service k3s.service afcyber-siem-first-boot.service
Requires=docker.service k3s.service

[Service]
Type=simple
User=root
Group=docker
WorkingDirectory=/opt/afcyber-siem-saas
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
Restart=on-failure
RestartSec=10
TimeoutStartSec=600

[Install]
WantedBy=multi-user.target
EOF
systemctl enable afcyber-siem.service
log "INFO" "Systemd services configured."

#-------------------------------------------------------------------------------
# Logging and Monitoring Setup
#-------------------------------------------------------------------------------
section_header "7. Logging and Monitoring Setup"

log "INFO" "Configuring log rotation..."
cat > /etc/logrotate.d/afcyber-siem << EOF
/opt/afcyber-siem-saas/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}

/var/log/packer-setup.log
/var/log/afcyber-siem-*.log {
    monthly
    rotate 3
    compress
    missingok
    notifempty
}
EOF
log "INFO" "Log rotation configured."

#-------------------------------------------------------------------------------
# Cloud-Init Preparation
#-------------------------------------------------------------------------------
section_header "8. Cloud-Init Preparation"

log "INFO" "Installing and configuring cloud-init..."
dnf -y install cloud-init cloud-utils-growpart
systemctl enable cloud-init

log "INFO" "Configuring cloud-init to run on first boot..."
cat > /etc/cloud/cloud.cfg.d/99-afcyber-siem.cfg << EOF
# AfCyber SIEM Cloud-Init Configuration
datasource_list: [ NoCloud, ConfigDrive, OpenStack, Ec2, Azure, GCP ]
system_info:
  distro: almalinux
  default_user:
    name: afcyber
    gecos: AfCyber Admin
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: [wheel, docker]
    shell: /bin/bash
    lock_passwd: true
# Grow the root partition on first boot
growpart:
  mode: auto
  devices: ['/']
# Run custom scripts on first boot
runcmd:
  - [ systemctl, restart, afcyber-siem.service ]
EOF

log "INFO" "Cleaning cloud-init logs and cache..."
cloud-init clean --logs --seed

log "INFO" "Cloud-init has been configured."
log "INFO" "The VM image will be customizable on first boot (e.g., setting hostname, SSH keys, user data)."

section_header "Main Setup Complete"
log "INFO" "The VM has been provisioned with the AfCyber SIEM platform."
log "INFO" "The final cleanup script will now run to prepare the image for distribution."
