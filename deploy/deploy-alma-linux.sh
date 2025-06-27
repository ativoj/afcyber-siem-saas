#!/bin/bash
#===============================================================================
# AfCyber SIEM - Multi-Tenant SaaS Platform Deployment Script for Alma Linux
#
# This script automates the deployment of the AfCyber SIEM platform on Alma Linux
# with comprehensive security, multi-tenant isolation, and enterprise-grade
# configuration for production environments.
#
# Author: AfCyber Labs
# License: Apache-2.0
# Version: 1.0.0
#===============================================================================

#-------------------------------------------------------------------------------
# Configuration Variables
#-------------------------------------------------------------------------------
SCRIPT_VERSION="1.0.0"
SCRIPT_NAME=$(basename "$0")
LOG_FILE="/var/log/afcyber-siem-deploy.log"
BACKUP_DIR="/var/backups/afcyber-siem"
INSTALL_DIR="/opt/afcyber-siem"
CONFIG_DIR="/etc/afcyber-siem"
DATA_DIR="/var/lib/afcyber-siem"
ENV_FILE="${CONFIG_DIR}/.env"

# System requirements
MIN_CPU_CORES=16
MIN_RAM_GB=32
MIN_DISK_GB=500

# Kubernetes & Docker versions
K3S_VERSION="v1.27.4+k3s1"
DOCKER_VERSION="24.0.5"
DOCKER_COMPOSE_VERSION="2.20.3"

# Default domain configuration
DEFAULT_DOMAIN="siem.example.com"
DEFAULT_EMAIL="admin@example.com"

# Default database passwords (will be auto-generated if not specified)
POSTGRES_PASSWORD=""
REDIS_PASSWORD=""
ELASTIC_PASSWORD=""
CASSANDRA_PASSWORD=""

# Ports to expose
PORTS=(22 80 443 514 1514 1515 9000 9001 8080 3000)

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

#-------------------------------------------------------------------------------
# Helper Functions
#-------------------------------------------------------------------------------

# Log messages to console and log file
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Create log directory if it doesn't exist
    mkdir -p "$(dirname "$LOG_FILE")"
    
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
        "DEBUG")
            if [[ "$DEBUG" == "true" ]]; then
                echo -e "${BLUE}[DEBUG]${NC} $message"
            fi
            ;;
    esac
    
    echo "$timestamp [$level] $message" >> "$LOG_FILE"
}

# Display error and exit
error_exit() {
    log "ERROR" "$1"
    if [ "$2" ]; then
        log "ERROR" "Suggested solution: $2"
    fi
    log "ERROR" "Deployment failed. Check $LOG_FILE for details."
    exit 1
}

# Display section header
section_header() {
    local title=$1
    local line=$(printf '=%.0s' {1..80})
    echo ""
    echo -e "${BLUE}$line${NC}"
    echo -e "${BLUE}$title${NC}"
    echo -e "${BLUE}$line${NC}"
    echo ""
    log "INFO" "Starting section: $title"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Generate a random password
generate_password() {
    local length=${1:-32}
    tr -dc 'A-Za-z0-9!#%&()*+,-./:;<=>?@[\]^_{}~' </dev/urandom | head -c "$length"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root" "Run with sudo or as root user"
    fi
}

# Backup a file before modifying
backup_file() {
    local file=$1
    if [ -f "$file" ]; then
        local backup="${file}.$(date +%Y%m%d%H%M%S).bak"
        cp "$file" "$backup"
        log "INFO" "Backed up $file to $backup"
    fi
}

# Create a rollback point
create_rollback_point() {
    local name=$1
    local timestamp=$(date +"%Y%m%d%H%M%S")
    local rollback_dir="${BACKUP_DIR}/rollback_${name}_${timestamp}"
    
    mkdir -p "$rollback_dir"
    
    # Save important configurations
    if [ -d "$CONFIG_DIR" ]; then
        cp -r "$CONFIG_DIR" "$rollback_dir/"
    fi
    
    # Save environment file
    if [ -f "$ENV_FILE" ]; then
        cp "$ENV_FILE" "$rollback_dir/"
    fi
    
    # Save kubernetes resources
    if command_exists kubectl; then
        kubectl get all -A -o yaml > "$rollback_dir/k8s_resources.yaml"
    fi
    
    log "INFO" "Created rollback point: $rollback_dir"
    echo "$rollback_dir"
}

# Wait for a service to be ready
wait_for_service() {
    local service_name=$1
    local check_command=$2
    local max_attempts=${3:-30}
    local sleep_time=${4:-10}
    
    log "INFO" "Waiting for $service_name to be ready..."
    
    local attempts=0
    until eval "$check_command" || [ $attempts -eq $max_attempts ]; do
        log "DEBUG" "Waiting for $service_name... Attempt $((attempts+1))/$max_attempts"
        sleep $sleep_time
        attempts=$((attempts+1))
    done
    
    if [ $attempts -eq $max_attempts ]; then
        error_exit "$service_name is not ready after $max_attempts attempts" "Check the service logs and status"
    else
        log "INFO" "$service_name is ready"
    fi
}

# Get system memory in GB
get_system_memory_gb() {
    local mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    echo $((mem_kb / 1024 / 1024))
}

# Get number of CPU cores
get_cpu_cores() {
    nproc
}

# Get available disk space in GB for a path
get_disk_space_gb() {
    local path=$1
    df -BG "$path" | awk 'NR==2 {print $4}' | sed 's/G//'
}

# Check if a port is in use
is_port_in_use() {
    local port=$1
    netstat -tuln | grep -q ":$port "
}

# Add a line to a file if it doesn't exist
add_line_to_file() {
    local line=$1
    local file=$2
    grep -qF -- "$line" "$file" || echo "$line" >> "$file"
}

# Replace a line in a file
replace_line_in_file() {
    local search=$1
    local replace=$2
    local file=$3
    sed -i "s|$search|$replace|g" "$file"
}

# Update progress
update_progress() {
    local step=$1
    local total=$2
    local percentage=$((step * 100 / total))
    printf "\r[%-50s] %d%%" "$(printf '#%.0s' $(seq 1 $((percentage / 2))))" "$percentage"
}

#-------------------------------------------------------------------------------
# Validation Functions
#-------------------------------------------------------------------------------

# Validate system requirements
validate_system_requirements() {
    section_header "Validating System Requirements"
    
    log "INFO" "Checking CPU cores..."
    local cpu_cores=$(get_cpu_cores)
    if [ "$cpu_cores" -lt "$MIN_CPU_CORES" ]; then
        log "WARN" "Insufficient CPU cores: $cpu_cores (minimum: $MIN_CPU_CORES)"
        read -p "Continue anyway? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error_exit "Insufficient CPU cores" "Provision a machine with at least $MIN_CPU_CORES cores"
        fi
    else
        log "INFO" "CPU cores: $cpu_cores - OK"
    fi
    
    log "INFO" "Checking memory..."
    local memory_gb=$(get_system_memory_gb)
    if [ "$memory_gb" -lt "$MIN_RAM_GB" ]; then
        log "WARN" "Insufficient memory: ${memory_gb}GB (minimum: ${MIN_RAM_GB}GB)"
        read -p "Continue anyway? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error_exit "Insufficient memory" "Provision a machine with at least ${MIN_RAM_GB}GB of RAM"
        fi
    else
        log "INFO" "Memory: ${memory_gb}GB - OK"
    fi
    
    log "INFO" "Checking disk space..."
    local disk_space_gb=$(get_disk_space_gb "/")
    if [ "$disk_space_gb" -lt "$MIN_DISK_GB" ]; then
        log "WARN" "Insufficient disk space: ${disk_space_gb}GB (minimum: ${MIN_DISK_GB}GB)"
        read -p "Continue anyway? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error_exit "Insufficient disk space" "Provision a machine with at least ${MIN_DISK_GB}GB of disk space"
        fi
    else
        log "INFO" "Disk space: ${disk_space_gb}GB - OK"
    fi
    
    log "INFO" "Checking OS version..."
    if [ -f /etc/almalinux-release ]; then
        local os_version=$(cat /etc/almalinux-release)
        log "INFO" "OS: $os_version - OK"
    else
        error_exit "This script requires Alma Linux" "Install Alma Linux 9 or higher"
    fi
    
    log "INFO" "Checking internet connectivity..."
    if ping -c 1 google.com &> /dev/null; then
        log "INFO" "Internet connectivity - OK"
    else
        error_exit "No internet connectivity" "Check network configuration and ensure internet access is available"
    fi
    
    log "INFO" "System requirements validation completed successfully"
}

# Validate ports
validate_ports() {
    section_header "Validating Port Availability"
    
    local conflict=false
    
    for port in "${PORTS[@]}"; do
        log "INFO" "Checking port $port..."
        if is_port_in_use "$port"; then
            log "WARN" "Port $port is already in use"
            conflict=true
        else
            log "INFO" "Port $port is available - OK"
        fi
    done
    
    if [ "$conflict" = true ]; then
        read -p "Some ports are already in use. Continue anyway? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            error_exit "Port conflicts detected" "Free up the required ports or modify the port configuration"
        fi
    else
        log "INFO" "All required ports are available"
    fi
}

# Validate domain
validate_domain() {
    local domain=$1
    
    if [[ ! "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
        error_exit "Invalid domain name: $domain" "Provide a valid domain name"
    fi
}

# Validate email
validate_email() {
    local email=$1
    
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        error_exit "Invalid email address: $email" "Provide a valid email address"
    fi
}

#-------------------------------------------------------------------------------
# Installation Functions
#-------------------------------------------------------------------------------

# Update system packages
update_system() {
    section_header "Updating System Packages"
    
    log "INFO" "Updating package lists..."
    dnf update -y || error_exit "Failed to update package lists"
    
    log "INFO" "Installing essential packages..."
    dnf install -y epel-release || error_exit "Failed to install EPEL repository"
    dnf install -y curl wget git vim htop net-tools unzip jq yum-utils \
        policycoreutils-python-utils setools-console nmap-ncat openssl \
        logrotation chrony firewalld || error_exit "Failed to install essential packages"
    
    log "INFO" "System packages updated successfully"
}

# Configure system settings
configure_system_settings() {
    section_header "Configuring System Settings"
    
    log "INFO" "Configuring system limits..."
    
    # Backup sysctl.conf
    backup_file "/etc/sysctl.conf"
    
    # Configure kernel parameters for container workloads
    cat > /etc/sysctl.d/99-afcyber-siem.conf << EOF
# Maximum number of open file descriptors
fs.file-max = 2097152

# Maximum number of processes
kernel.pid_max = 4194304

# Increase system IP port limits
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1

# VM memory settings
vm.max_map_count = 262144
vm.swappiness = 10
vm.dirty_ratio = 40
vm.dirty_background_ratio = 10
vm.overcommit_memory = 1

# Network settings
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
EOF
    
    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-afcyber-siem.conf || log "WARN" "Failed to apply some sysctl settings"
    
    # Configure user limits
    cat > /etc/security/limits.d/99-afcyber-siem.conf << EOF
# Increase limits for all users
*               soft    nofile          1048576
*               hard    nofile          1048576
*               soft    nproc           262144
*               hard    nproc           262144
*               soft    memlock         unlimited
*               hard    memlock         unlimited

# Specific limits for elasticsearch
elasticsearch   soft    nofile          1048576
elasticsearch   hard    nofile          1048576

# Specific limits for kafka
kafka           soft    nofile          1048576
kafka           hard    nofile          1048576
EOF
    
    log "INFO" "Configuring time synchronization..."
    systemctl enable --now chronyd
    chronyc makestep
    
    log "INFO" "System settings configured successfully"
}

# Install Docker and Docker Compose
install_docker() {
    section_header "Installing Docker and Docker Compose"
    
    # Check if Docker is already installed
    if command_exists docker && docker --version | grep -q "$DOCKER_VERSION"; then
        log "INFO" "Docker $DOCKER_VERSION is already installed"
    else
        log "INFO" "Installing Docker..."
        
        # Remove old versions
        dnf remove -y docker docker-client docker-client-latest docker-common \
            docker-latest docker-latest-logrotate docker-logrotate docker-engine podman runc || true
        
        # Set up the repository
        dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo || \
            error_exit "Failed to add Docker repository"
        
        # Install Docker Engine
        dnf install -y docker-ce-$DOCKER_VERSION docker-ce-cli-$DOCKER_VERSION containerd.io || \
            error_exit "Failed to install Docker"
        
        # Start and enable Docker
        systemctl enable --now docker || error_exit "Failed to enable Docker service"
        
        log "INFO" "Docker $DOCKER_VERSION installed successfully"
    fi
    
    # Check if Docker Compose is already installed
    if command_exists docker-compose && docker-compose --version | grep -q "$DOCKER_COMPOSE_VERSION"; then
        log "INFO" "Docker Compose $DOCKER_COMPOSE_VERSION is already installed"
    else
        log "INFO" "Installing Docker Compose..."
        
        # Download Docker Compose binary
        curl -L "https://github.com/docker/compose/releases/download/v$DOCKER_COMPOSE_VERSION/docker-compose-$(uname -s)-$(uname -m)" \
            -o /usr/local/bin/docker-compose || error_exit "Failed to download Docker Compose"
        
        # Apply executable permissions
        chmod +x /usr/local/bin/docker-compose || error_exit "Failed to set permissions on Docker Compose"
        
        # Create symbolic link
        ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose || true
        
        log "INFO" "Docker Compose $DOCKER_COMPOSE_VERSION installed successfully"
    fi
    
    # Create docker group and add current user
    groupadd -f docker
    usermod -aG docker "$SUDO_USER" || true
    
    log "INFO" "Docker installation completed successfully"
}

# Install Kubernetes (K3s)
install_kubernetes() {
    section_header "Installing Kubernetes (K3s)"
    
    # Check if K3s is already installed
    if command_exists kubectl && kubectl version | grep -q "$K3S_VERSION"; then
        log "INFO" "K3s $K3S_VERSION is already installed"
    else
        log "INFO" "Installing K3s..."
        
        # Download K3s installation script
        curl -sfL https://get.k3s.io > /tmp/k3s-install.sh || \
            error_exit "Failed to download K3s installation script"
        
        # Make script executable
        chmod +x /tmp/k3s-install.sh
        
        # Install K3s without Traefik (we'll use our own ingress)
        INSTALL_K3S_VERSION="$K3S_VERSION" INSTALL_K3S_EXEC="--disable traefik" \
            /tmp/k3s-install.sh || error_exit "Failed to install K3s"
        
        # Wait for K3s to be ready
        wait_for_service "K3s" "kubectl get nodes" 30 5
        
        # Create symbolic link for kubectl
        ln -sf /usr/local/bin/kubectl /usr/bin/kubectl || true
        
        log "INFO" "K3s $K3S_VERSION installed successfully"
    fi
    
    # Create .kube directory for the user
    if [ -n "$SUDO_USER" ]; then
        mkdir -p /home/$SUDO_USER/.kube
        cp /etc/rancher/k3s/k3s.yaml /home/$SUDO_USER/.kube/config
        chown -R $SUDO_USER:$SUDO_USER /home/$SUDO_USER/.kube
        chmod 600 /home/$SUDO_USER/.kube/config
    fi
    
    # Set KUBECONFIG environment variable
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
    
    # Install Helm
    if ! command_exists helm; then
        log "INFO" "Installing Helm..."
        curl -fsSL -o /tmp/get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 || \
            error_exit "Failed to download Helm installation script"
        chmod +x /tmp/get_helm.sh
        /tmp/get_helm.sh || error_exit "Failed to install Helm"
        log "INFO" "Helm installed successfully"
    else
        log "INFO" "Helm is already installed"
    fi
    
    # Add required Helm repositories
    log "INFO" "Adding Helm repositories..."
    helm repo add jetstack https://charts.jetstack.io || log "WARN" "Failed to add Jetstack Helm repository"
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts || log "WARN" "Failed to add Prometheus Helm repository"
    helm repo add grafana https://grafana.github.io/helm-charts || log "WARN" "Failed to add Grafana Helm repository"
    helm repo update
    
    log "INFO" "Kubernetes installation completed successfully"
}

# Configure SSL certificates
configure_ssl() {
    section_header "Configuring SSL Certificates"
    
    local domain="$1"
    local email="$2"
    
    # Create directory for certificates
    mkdir -p "${CONFIG_DIR}/certs"
    
    # Check if we should use Let's Encrypt or self-signed certificates
    if [ "$USE_LETSENCRYPT" = "true" ]; then
        log "INFO" "Setting up Let's Encrypt certificates..."
        
        # Install certbot
        dnf install -y certbot || error_exit "Failed to install certbot"
        
        # Request certificate
        certbot certonly --standalone --agree-tos --non-interactive \
            --preferred-challenges http --email "$email" -d "$domain" \
            -d "*.${domain}" || error_exit "Failed to obtain Let's Encrypt certificate"
        
        # Copy certificates to config directory
        cp /etc/letsencrypt/live/$domain/fullchain.pem "${CONFIG_DIR}/certs/tls.crt"
        cp /etc/letsencrypt/live/$domain/privkey.pem "${CONFIG_DIR}/certs/tls.key"
        
        # Set up auto-renewal
        echo "0 0,12 * * * root certbot renew --quiet --post-hook 'cp /etc/letsencrypt/live/$domain/fullchain.pem ${CONFIG_DIR}/certs/tls.crt && cp /etc/letsencrypt/live/$domain/privkey.pem ${CONFIG_DIR}/certs/tls.key && systemctl reload nginx'" > /etc/cron.d/certbot-renew
        
        log "INFO" "Let's Encrypt certificates configured successfully"
    else
        log "INFO" "Generating self-signed certificates..."
        
        # Generate self-signed certificate
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "${CONFIG_DIR}/certs/tls.key" \
            -out "${CONFIG_DIR}/certs/tls.crt" \
            -subj "/CN=$domain/O=AfCyber SIEM/C=US" \
            -addext "subjectAltName = DNS:$domain, DNS:*.$domain" || \
            error_exit "Failed to generate self-signed certificate"
        
        log "INFO" "Self-signed certificates generated successfully"
    fi
    
    # Set proper permissions
    chmod 600 "${CONFIG_DIR}/certs/tls.key"
    chmod 644 "${CONFIG_DIR}/certs/tls.crt"
    
    log "INFO" "SSL certificates configured successfully"
}

# Configure firewall
configure_firewall() {
    section_header "Configuring Firewall"
    
    log "INFO" "Setting up firewalld..."
    
    # Enable and start firewalld
    systemctl enable --now firewalld || error_exit "Failed to enable firewalld"
    
    # Allow required ports
    for port in "${PORTS[@]}"; do
        log "INFO" "Opening port $port..."
        firewall-cmd --permanent --add-port=$port/tcp || log "WARN" "Failed to open port $port/tcp"
    done
    
    # Allow UDP ports for syslog and DNS
    firewall-cmd --permanent --add-port=514/udp || log "WARN" "Failed to open port 514/udp"
    firewall-cmd --permanent --add-port=53/udp || log "WARN" "Failed to open port 53/udp"
    
    # Reload firewall
    firewall-cmd --reload || error_exit "Failed to reload firewall configuration"
    
    log "INFO" "Firewall configured successfully"
}

# Configure SELinux
configure_selinux() {
    section_header "Configuring SELinux"
    
    log "INFO" "Checking SELinux status..."
    
    # Check if SELinux is enabled
    if sestatus | grep -q "SELinux status: *enabled"; then
        log "INFO" "SELinux is enabled, configuring policies..."
        
        # Install SELinux utilities if not already installed
        dnf install -y policycoreutils-python-utils setools-console || \
            error_exit "Failed to install SELinux utilities"
        
        # Create directory for custom policies
        mkdir -p "${CONFIG_DIR}/selinux"
        
        # Create custom policy for AfCyber SIEM
        cat > "${CONFIG_DIR}/selinux/afcyber_siem.te" << EOF
module afcyber_siem 1.0;

require {
    type container_t;
    type container_file_t;
    type http_port_t;
    type syslogd_port_t;
    type transproxy_port_t;
    type unreserved_port_t;
    class tcp_socket name_bind;
    class file { getattr open read };
    class dir { search };
}

#============= container_t ==============
allow container_t http_port_t:tcp_socket name_bind;
allow container_t syslogd_port_t:tcp_socket name_bind;
allow container_t transproxy_port_t:tcp_socket name_bind;
allow container_t unreserved_port_t:tcp_socket name_bind;
EOF
        
        # Compile and install the policy
        cd "${CONFIG_DIR}/selinux"
        checkmodule -M -m -o afcyber_siem.mod afcyber_siem.te || \
            error_exit "Failed to compile SELinux policy module"
        semodule_package -o afcyber_siem.pp -m afcyber_siem.mod || \
            error_exit "Failed to package SELinux policy module"
        semodule -i afcyber_siem.pp || \
            error_exit "Failed to install SELinux policy module"
        
        # Set correct contexts for directories
        semanage fcontext -a -t container_file_t "${DATA_DIR}(/.*)?" || \
            log "WARN" "Failed to set SELinux context for data directory"
        semanage fcontext -a -t container_file_t "${CONFIG_DIR}(/.*)?" || \
            log "WARN" "Failed to set SELinux context for config directory"
        restorecon -Rv "${DATA_DIR}" "${CONFIG_DIR}" || \
            log "WARN" "Failed to restore SELinux contexts"
        
        # Set port contexts
        for port in "${PORTS[@]}"; do
            semanage port -a -t http_port_t -p tcp $port || \
                semanage port -m -t http_port_t -p tcp $port || \
                log "WARN" "Failed to set SELinux port context for port $port"
        done
        
        log "INFO" "SELinux policies configured successfully"
    else
        log "WARN" "SELinux is disabled. For production environments, it's recommended to enable SELinux."
        read -p "Would you like to enable SELinux in permissive mode? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log "INFO" "Enabling SELinux in permissive mode..."
            sed -i 's/SELINUX=disabled/SELINUX=permissive/' /etc/selinux/config
            log "INFO" "SELinux will be enabled in permissive mode after reboot"
        fi
    fi
    
    log "INFO" "SELinux configuration completed"
}

# Initialize databases
initialize_databases() {
    section_header "Initializing Databases"
    
    # Create directories for database data
    mkdir -p "${DATA_DIR}/postgres"
    mkdir -p "${DATA_DIR}/elasticsearch"
    mkdir -p "${DATA_DIR}/mongodb"
    mkdir -p "${DATA_DIR}/cassandra"
    mkdir -p "${DATA_DIR}/redis"
    
    # Set proper permissions
    chmod -R 750 "${DATA_DIR}"
    
    # Generate database passwords if not already set
    if [ -z "$POSTGRES_PASSWORD" ]; then
        POSTGRES_PASSWORD=$(generate_password 32)
        log "INFO" "Generated PostgreSQL password"
    fi
    
    if [ -z "$REDIS_PASSWORD" ]; then
        REDIS_PASSWORD=$(generate_password 32)
        log "INFO" "Generated Redis password"
    fi
    
    if [ -z "$ELASTIC_PASSWORD" ]; then
        ELASTIC_PASSWORD=$(generate_password 32)
        log "INFO" "Generated Elasticsearch password"
    fi
    
    if [ -z "$CASSANDRA_PASSWORD" ]; then
        CASSANDRA_PASSWORD=$(generate_password 32)
        log "INFO" "Generated Cassandra password"
    fi
    
    # Create Kubernetes secrets for database credentials
    kubectl create namespace afcyber-siem || true
    
    kubectl create secret generic db-credentials -n afcyber-siem \
        --from-literal=postgres-password="$POSTGRES_PASSWORD" \
        --from-literal=redis-password="$REDIS_PASSWORD" \
        --from-literal=elastic-password="$ELASTIC_PASSWORD" \
        --from-literal=cassandra-password="$CASSANDRA_PASSWORD" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    log "INFO" "Database initialization completed successfully"
}

# Deploy core services
deploy_core_services() {
    section_header "Deploying Core Services"
    
    # Create namespaces
    kubectl create namespace afcyber-siem || true
    kubectl create namespace monitoring || true
    kubectl create namespace ingress-nginx || true
    
    # Deploy cert-manager for certificate management
    log "INFO" "Deploying cert-manager..."
    helm upgrade --install cert-manager jetstack/cert-manager \
        --namespace cert-manager --create-namespace \
        --set installCRDs=true \
        --version v1.12.0 || error_exit "Failed to deploy cert-manager"
    
    # Wait for cert-manager to be ready
    wait_for_service "cert-manager" "kubectl get pods -n cert-manager | grep -q '1/1'" 30 5
    
    # Deploy NGINX Ingress Controller
    log "INFO" "Deploying NGINX Ingress Controller..."
    cat > /tmp/nginx-ingress-values.yaml << EOF
controller:
  service:
    type: LoadBalancer
  config:
    use-forwarded-headers: "true"
    proxy-body-size: "100m"
    client-max-body-size: "100m"
    proxy-connect-timeout: "300"
    proxy-read-timeout: "300"
    proxy-send-timeout: "300"
    enable-modsecurity: "true"
    enable-owasp-modsecurity-crs: "true"
    server-tokens: "false"
    ssl-protocols: "TLSv1.2 TLSv1.3"
    ssl-ciphers: "HIGH:!aNULL:!MD5"
  metrics:
    enabled: true
    serviceMonitor:
      enabled: true
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 512Mi
EOF
    
    helm upgrade --install ingress-nginx ingress-nginx \
        --repo https://kubernetes.github.io/ingress-nginx \
        --namespace ingress-nginx \
        --values /tmp/nginx-ingress-values.yaml || error_exit "Failed to deploy NGINX Ingress Controller"
    
    # Wait for NGINX Ingress Controller to be ready
    wait_for_service "NGINX Ingress Controller" "kubectl get pods -n ingress-nginx | grep -q '1/1'" 30 5
    
    # Deploy Prometheus and Grafana for monitoring
    log "INFO" "Deploying Prometheus and Grafana..."
    cat > /tmp/prometheus-values.yaml << EOF
prometheus:
  prometheusSpec:
    retention: 15d
    resources:
      requests:
        cpu: 200m
        memory: 512Mi
      limits:
        cpu: 1000m
        memory: 2Gi
    storageSpec:
      volumeClaimTemplate:
        spec:
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 50Gi
alertmanager:
  alertmanagerSpec:
    storage:
      volumeClaimTemplate:
        spec:
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 10Gi
grafana:
  adminPassword: "${GRAFANA_ADMIN_PASSWORD:-admin}"
  persistence:
    enabled: true
    size: 10Gi
  dashboardProviders:
    dashboardproviders.yaml:
      apiVersion: 1
      providers:
      - name: 'afcyber-siem'
        orgId: 1
        folder: 'AfCyber SIEM'
        type: file
        disableDeletion: false
        editable: true
        options:
          path: /var/lib/grafana/dashboards/afcyber-siem
  dashboards:
    afcyber-siem:
      security-overview:
        file: dashboards/security-overview.json
      wazuh-overview:
        file: dashboards/wazuh-overview.json
      graylog-overview:
        file: dashboards/graylog-overview.json
      thehive-overview:
        file: dashboards/thehive-overview.json
      opencti-overview:
        file: dashboards/opencti-overview.json
      misp-overview:
        file: dashboards/misp-overview.json
      velociraptor-overview:
        file: dashboards/velociraptor-overview.json
      ml-anomaly-detection:
        file: dashboards/ml-anomaly-detection.json
EOF
    
    helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
        --namespace monitoring \
        --values /tmp/prometheus-values.yaml || error_exit "Failed to deploy Prometheus and Grafana"
    
    # Wait for Prometheus and Grafana to be ready
    wait_for_service "Prometheus" "kubectl get pods -n monitoring -l app=prometheus | grep -q '2/2'" 30 10
    wait_for_service "Grafana" "kubectl get pods -n monitoring -l app.kubernetes.io/name=grafana | grep -q '1/1'" 30 5
    
    log "INFO" "Core services deployed successfully"
}

# Deploy AfCyber SIEM platform
deploy_afcyber_siem() {
    section_header "Deploying AfCyber SIEM Platform"
    
    # Create directories for AfCyber SIEM
    mkdir -p "${CONFIG_DIR}/kubernetes"
    mkdir -p "${CONFIG_DIR}/dashboards"
    
    # Generate values file for Helm chart
    cat > "${CONFIG_DIR}/kubernetes/values.yaml" << EOF
# AfCyber SIEM Platform - Helm Values
global:
  domain: "${DOMAIN}"
  storageClass: "local-path"
  multiTenant: true
  
  # Security settings
  security:
    adminEmail: "${ADMIN_EMAIL}"
    adminPassword: "${ADMIN_PASSWORD:-$(generate_password 16)}"
    jwtSecret: "${JWT_SECRET:-$(generate_password 32)}"
    
  # Database credentials
  postgres:
    username: "postgres"
    password: "${POSTGRES_PASSWORD}"
    database: "afcyber_siem"
  
  redis:
    password: "${REDIS_PASSWORD}"
  
  elasticsearch:
    username: "elastic"
    password: "${ELASTIC_PASSWORD}"
  
  cassandra:
    username: "cassandra"
    password: "${CASSANDRA_PASSWORD}"
  
  # S3 storage for backups
  s3:
    enabled: ${S3_BACKUP_ENABLED:-false}
    bucket: "${S3_BUCKET:-afcyber-siem-backups}"
    region: "${S3_REGION:-us-east-1}"
    accessKey: "${S3_ACCESS_KEY:-}"
    secretKey: "${S3_SECRET_KEY:-}"
  
  # SMTP settings for notifications
  smtp:
    enabled: ${SMTP_ENABLED:-false}
    host: "${SMTP_HOST:-smtp.example.com}"
    port: ${SMTP_PORT:-587}
    username: "${SMTP_USERNAME:-}"
    password: "${SMTP_PASSWORD:-}"
    from: "${SMTP_FROM:-siem-alerts@example.com}"
    
# Component-specific settings
wazuh:
  enabled: true
  manager:
    replicaCount: 1
    resources:
      requests:
        cpu: 1000m
        memory: 2Gi
      limits:
        cpu: 2000m
        memory: 4Gi
    persistence:
      size: 100Gi
  indexer:
    replicaCount: 1
    resources:
      requests:
        cpu: 1000m
        memory: 4Gi
      limits:
        cpu: 2000m
        memory: 8Gi
    persistence:
      size: 200Gi
  dashboard:
    replicaCount: 1
    resources:
      requests:
        cpu: 500m
        memory: 1Gi
      limits:
        cpu: 1000m
        memory: 2Gi

graylog:
  enabled: true
  replicaCount: 1
  resources:
    requests:
      cpu: 1000m
      memory: 2Gi
    limits:
      cpu: 2000m
      memory: 4Gi
  persistence:
    size: 100Gi
  mongodb:
    resources:
      requests:
        cpu: 500m
        memory: 1Gi
      limits:
        cpu: 1000m
        memory: 2Gi
    persistence:
      size: 50Gi

thehive:
  enabled: true
  replicaCount: 1
  resources:
    requests:
      cpu: 1000m
      memory: 2Gi
    limits:
      cpu: 2000m
      memory: 4Gi
  persistence:
    size: 100Gi
  cortex:
    enabled: true
    resources:
      requests:
        cpu: 500m
        memory: 1Gi
      limits:
        cpu: 1000m
        memory: 2Gi

opencti:
  enabled: true
  replicaCount: 1
  resources:
    requests:
      cpu: 1000m
      memory: 4Gi
    limits:
      cpu: 2000m
      memory: 8Gi
  persistence:
    size: 100Gi
  workers:
    replicaCount: 2
    resources:
      requests:
        cpu: 500m
        memory: 1Gi
      limits:
        cpu: 1000m
        memory: 2Gi

misp:
  enabled: true
  replicaCount: 1
  resources:
    requests:
      cpu: 1000m
      memory: 2Gi
    limits:
      cpu: 2000m
      memory: 4Gi
  persistence:
    size: 50Gi
  mysql:
    resources:
      requests:
        cpu: 500m
        memory: 1Gi
      limits:
        cpu: 1000m
        memory: 2Gi
    persistence:
      size: 50Gi

velociraptor:
  enabled: true
  replicaCount: 1
  resources:
    requests:
      cpu: 1000m
      memory: 2Gi
    limits:
      cpu: 2000m
      memory: 4Gi
  persistence:
    size: 100Gi

ml:
  enabled: true
  anomalyDetection:
    replicaCount: 1
    resources:
      requests:
        cpu: 1000m
        memory: 2Gi
      limits:
        cpu: 2000m
        memory: 4Gi
  threatScoring:
    replicaCount: 1
    resources:
      requests:
        cpu: 1000m
        memory: 2Gi
      limits:
        cpu: 2000m
        memory: 4Gi
  alertClustering:
    replicaCount: 1
    resources:
      requests:
        cpu: 1000m
        memory: 2Gi
      limits:
        cpu: 2000m
        memory: 4Gi
  nlpEnrichment:
    replicaCount: 1
    resources:
      requests:
        cpu: 1000m
        memory: 4Gi
      limits:
        cpu: 2000m
        memory: 8Gi

kafka:
  enabled: true
  replicaCount: 1
  resources:
    requests:
      cpu: 1000m
      memory: 2Gi
    limits:
      cpu: 2000m
      memory: 4Gi
  persistence:
    size: 100Gi
  zookeeper:
    replicaCount: 1
    resources:
      requests:
        cpu: 500m
        memory: 1Gi
      limits:
        cpu: 1000m
        memory: 2Gi
    persistence:
      size: 20Gi

saas:
  enabled: true
  api:
    replicaCount: 2
    resources:
      requests:
        cpu: 500m
        memory: 1Gi
      limits:
        cpu: 1000m
        memory: 2Gi
  frontend:
    replicaCount: 2
    resources:
      requests:
        cpu: 500m
        memory: 1Gi
      limits:
        cpu: 1000m
        memory: 2Gi
  tenantManager:
    replicaCount: 1
    resources:
      requests:
        cpu: 500m
        memory: 1Gi
      limits:
        cpu: 1000m
        memory: 2Gi
EOF
    
    # Create Helm chart repository
    log "INFO" "Adding AfCyber SIEM Helm repository..."
    helm repo add afcyber https://charts.afcyber.io || \
        error_exit "Failed to add AfCyber SIEM Helm repository"
    helm repo update
    
    # Deploy AfCyber SIEM platform
    log "INFO" "Deploying AfCyber SIEM platform..."
    helm upgrade --install afcyber-siem afcyber/siem \
        --namespace afcyber-siem \
        --values "${CONFIG_DIR}/kubernetes/values.yaml" \
        --timeout 15m || error_exit "Failed to deploy AfCyber SIEM platform"
    
    # Wait for key services to be ready
    log "INFO" "Waiting for AfCyber SIEM services to be ready..."
    wait_for_service "SaaS API" "kubectl get pods -n afcyber-siem -l app=saas-api | grep -q '1/1'" 60 10
    wait_for_service "Wazuh Manager" "kubectl get pods -n afcyber-siem -l app=wazuh-manager | grep -q '1/1'" 60 10
    wait_for_service "Graylog" "kubectl get pods -n afcyber-siem -l app=graylog | grep -q '1/1'" 60 10
    
    log "INFO" "AfCyber SIEM platform deployed successfully"
}

# Configure backup and recovery
configure_backup() {
    section_header "Configuring Backup and Recovery"
    
    # Create backup directories
    mkdir -p "${BACKUP_DIR}/daily"
    mkdir -p "${BACKUP_DIR}/weekly"
    mkdir -p "${BACKUP_DIR}/monthly"
    
    # Create backup script
    cat > "${INSTALL_DIR}/bin/backup.sh" << 'EOF'
#!/bin/bash
# AfCyber SIEM Platform - Backup Script

BACKUP_DIR="/var/backups/afcyber-siem"
CONFIG_DIR="/etc/afcyber-siem"
DATA_DIR="/var/lib/afcyber-siem"
LOG_FILE="/var/log/afcyber-siem-backup.log"
DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_TYPE=${1:-daily}
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_TYPE}/afcyber-siem-${DATE}"
RETENTION_DAYS=7

# Log function
log() {
    echo "$(date +"%Y-%m-%d %H:%M:%S") - $1" | tee -a "$LOG_FILE"
}

# Create backup directory
mkdir -p "$BACKUP_PATH"

log "Starting $BACKUP_TYPE backup to $BACKUP_PATH"

# Backup Kubernetes resources
log "Backing up Kubernetes resources..."
mkdir -p "$BACKUP_PATH/kubernetes"
kubectl get all -A -o yaml > "$BACKUP_PATH/kubernetes/all-resources.yaml"
kubectl get pv,pvc -A -o yaml > "$BACKUP_PATH/kubernetes/storage.yaml"
kubectl get secrets -A -o yaml > "$BACKUP_PATH/kubernetes/secrets.yaml"
kubectl get configmaps -A -o yaml > "$BACKUP_PATH/kubernetes/configmaps.yaml"

# Backup configuration
log "Backing up configuration files..."
cp -r "$CONFIG_DIR" "$BACKUP_PATH/"

# Backup environment file
if [ -f "$CONFIG_DIR/.env" ]; then
    cp "$CONFIG_DIR/.env" "$BACKUP_PATH/"
fi

# Backup database data using kubectl exec
log "Backing up PostgreSQL database..."
POSTGRES_POD=$(kubectl get pods -n afcyber-siem -l app=postgres -o jsonpath="{.items[0].metadata.name}")
if [ -n "$POSTGRES_POD" ]; then
    kubectl exec -n afcyber-siem "$POSTGRES_POD" -- pg_dump -U postgres afcyber_siem > "$BACKUP_PATH/postgres-dump.sql"
fi

# Create archive
log "Creating backup archive..."
tar -czf "$BACKUP_PATH.tar.gz" -C "$BACKUP_PATH/.." "$(basename "$BACKUP_PATH")"
rm -rf "$BACKUP_PATH"

# Upload to S3 if configured
if [ -n "$S3_BUCKET" ]; then
    log "Uploading backup to S3..."
    aws s3 cp "$BACKUP_PATH.tar.gz" "s3://$S3_BUCKET/${BACKUP_TYPE}/" || log "Failed to upload backup to S3"
fi

# Clean up old backups
log "Cleaning up old backups..."
find "${BACKUP_DIR}/${BACKUP_TYPE}" -name "*.tar.gz" -type f -mtime +$RETENTION_DAYS -delete

log "Backup completed successfully"
EOF
    
    chmod +x "${INSTALL_DIR}/bin/backup.sh"
    
    # Create cron jobs for backups
    cat > /etc/cron.d/afcyber-siem-backup << EOF
# AfCyber SIEM Platform - Backup Schedule
0 1 * * * root ${INSTALL_DIR}/bin/backup.sh daily > /dev/null 2>&1
0 2 * * 0 root ${INSTALL_DIR}/bin/backup.sh weekly > /dev/null 2>&1
0 3 1 * * root ${INSTALL_DIR}/bin/backup.sh monthly > /dev/null 2>&1
EOF
    
    # Create restore script
    cat > "${INSTALL_DIR}/bin/restore.sh" << 'EOF'
#!/bin/bash
# AfCyber SIEM Platform - Restore Script

CONFIG_DIR="/etc/afcyber-siem"
LOG_FILE="/var/log/afcyber-siem-restore.log"
BACKUP_FILE="$1"

# Log function
log() {
    echo "$(date +"%Y-%m-%d %H:%M:%S") - $1" | tee -a "$LOG_FILE"
}

# Check if backup file is provided
if [ -z "$BACKUP_FILE" ]; then
    log "Error: No backup file specified"
    echo "Usage: $0 <backup-file.tar.gz>"
    exit 1
fi

# Check if backup file exists
if [ ! -f "$BACKUP_FILE" ]; then
    log "Error: Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Create temporary directory
TEMP_DIR=$(mktemp -d)
log "Extracting backup to $TEMP_DIR"

# Extract backup
tar -xzf "$BACKUP_FILE" -C "$TEMP_DIR" || {
    log "Error: Failed to extract backup"
    rm -rf "$TEMP_DIR"
    exit 1
}

# Find the backup directory (should be only one directory)
BACKUP_DIR=$(find "$TEMP_DIR" -type d -name "afcyber-siem-*" | head -1)
if [ -z "$BACKUP_DIR" ]; then
    log "Error: Could not find backup directory in archive"
    rm -rf "$TEMP_DIR"
    exit 1
fi

# Restore configuration
log "Restoring configuration files..."
cp -r "$BACKUP_DIR/etc-afcyber-siem/"* "$CONFIG_DIR/" || log "Warning: Failed to restore some configuration files"

# Restore environment file
if [ -f "$BACKUP_DIR/.env" ]; then
    cp "$BACKUP_DIR/.env" "$CONFIG_DIR/.env" || log "Warning: Failed to restore environment file"
fi

# Restore Kubernetes resources
log "Restoring Kubernetes resources..."
if [ -f "$BACKUP_DIR/kubernetes/configmaps.yaml" ]; then
    kubectl apply -f "$BACKUP_DIR/kubernetes/configmaps.yaml" || log "Warning: Failed to restore ConfigMaps"
fi

if [ -f "$BACKUP_DIR/kubernetes/secrets.yaml" ]; then
    kubectl apply -f "$BACKUP_DIR/kubernetes/secrets.yaml" || log "Warning: Failed to restore Secrets"
fi

# Restore PostgreSQL database
log "Restoring PostgreSQL database..."
if [ -f "$BACKUP_DIR/postgres-dump.sql" ]; then
    POSTGRES_POD=$(kubectl get pods -n afcyber-siem -l app=postgres -o jsonpath="{.items[0].metadata.name}")
    if [ -n "$POSTGRES_POD" ]; then
        cat "$BACKUP_DIR/postgres-dump.sql" | kubectl exec -i -n afcyber-siem "$POSTGRES_POD" -- psql -U postgres afcyber_siem || log "Warning: Failed to restore PostgreSQL database"
    else
        log "Warning: PostgreSQL pod not found"
    fi
fi

# Clean up
log "Cleaning up temporary files..."
rm -rf "$TEMP_DIR"

log "Restore completed successfully"
log "You may need to restart some services: kubectl rollout restart deployment -n afcyber-siem"
EOF
    
    chmod +x "${INSTALL_DIR}/bin/restore.sh"
    
    log "INFO" "Backup and recovery configured successfully"
}

# Configure log rotation
configure_log_rotation() {
    section_header "Configuring Log Rotation"
    
    # Create log rotation configuration
    cat > /etc/logrotate.d/afcyber-siem << EOF
/var/log/afcyber-siem*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        systemctl reload rsyslog >/dev/null 2>&1 || true
    endscript
}
EOF
    
    log "INFO" "Log rotation configured successfully"
}

# Configure system performance
configure_performance() {
    section_header "Configuring System Performance"
    
    # Create performance tuning script
    cat > "${INSTALL_DIR}/bin/tune-performance.sh" << 'EOF'
#!/bin/bash
# AfCyber SIEM Platform - Performance Tuning Script

LOG_FILE="/var/log/afcyber-siem-performance.log"

# Log function
log() {
    echo "$(date +"%Y-%m-%d %H:%M:%S") - $1" | tee -a "$LOG_FILE"
}

log "Starting performance tuning"

# Get system memory in GB
MEM_GB=$(grep MemTotal /proc/meminfo | awk '{print $2/1024/1024}' | cut -d. -f1)
CPU_CORES=$(nproc)

log "System has $MEM_GB GB RAM and $CPU_CORES CPU cores"

# Tune kernel parameters based on available resources
if [ "$MEM_GB" -ge 64 ]; then
    # High memory system
    log "Applying high-memory system tuning"
    sysctl -w vm.swappiness=10
    sysctl -w vm.dirty_ratio=40
    sysctl -w vm.dirty_background_ratio=10
    sysctl -w vm.max_map_count=1048576
elif [ "$MEM_GB" -ge 32 ]; then
    # Medium memory system
    log "Applying medium-memory system tuning"
    sysctl -w vm.swappiness=30
    sysctl -w vm.dirty_ratio=30
    sysctl -w vm.dirty_background_ratio=5
    sysctl -w vm.max_map_count=524288
else
    # Low memory system
    log "Applying low-memory system tuning"
    sysctl -w vm.swappiness=60
    sysctl -w vm.dirty_ratio=20
    sysctl -w vm.dirty_background_ratio=3
    sysctl -w vm.max_map_count=262144
fi

# Tune network parameters
sysctl -w net.core.somaxconn=65535
sysctl -w net.core.netdev_max_backlog=65536
sysctl -w net.ipv4.tcp_max_syn_backlog=65536
sysctl -w net.ipv4.tcp_fin_timeout=30
sysctl -w net.ipv4.tcp_keepalive_time=300
sysctl -w net.ipv4.tcp_max_tw_buckets=2000000
sysctl -w net.ipv4.tcp_tw_reuse=1

# Apply I/O scheduler optimizations for SSDs
for DEVICE in $(lsblk -d -o name | grep -v NAME | grep -v loop); do
    if [ -f "/sys/block/$DEVICE/queue/rotational" ] && [ "$(cat /sys/block/$DEVICE/queue/rotational)" -eq 0 ]; then
        log "Applying SSD optimizations for /dev/$DEVICE"
        echo deadline > /sys/block/$DEVICE/queue/scheduler
        echo 0 > /sys/block/$DEVICE/queue/add_random
        echo 256 > /sys/block/$DEVICE/queue/nr_requests
    fi
done

# Tune Docker daemon
if [ -f /etc/docker/daemon.json ]; then
    cp /etc/docker/daemon.json /etc/docker/daemon.json.bak
fi

cat > /etc/docker/daemon.json << EOL
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "3"
  },
  "storage-driver": "overlay2",
  "storage-opts": [
    "overlay2.override_kernel_check=true"
  ],
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 1048576,
      "Soft": 1048576
    }
  },
  "live-restore": true,
  "default-shm-size": "64M",
  "max-concurrent-downloads": 10,
  "max-concurrent-uploads": 10
}
EOL

# Restart Docker to apply changes
systemctl restart docker

# Tune K3s resources
if [ -f /etc/systemd/system/k3s.service ]; then
    mkdir -p /etc/systemd/system/k3s.service.d/
    cat > /etc/systemd/system/k3s.service.d/resources.conf << EOL
[Service]
CPUAccounting=true
MemoryAccounting=true
EOL
    systemctl daemon-reload
    systemctl restart k3s
fi

log "Performance tuning completed"
EOF
    
    chmod +x "${INSTALL_DIR}/bin/tune-performance.sh"
    
    # Run the performance tuning script
    "${INSTALL_DIR}/bin/tune-performance.sh"
    
    log "INFO" "System performance tuning completed"
}

# Create health check script
create_health_check() {
    section_header "Creating Health Check Scripts"
    
    # Create health check script
    cat > "${INSTALL_DIR}/bin/health-check.sh" << 'EOF'
#!/bin/bash
# AfCyber SIEM Platform - Health Check Script

LOG_FILE="/var/log/afcyber-siem-health.log"
ALERT_EMAIL=""
ALERT_WEBHOOK=""

# Log function
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "$timestamp [$level] $message" | tee -a "$LOG_FILE"
}

# Send alert
send_alert() {
    local subject="$1"
    local message="$2"
    
    # Send email if configured
    if [ -n "$ALERT_EMAIL" ]; then
        echo "$message" | mail -s "$subject" "$ALERT_EMAIL"
    fi
    
    # Send webhook if configured
    if [ -n "$ALERT_WEBHOOK" ]; then
        curl -s -X POST -H "Content-Type: application/json" -d "{\"text\":\"$subject\", \"message\":\"$message\"}" "$ALERT_WEBHOOK"
    fi
}

log "INFO" "Starting health check"

# Check system resources
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}')
MEM_USAGE=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')

log "INFO" "System: CPU: ${CPU_USAGE}%, Memory: ${MEM_USAGE}%, Disk: ${DISK_USAGE}%"

# Check if resource usage is too high
if (( $(echo "$CPU_USAGE > 90" | bc -l) )); then
    log "WARN" "High CPU usage: ${CPU_USAGE}%"
    send_alert "AfCyber SIEM - High CPU Usage" "CPU usage is at ${CPU_USAGE}%"
fi

if (( $(echo "$MEM_USAGE > 90" | bc -l) )); then
    log "WARN" "High memory usage: ${MEM_USAGE}%"
    send_alert "AfCyber SIEM - High Memory Usage" "Memory usage is at ${MEM_USAGE}%"
fi

if [ "$DISK_USAGE" -gt 90 ]; then
    log "WARN" "High disk usage: ${DISK_USAGE}%"
    send_alert "AfCyber SIEM - High Disk Usage" "Disk usage is at ${DISK_USAGE}%"
fi

# Check Kubernetes node status
log "INFO" "Checking Kubernetes node status"
NODE_STATUS=$(kubectl get nodes -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}')
if [ "$NODE_STATUS" != "True" ]; then
    log "ERROR" "Kubernetes node is not ready"
    send_alert "AfCyber SIEM - Kubernetes Node Not Ready" "Kubernetes node is reporting not ready status"
fi

# Check pod status
log "INFO" "Checking pod status"
UNHEALTHY_PODS=$(kubectl get pods -A | grep -v "Running\|Completed" | grep -v "NAME")
if [ -n "$UNHEALTHY_PODS" ]; then
    log "WARN" "Unhealthy pods detected:"
    echo "$UNHEALTHY_PODS" | tee -a "$LOG_FILE"
    send_alert "AfCyber SIEM - Unhealthy Pods Detected" "$(echo "$UNHEALTHY_PODS" | head -10)"
fi

# Check service status
log "INFO" "Checking service status"
for SERVICE in wazuh-manager graylog thehive opencti misp velociraptor saas-api; do
    POD_STATUS=$(kubectl get pods -n afcyber-siem -l app=$SERVICE -o jsonpath='{.items[0].status.phase}' 2>/dev/null)
    if [ "$POD_STATUS" != "Running" ]; then
        log "WARN" "Service $SERVICE is not running (status: $POD_STATUS)"
        send_alert "AfCyber SIEM - Service Not Running" "Service $SERVICE is not running (status: $POD_STATUS)"
    else
        log "INFO" "Service $SERVICE is running"
    fi
done

# Check ingress status
log "INFO" "Checking ingress status"
INGRESS_STATUS=$(kubectl get pods -n ingress-nginx -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].status.phase}' 2>/dev/null)
if [ "$INGRESS_STATUS" != "Running" ]; then
    log "WARN" "Ingress controller is not running (status: $INGRESS_STATUS)"
    send_alert "AfCyber SIEM - Ingress Not Running" "Ingress controller is not running (status: $INGRESS_STATUS)"
else
    log "INFO" "Ingress controller is running"
fi

# Check database status
log "INFO" "Checking database status"
for DB in postgres elasticsearch mongodb cassandra redis; do
    POD_STATUS=$(kubectl get pods -n afcyber-siem -l app=$DB -o jsonpath='{.items[0].status.phase}' 2>/dev/null)
    if [ "$POD_STATUS" != "Running" ]; then
        log "WARN" "Database $DB is not running (status: $POD_STATUS)"
        send_alert "AfCyber SIEM - Database Not Running" "Database $DB is not running (status: $POD_STATUS)"
    else
        log "INFO" "Database $DB is running"
    fi
done

log "INFO" "Health check completed"
EOF
    
    chmod +x "${INSTALL_DIR}/bin/health-check.sh"
    
    # Create cron job for health checks
    cat > /etc/cron.d/afcyber-siem-health << EOF
# AfCyber SIEM Platform - Health Check Schedule
*/15 * * * * root ${INSTALL_DIR}/bin/health-check.sh > /dev/null 2>&1
EOF
    
    log "INFO" "Health check scripts created successfully"
}

# Create auto-startup configuration
configure_auto_startup() {
    section_header "Configuring Auto-Startup"
    
    # Create systemd service for AfCyber SIEM
    cat > /etc/systemd/system/afcyber-siem.service << EOF
[Unit]
Description=AfCyber SIEM Platform
After=docker.service network.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/bin/startup.sh
ExecStop=${INSTALL_DIR}/bin/shutdown.sh
TimeoutStartSec=300
TimeoutStopSec=300

[Install]
WantedBy=multi-user.target
EOF
    
    # Create startup script
    mkdir -p "${INSTALL_DIR}/bin"
    cat > "${INSTALL_DIR}/bin/startup.sh" << 'EOF'
#!/bin/bash
# AfCyber SIEM Platform - Startup Script

LOG_FILE="/var/log/afcyber-siem-startup.log"

# Log function
log() {
    echo "$(date +"%Y-%m-%d %H:%M:%S") - $1" | tee -a "$LOG_FILE"
}

log "Starting AfCyber SIEM Platform"

# Ensure K3s is running
if ! systemctl is-active --quiet k3s; then
    log "Starting K3s..."
    systemctl start k3s
    sleep 10
fi

# Wait for K3s to be ready
log "Waiting for K3s to be ready..."
timeout 60 bash -c 'until kubectl get nodes; do sleep 2; done'

# Check if pods are running
if ! kubectl get pods -n afcyber-siem 2>/dev/null | grep -q Running; then
    log "Deploying AfCyber SIEM services..."
    
    # Apply Kubernetes resources
    if [ -d "/etc/afcyber-siem/kubernetes" ]; then
        kubectl apply -f /etc/afcyber-siem/kubernetes/
    fi
    
    # Apply Helm chart if needed
    if ! helm list -n afcyber-siem | grep -q afcyber-siem; then
        log "Installing AfCyber SIEM Helm chart..."
        helm upgrade --install afcyber-siem afcyber/siem \
            --namespace afcyber-siem --create-namespace \
            --values /etc/afcyber-siem/kubernetes/values.yaml
    fi
else
    log "AfCyber SIEM services are already running"
fi

# Run performance tuning
if [ -f "/opt/afcyber-siem/bin/tune-performance.sh" ]; then
    log "Running performance tuning..."
    /opt/afcyber-siem/bin/tune-performance.sh
fi

log "AfCyber SIEM Platform startup completed"
EOF
    
    chmod +x "${INSTALL_DIR}/bin/startup.sh"
    
    # Create shutdown script
    cat > "${INSTALL_DIR}/bin/shutdown.sh" << 'EOF'
#!/bin/bash
# AfCyber SIEM Platform - Shutdown Script

LOG_FILE="/var/log/afcyber-siem-shutdown.log"

# Log function
log() {
    echo "$(date +"%Y-%m-%d %H:%M:%S") - $1" | tee -a "$LOG_FILE"
}

log "Shutting down AfCyber SIEM Platform"

# Create a backup before shutdown
if [ -f "/opt/afcyber-siem/bin/backup.sh" ]; then
    log "Creating shutdown backup..."
    /opt/afcyber-siem/bin/backup.sh shutdown
fi

# Scale down deployments gracefully
log "Scaling down deployments..."
kubectl scale deployment -n afcyber-siem --all --replicas=0

# Wait for pods to terminate
log "Waiting for pods to terminate..."
timeout 120 bash -c 'while kubectl get pods -n afcyber-siem 2>/dev/null | grep -q Running; do sleep 2; done'

log "AfCyber SIEM Platform shutdown completed"
EOF
    
    chmod +x "${INSTALL_DIR}/bin/shutdown.sh"
    
    # Enable and start the service
    systemctl daemon-reload
    systemctl enable afcyber-siem
    
    log "INFO" "Auto-startup configured successfully"
}

# Create first tenant
create_first_tenant() {
    section_header "Creating First Tenant"
    
    # Wait for tenant manager to be ready
    wait_for_service "Tenant Manager" "kubectl get pods -n afcyber-siem -l app=tenant-manager | grep -q '1/1'" 30 10
    
    # Create tenant creation script
    cat > "${INSTALL_DIR}/bin/create-tenant.sh" << 'EOF'
#!/bin/bash
# AfCyber SIEM Platform - Tenant Creation Script

TENANT_NAME="$1"
TENANT_PLAN="${2:-standard}"
TENANT_ADMIN_EMAIL="$3"
TENANT_ADMIN_PASSWORD="$4"

if [ -z "$TENANT_NAME" ] || [ -z "$TENANT_ADMIN_EMAIL" ]; then
    echo "Usage: $0 <tenant-name> [plan] <admin-email> [admin-password]"
    echo "  plan: basic, standard, enterprise (default: standard)"
    exit 1
fi

# Generate password if not provided
if [ -z "$TENANT_ADMIN_PASSWORD" ]; then
    TENANT_ADMIN_PASSWORD=$(tr -dc 'A-Za-z0-9!#%&()*+,-./:;<=>?@[\]^_{}~' </dev/urandom | head -c 16)
    echo "Generated password for tenant admin: $TENANT_ADMIN_PASSWORD"
fi

# Create tenant using kubectl exec
TENANT_MANAGER_POD=$(kubectl get pods -n afcyber-siem -l app=tenant-manager -o jsonpath="{.items[0].metadata.name}")
if [ -z "$TENANT_MANAGER_POD" ]; then
    echo "Error: Tenant manager pod not found"
    exit 1
fi

echo "Creating tenant $TENANT_NAME with plan $TENANT_PLAN..."
kubectl exec -n afcyber-siem "$TENANT_MANAGER_POD" -- \
    node /app/scripts/create-tenant.js \
    --name "$TENANT_NAME" \
    --plan "$TENANT_PLAN" \
    --email "$TENANT_ADMIN_EMAIL" \
    --password "$TENANT_ADMIN_PASSWORD"

echo "Tenant creation completed"
echo "Tenant: $TENANT_NAME"
echo "Admin Email: $TENANT_ADMIN_EMAIL"
echo "Admin Password: $TENANT_ADMIN_PASSWORD"
EOF
    
    chmod +x "${INSTALL_DIR}/bin/create-tenant.sh"
    
    # Create first tenant if email is provided
    if [ -n "$ADMIN_EMAIL" ]; then
        log "INFO" "Creating first tenant..."
        "${INSTALL_DIR}/bin/create-tenant.sh" "default" "enterprise" "$ADMIN_EMAIL" "$ADMIN_PASSWORD"
    else
        log "INFO" "Skipping tenant creation (no admin email provided)"
    fi
    
    log "INFO" "Tenant creation script created successfully"
}

# Display completion message
display_completion() {
    section_header "Deployment Complete"
    
    # Get service URLs
    EXTERNAL_IP=$(kubectl get service -n ingress-nginx ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    if [ -z "$EXTERNAL_IP" ]; then
        EXTERNAL_IP=$(hostname -I | awk '{print $1}')
    fi
    
    log "INFO" "AfCyber SIEM Platform has been successfully deployed!"
    log "INFO" "You can access the platform using the following URLs:"
    log "INFO" ""
    log "INFO" "Main Dashboard: https://${DOMAIN}"
    log "INFO" "Admin Portal: https://admin.${DOMAIN}"
    log "INFO" "API: https://api.${DOMAIN}"
    log "INFO" ""
    log "INFO" "If DNS is not configured, you can use the IP address: ${EXTERNAL_IP}"
    log "INFO" ""
    log "INFO" "Default credentials:"
    log "INFO" "Email: ${ADMIN_EMAIL}"
    log "INFO" "Password: ${ADMIN_PASSWORD}"
    log "INFO" ""
    log "INFO" "You can find more information in the following locations:"
    log "INFO" "- Configuration: ${CONFIG_DIR}"
    log "INFO" "- Logs: /var/log/afcyber-siem*"
    log "INFO" "- Backups: ${BACKUP_DIR}"
    log "INFO" ""
    log "INFO" "Useful commands:"
    log "INFO" "- Check system status: ${INSTALL_DIR}/bin/health-check.sh"
    log "INFO" "- Create backup: ${INSTALL_DIR}/bin/backup.sh"
    log "INFO" "- Create tenant: ${INSTALL_DIR}/bin/create-tenant.sh <name> <plan> <email>"
    log "INFO" ""
    log "INFO" "For more information, refer to the documentation at:"
    log "INFO" "https://docs.afcyber.example.com/siem-platform/"
}

#-------------------------------------------------------------------------------
# Main Script
#-------------------------------------------------------------------------------

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --domain)
            DOMAIN="$2"
            shift
            shift
            ;;
        --email)
            ADMIN_EMAIL="$2"
            shift
            shift
            ;;
        --password)
            ADMIN_PASSWORD="$2"
            shift
            shift
            ;;
        --use-letsencrypt)
            USE_LETSENCRYPT=true
            shift
            ;;
        --s3-backup)
            S3_BACKUP_ENABLED=true
            shift
            ;;
        --s3-bucket)
            S3_BUCKET="$2"
            shift
            shift
            ;;
        --s3-region)
            S3_REGION="$2"
            shift
            shift
            ;;
        --s3-access-key)
            S3_ACCESS_KEY="$2"
            shift
            shift
            ;;
        --s3-secret-key)
            S3_SECRET_KEY="$2"
            shift
            shift
            ;;
        --smtp-host)
            SMTP_HOST="$2"
            SMTP_ENABLED=true
            shift
            shift
            ;;
        --smtp-port)
            SMTP_PORT="$2"
            shift
            shift
            ;;
        --smtp-user)
            SMTP_USERNAME="$2"
            shift
            shift
            ;;
        --smtp-pass)
            SMTP_PASSWORD="$2"
            shift
            shift
            ;;
        --smtp-from)
            SMTP_FROM="$2"
            shift
            shift
            ;;
        --debug)
            DEBUG=true
            shift
            ;;
        --help)
            echo "AfCyber SIEM Platform - Deployment Script"
            echo ""
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --domain DOMAIN        Domain name for the platform (default: $DEFAULT_DOMAIN)"
            echo "  --email EMAIL          Admin email address (default: $DEFAULT_EMAIL)"
            echo "  --password PASSWORD    Admin password (auto-generated if not provided)"
            echo "  --use-letsencrypt      Use Let's Encrypt for SSL certificates"
            echo "  --s3-backup            Enable S3 backups"
            echo "  --s3-bucket BUCKET     S3 bucket name for backups"
            echo "  --s3-region REGION     S3 region for backups"
            echo "  --s3-access-key KEY    S3 access key"
            echo "  --s3-secret-key KEY    S3 secret key"
            echo "  --smtp-host HOST       SMTP server hostname"
            echo "  --smtp-port PORT       SMTP server port"
            echo "  --smtp-user USERNAME   SMTP username"
            echo "  --smtp-pass PASSWORD   SMTP password"
            echo "  --smtp-from EMAIL      SMTP from address"