#!/bin/bash -eux
#===============================================================================
# AfCyber SIEM - Final Cleanup Script for Proxmox Templates
#
# This script is the final step in the Packer build process. It prepares the
# virtual machine to be converted into a clean, secure, and optimized
# Proxmox VE template.
#
# Key actions performed:
# - Stops all application services.
# - Cleans package manager caches and temporary files.
# - Scrubs all log files and system identifiers.
# - Resets network configuration and cloud-init state.
# - Removes unique SSH host keys and machine-id for safe cloning.
# - Optimizes the filesystem to minimize the final template size.
#
# Author: AfCyber Labs
# License: Apache-2.0
#===============================================================================

# --- Helper Function for Logging ---
log() {
    echo "==> ${1}: ${2}"
}

# --- Stop Services ---
section_header() {
    log "INFO" "======================================================================"
    log "INFO" "$1"
    log "INFO" "======================================================================"
}

section_header "Step 1: Gracefully Stopping Services"
log "INFO" "Stopping AfCyber SIEM application stack..."
if systemctl is-active --quiet afcyber-siem.service; then
    systemctl stop afcyber-siem.service
fi

log "INFO" "Stopping Kubernetes (K3s) service..."
if systemctl is-active --quiet k3s.service; then
    systemctl stop k3s.service
fi

log "INFO" "Stopping Docker service..."
if systemctl is-active --quiet docker.service; then
    systemctl stop docker.service
fi

# --- Package and Cache Cleanup ---
section_header "Step 2: Cleaning Package Caches"
log "INFO" "Cleaning all DNF package manager caches..."
dnf clean all
log "INFO" "Removing temporary build files from /tmp and /var/tmp..."
rm -rf /tmp/*
rm -rf /var/tmp/*

# --- Log File Cleanup ---
section_header "Step 3: Scrubbing Log Files"
log "INFO" "Truncating all log files in /var/log..."
find /var/log -type f -name "*.log" -exec truncate --size 0 {} \;
find /var/log -type f -name "*.[0-9]" -exec rm -f {} \;
find /var/log -type f -name "*.gz" -exec rm -f {} \;
log "INFO" "Cleaning journald logs..."
journalctl --rotate
journalctl --vacuum-time=1s
log "INFO" "All system and application logs have been cleared."

# --- Network Interface Cleanup ---
section_header "Step 4: Resetting Network Configuration"
log "INFO" "Removing persistent network device rules..."
rm -f /etc/udev/rules.d/70-persistent-net.rules
log "INFO" "Cleaning network interface configuration files..."
# Remove hardware-specific info like HWADDR/UUID from ifcfg scripts
for ifcfg in $(find /etc/sysconfig/network-scripts -name "ifcfg-*" ! -name "ifcfg-lo"); do
    sed -i '/^HWADDR/d' "$ifcfg"
    sed -i '/^UUID/d' "$ifcfg"
done
log "INFO" "Network configuration has been generalized for cloning."

# --- System Identity Reset ---
section_header "Step 5: Resetting System Identity for Templating"
log "INFO" "Removing SSH host keys..."
rm -f /etc/ssh/ssh_host_*
log "INFO" "SSH host keys removed. New keys will be generated on first boot of a cloned VM."

log "INFO" "Resetting machine-id..."
# This ensures each cloned VM gets a unique ID, critical for DHCP and other services.
truncate -s 0 /etc/machine-id
if [ -f /var/lib/dbus/machine-id ]; then
    rm -f /var/lib/dbus/machine-id
    ln -s /etc/machine-id /var/lib/dbus/machine-id
fi
log "INFO" "Machine ID has been reset."

log "INFO" "Cleaning cloud-init state..."
# This forces cloud-init to re-run on the next boot, applying any customization from Proxmox.
cloud-init clean --logs --seed
log "INFO" "Cloud-init state reset. The template is now ready for customization on clone."

# --- User and History Cleanup ---
section_header "Step 6: Cleaning User and Shell History"
log "INFO" "Removing the temporary 'packer' user..."
userdel -r packer &>/dev/null || true

log "INFO" "Clearing shell history for all users..."
unset HISTFILE
rm -f /root/.bash_history
history -c
if [ -d /home ]; then
    for user_home in /home/*; do
        if [ -f "${user_home}/.bash_history" ]; then
            rm -f "${user_home}/.bash_history"
        fi
    done
fi
log "INFO" "All shell history has been cleared."

# --- Filesystem Optimization for Template Size Reduction ---
section_header "Step 7: Optimizing Filesystem for Compression"
log "INFO" "Running fstrim to discard unused blocks on thin-provisioned storage..."
fstrim -av

log "INFO" "Zeroing out free space on the disk to improve template compression..."
# This creates a large file of zeros that fills all free space, which compresses
# extremely well, significantly reducing the final template image size.
dd if=/dev/zero of=/zero bs=1M status=progress || echo "dd exit code $? is suppressed"
log "INFO" "Removing the temporary zero file..."
rm -f /zero

# Sync to ensure all data is written to disk before Packer shuts down the VM.
log "INFO" "Flushing filesystem buffers to disk..."
sync
sync
sync

# --- Final Validation and Completion Message ---
section_header "Final Validation"
log "INFO" "Verifying cleanup status..."
if [ -f /etc/ssh/ssh_host_rsa_key ]; then
    error_exit "Validation failed: SSH host keys were not removed."
fi
if [ -s /etc/machine-id ]; then
    error_exit "Validation failed: Machine ID was not reset."
fi
if [ -f /root/.bash_history ]; then
    error_exit "Validation failed: Root bash history was not cleared."
fi
log "INFO" "Validation successful. The system is clean and ready for templating."

log "INFO" "======================================================================"
log "INFO" "Cleanup complete. The VM is now prepared for shutdown and conversion"
log "INFO" "into a Proxmox template."
log "INFO" "======================================================================"
