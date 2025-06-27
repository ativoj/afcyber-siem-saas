# AfCyber SIEM on Proxmox VE – Complete Implementation Guide  
`Version 1.0 | Last updated 2025-06-27`

> **Target environment**  
> Proxmox VE node: **172.16.0.43:8006** (`pve-core`) running Proxmox 8.x with `local` (ISO/snippets) and `local-lvm` (thin-LVM) storage pools.

---

## Table of Contents
1. [Architecture Overview](#1-architecture-overview)  
2. [Prerequisites](#2-prerequisites)  
3. [Create Proxmox API Token](#3-create-proxmox-api-token)  
4. [Install Packer & Plugins](#4-install-packer--plugins)  
5. [Clone Repository & File Layout](#5-clone-repository--file-layout)  
6. [Template Build Workflow](#6-template-build-workflow)  
7. [Validate & Test Templates](#7-validate--test-templates)  
8. [Deploy Multi-Tenant VMs](#8-deploy-multi-tenant-vms)  
9. [Cloud-Init Customisation](#9-cloud-init-customisation)  
10. [Production Deployment Patterns](#10-production-deployment-patterns)  
11. [Monitoring & Day-2 Operations](#11-monitoring--day-2-operations)  
12. [Troubleshooting](#12-troubleshooting)  
13. [Best-Practices & Optimisation](#13-best-practices--optimisation)  
14. [Appendix – Useful One-Liners](#14-appendix--useful-one-liners)

---

## 1. Architecture Overview
AfCyber SIEM templates ship with: **Docker + K3s**, Wazuh, Graylog, TheHive/Cortex, OpenCTI/MISP, Velociraptor, SaaS control-plane, ML services, Prometheus/Grafana, Node-Exporter, QEMU Guest Agent & Cloud-Init.

Each **template (small/medium/large)** is built once and **cloned per tenant**.  Clones are customised via Cloud-Init (`ConfigDrive`) and optionally placed in HA groups, backed-up with vzdump, or replicated across cluster nodes.

_Screenshot description_: *Diagram showing Proxmox node with three linked-clone VMs (`tenant-alpha`, `tenant-beta`, `tenant-gamma`) behind Ingress-NGINX LB.*

---

## 2. Prerequisites

| Item | Minimum | Notes |
|------|---------|-------|
| Proxmox VE | 7.x/8.x | qemu-guest-agent + cloud-init packages installed |
| Hardware | 32 vCPU / 64 GB RAM / 500 GB SSD | for build node; runtime VMs size per template |
| Network | Internet outbound | to pull ISO & container layers |
| Workstation | Linux/macOS with ssh, git, packer | or build directly on Proxmox node |

```bash
# On Proxmox host (as root)
apt update
apt install qemu-guest-agent cloud-init cloud-utils-growpart curl git jq -y
systemctl enable --now qemu-guest-agent
```

---

## 3. Create Proxmox API Token
1. **GUI** → *Datacenter ➜ Permissions ➜ API Tokens ➜ Add*  
2. **User**: `root@pam`  
3. **Token ID**: `packer`  
4. **Privileges**: un-check *Privilege Separation*  
5. **Expire**: *No*  
6. **Note generated secret** – will not be shown again!

**Minimum ACL** (Datacenter level):  
`VM.Allocate, VM.Clone, VM.Config.*, VM.Monitor, VM.PowerMgmt, Datastore.AllocateSpace, Datastore.AllocateTemplate, Sys.Modify`.

CLI alternative:

```bash
pveum user token add root@pam packer --privsep 0
pveum acl modify / -u root@pam@packer -p "VM.Allocate VM.Clone VM.Config.Disk VM.Config.Network VM.Config.CDROM VM.Config.CPU VM.Config.Memory VM.Monitor VM.PowerMgmt Datastore.AllocateSpace Datastore.AllocateTemplate Sys.Modify"
```

---

## 4. Install Packer & Plugins
```bash
# Debian/Ubuntu workstation
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt update && sudo apt install packer -y

# Verify
packer version   # ≥1.8
```

Plugins automatically download on `packer init`, including `hashicorp/proxmox`.

---

## 5. Clone Repository & File Layout
```bash
git clone https://github.com/your-org/afcyber-siem-saas.git
cd afcyber-siem-saas/proxmox-builder

tree -L 2
# .
# ├─ packer-proxmox.pkr.hcl        # Main builder
# ├─ scripts/                      # 00-main-setup.sh, 99-proxmox-cleanup.sh
# ├─ http/ks.cfg                   # Kickstart
# ├─ ansible/security-hardening.yml
# └─ README.md
```

Create **secrets file** `secrets.auto.pkrvars.hcl`:

```hcl
proxmox_url                = "https://172.16.0.43:8006/api2/json"
proxmox_token_id           = "root@pam!packer"
proxmox_token_secret       = "YOUR_LONG_SECRET"
proxmox_node               = "pve-core"
network_bridge             = "vmbr0"
storage_pool               = "local-lvm"
iso_storage_pool           = "local"
```

---

## 6. Template Build Workflow

### 6.1 Initialise & Validate
```bash
packer init .
packer validate -var-file=secrets.auto.pkrvars.hcl packer-proxmox.pkr.hcl
```

### 6.2 Build Templates
```bash
time packer build -var-file=secrets.auto.pkrvars.hcl packer-proxmox.pkr.hcl
```

Expected duration: **~30 min** (depends on bandwidth & storage speed).  
Resulting Proxmox templates:

| VMID | Name                             | Size | Tag |
|------|----------------------------------|------|-----|
| 9001 | `afcyber-siem-small-template`    | 250 GB | prod |
| 9002 | `afcyber-siem-medium-template`   | 500 GB | prod |
| 9003 | `afcyber-siem-large-template`    | 1 TB  | prod |

_Screenshot description_: *Proxmox UI ➜ VMs list showing three templates with blue T icons.*

### 6.3 Post-Build Manifest & Checksums
`builds/proxmox-manifest.json` and `SHA256SUMS` in `proxmox-builder/builds/`.

---

## 7. Validate & Test Templates
```bash
./proxmox-template-manager.sh validate 9002
# Clones, boots, waits for IP, pings, checks SSH, destroys clone.
```

Manual quick test:

```bash
qm clone 9002 120 --name test-siem --full
qm set 120 --ipconfig0 ip=dhcp
qm start 120
qm guest cmd 120 network-get-interfaces
ssh afcyber@<vm-ip>  # key or default disabled password
docker ps   # ensure containers running
```

Expected: `docker ps` shows ~35 containers `Up`.

---

## 8. Deploy Multi-Tenant VMs

### 8.1 One-Liner
```bash
./proxmox-template-manager.sh provision-tenant acme-corp medium
```
Creates VM from **medium** template, injects SSH key, runs first-boot script to onboard tenant.

### 8.2 Bulk Deployment
```bash
./proxmox-template-manager.sh deploy 9001 5 labdemo
```
Creates `labdemo-1 … labdemo-5` VMs.

### 8.3 HA & Replication
```bash
# Convert VM 130 to HA resource
ha-manager add vm:130 --group core-ha

# Replicate template to another node
./proxmox-template-manager.sh replicate 9002 pve-edge
```

---

## 9. Cloud-Init Customisation

### 9.1 Basic DHCP
```yaml
#cloud-config
hostname: alpha-siem
users:
  - name: afcyber
    ssh_authorized_keys:
      - ssh-rsa AAAA... user@laptop
```

```bash
qm clone 9001 150 --name alpha-siem
qm set 150 --ipconfig0 ip=dhcp
qm set 150 --cicustom "user=local:snippets/alpha-user.yaml"
qm start 150
```

### 9.2 Static IP + Tenant Onboarding
```yaml
#cloud-config
hostname: beta-siem
runcmd:
  - [/opt/afcyber-siem-saas/bin/create-tenant.sh, beta, enterprise, soc@beta.com]
```

```bash
qm set 151 --ipconfig0 ip=192.168.50.210/24,gw=192.168.50.1
```

### 9.3 Join Existing K3s Cluster (worker node)
```yaml
#cloud-config
write_files:
  - path: /var/lib/rancher/k3s/agent/etc/config.yaml
    content: |
      server: https://10.0.0.10:6443
      token: "K3S_CLUSTER_TOKEN"
runcmd:
  - systemctl enable --now k3s-agent
```

---

## 10. Production Deployment Patterns

| Pattern | Description |
|---------|-------------|
| **Per-Tenant VM** | Each customer gets isolated VM (recommended for MSSPs). |
| **Namespace Multi-Tenant** | Large template shared; SaaS control-plane enforces namespace quotas. |
| **Edge Collector** | Small template near OT floor forwarding events to central SIEM. |
| **Blue-Green Upgrade** | Keep old template tagged `prod`, build new `candidate`, migrate tenants. |

---

## 11. Monitoring & Day-2 Operations

### 11.1 Node & VM Metrics  
Proxmox exports RRD; additionally Node-Exporter (port 9100) scraped by **Prometheus** inside platform.

### 11.2 Health-Check Script
```
/opt/afcyber-siem-saas/bin/health-check.sh
```
Runs every 15 min via cron, alerts via email/webhook.

### 11.3 Backup
```bash
./proxmox-template-manager.sh backup 9002   # vzdump snapshot → PBS
```

### 11.4 Rolling Updates
```bash
# Within tenant VM
cd /opt/afcyber-siem-saas
git pull
docker-compose pull
docker-compose up -d
```

Use **HA group** to live-migrate before host maintenance.

---

## 12. Troubleshooting

| Step | Symptom | Fix |
|------|---------|-----|
| Build | `Waiting for SSH` timeout | ISO unreachable, wrong bridge; verify `vmbr0` DHCP. |
| First boot | Stuck at `Starting K3s` | Memory balloon still enabled – edit template `balloon=0`. |
| Clone | No IP via guest-agent | cloud-init network mis-set; run `qm cloudinit dump  <vmid>`. |
| Service | Wazuh not starting | Check `/var/ossec/logs/ossec.log`; ensure `/var/lib/afcyber-siem` permission 1000:1000. |
| High IO wait | Disk on spinning pool | Move VM disk to SSD pool, enable `iothread=1`. |
| Migration fails | `ip address missing on source vmbr0` | Ensure same bridge name on both nodes. |

---

## 13. Best-Practices & Optimisation

* **Template storage** on **SSD/NVMe thin-LVM** with `discard=on`.
* Enable **QEMU Guest Agent** and `virtio-scsi-single` controller.
* Use **CPU type `host`** for clones, `numa=on` for >32 vCPU.
* Rotate logs via logrotate; keep `/var/log` separate LV (already in kickstart).
* Backup templates nightly then **test restore** monthly.
* Tag templates (`prod`, `deprecated`); run cleanup script quarterly.
* Keep `vm.max_map_count=262144` and `fs.file-max=2,097,152`.
* Use **PBS** with `zstd` compression for efficient backups.
* Monitor **K3s** with `k3s kubectl top nodes` and **Prometheus** dashboards.

---

## 14. Appendix – Useful One-Liners

```bash
# List AfCyber templates
pvesh get /cluster/resources --type vm | jq -r '.[] | select(.template==1 and .name|test("afcyber")) | "\(.vmid)\t\(.name)"'

# Unlock stuck template
qm unlock 9002

# Convert clone to HA
ha-manager add vm:150 --group core-ha

# Live migrate running tenant VM
qm migrate 150 pve-edge --online

# Re-generate cloud-init drive
qm cloudinit update 150
```

---

> _Need help?_  Reach **AfCyber Labs Support**: support@afcyber.example.com  
> Commercial SLA, cluster design, and incident response service available.
