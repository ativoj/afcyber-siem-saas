# AfCyber SIEM – Proxmox VE VM-Image Builder  
Comprehensive guide for building, managing, and operating AfCyber SIEM multi-tenant templates on Proxmox VE.

---

## 1 Overview

**AfCyber SIEM Proxmox Builder** automates creation of production-ready VM *templates* that ship with the full AfCyber SIEM stack pre-installed (Wazuh, Graylog, TheHive + Cortex, OpenCTI + MISP, Velociraptor, Grafana, SaaS control-plane, ML services).  
The builder uses **HashiCorp Packer** with the `proxmox-iso` plugin to orchestrate the entire lifecycle:

```
ISO  ➜  Kickstart  ➜  Provision → Harden → Cleanup → Convert to Template
                                    │
                                    └── generate manifest & checksums
```

Key objectives:

* One-click generation of **small / medium / large** templates (8/16/32 vCPU).
* **Cloud-init ready** – hostname, networking, users, disks auto-expand at clone time.
* **Security hardened** for CIS RHEL 9 baseline & Proxmox virt-IO optimisation.
* Seamless integration with Proxmox features: **cluster replication, vzdump backups, live migration, HA**.

---

## 2 Architecture Specific to Proxmox

| Layer | Component | Proxmox Feature Leveraged |
|-------|-----------|---------------------------|
| Builder | packer-proxmox.pkr.hcl | Uses `proxmox-iso` API to create a VM on target node, upload ISO, monitor installation |
| Provision | `scripts/00-main-setup.sh` | Runs *inside* the VM; installs Docker, K3s, AfCyber stack, pulls images |
| Harden | `ansible/security-hardening.yml` | Applies SELinux policies, firewall, CIS settings |
| Cleanup | `scripts/99-proxmox-cleanup.sh` | Removes secrets, resets machine-id, trims disk |
| Template | Proxmox converts final VM ➜ **immutable template** | QEMU Guest Agent, cloud-init drive, virtio-scsi, discard = on |
| Distribution | `proxmox-template-manager.sh` | Build, validate, clone, backup, replicate, lifecycle tag/untag |

---

## 3 Setup & Configuration

### 3.1 Requirements

| Item | Version | Notes |
|------|---------|-------|
| Proxmox VE | 7.x / 8.x | Cluster or standalone |
| Packer | ≥ 1.8 | Installed on workstation *or* on a build node |
| Packer Proxmox plugin | ≥ 1.1.3 | Automatically handled by `packer init` |
| Ansible | ≥ 2.15 | Security-hardening role |
| ISO Storage | `local` or other | Must contain AlmaLinux ISO |
| Build Node Resources | 32 vCPU / 64 GB RAM / 250 GB free | Only for the build VM – template sizes smaller |

### 3.2 Clone Repository

```bash
git clone https://github.com/your-org/afcyber-siem-saas.git
cd afcyber-siem-saas/proxmox-builder
```

### 3.3 Create secrets file

`secrets.auto.pkrvars.hcl` (ignored via `.gitignore`):

```hcl
proxmox_url                = "https://pve1.example.com:8006/api2/json"
proxmox_token_id           = "packer@pve!token"
proxmox_token_secret       = "longsecretvalue"
proxmox_node               = "pve1"
proxmox_insecure_skip_tls_verify = true
network_bridge             = "vmbr0"
storage_pool               = "local-lvm"
iso_storage_pool           = "local"
```

---

## 4 Packer × Proxmox Integration

* **proxmox-iso** builder provisions a *temporary* VM with:
  * `virtio-scsi-pci` controller, `qemu-agent` flag, balloon disabled.
* Kickstart served via Packer HTTP server; installation is fully unattended.
* After provisioning, Packer executes Proxmox API calls to:
  * **Convert VM to template** (`qm template <vmid>`).
  * **Move** or **rename** template as per `template_name`.
  * Tag template with build metadata (`tags=`).

---

## 5 Template Building Workflow

1. `packer init .` → download plugins.  
2. `packer build -var-file=secrets.auto.pkrvars.hcl packer-proxmox.pkr.hcl`  
3. Builder produces **three templates** (`small`, `medium`, `large`) with ID 9001–9003.  
4. Manifest file `builds/proxmox-manifest.json` & checksums saved for traceability.  
5. Optional post-processor triggers **vzdump backup** of each template.

---

## 6 Multi-Tenant Deployment Scenarios

| Scenario | Pattern |
|----------|---------|
| **MSSP–per-tenant VM** | Clone one template per customer; cloud-init injects unique FQDN, VLAN, resource quota. |
| **Shared-cluster (namespace isolation)** | Deploy a *large* template, then use SaaS control-plane to carve namespaces in K3s for each tenant. |
| **Burst scaling** | Use API script to clone additional *worker* VMs (no control-plane) and join K3s via cloud-init. |
| **Edge collector** | Deploy *small* template near OT/IoT networks; forward logs to central tenant instance. |

---

## 7 Production Best Practices

1. **Place templates on SSD/NVMe (thin-LVM or ZFS) with `discard=on`** for fast clone.  
2. Enable **QEMU Guest Agent** *and* **balloon=0** in template to avoid memory fluctuation.  
3. Use **cloud-init IPAM** (`qm set <id> --ipconfig0 ip=dhcp,gw=<gw>`) to avoid manual NIC edits.  
4. Tag templates with `prod`, `dev`, `deprecated`; automated cleanup script removes obsolete ones.  
5. Schedule **nightly vzdump** backups to PBS or other storage – builder script includes hooks.  

---

## 8 Security Considerations

| Area | Hardening Measure |
|------|-------------------|
| VM Template | SELinux enforcing, custom policy `afcyber_siem.pp` |
| Secrets | All passwords rotated on first boot via cloud-init; no static creds remain in template |
| SSH | Host keys removed; key-only login enforced after clone |
| Firewall | `firewalld` active; only necessary SIEM ports open |
| Updates | Template built from latest AlmaLinux; `dnf-automatic` can be enabled on clone |
| Proxmox Roles | Use **token with least privileges** (`VM.Clone`, `VM.Config.*`, `VFIO.Use`) for Packer |

---

## 9 Performance Optimization Tips

* Set **CPU type** to *host* for clones to leverage all host instructions.  
* Use **virtio-scsi single** + `iothread=1` for heavy Elasticsearch IO.  
* Increase **`vm.max_map_count` = 262144** already baked into template.  
* Pin **Kafka / Elasticsearch** disks to faster storage class if using Ceph.  
* Enable **discard/TRIM** on LVM-thin to reduce bloat (`qm set <id> --scsi0 ...,discard=on`).  
* Consider **hugepages** for JVM-heavy services on >64 GB nodes.

---

## 10 Troubleshooting Guide

| Symptom | Likely Cause | Resolution |
|---------|--------------|------------|
| `packer build` hangs at “Waiting for SSH” | ISO not reachable or wrong kickstart path | Verify `iso_url`, firewall, and boot commands |
| Template boots but cloud-init fails | Missing `nocloud` datasource | Ensure Proxmox **cloud-init drive** attached and user-data present |
| High iowait inside VM | Disk on HDD pool | Move VM to SSD/ZFS, enable `iothread` |
| Cloned VM stuck at `Starting K3s` | Memory ballooning enabled | Set `balloon=0` in template |
| Migration fails with `disk locked` | Backup or snapshot running | Unlock disk `qm unlock <id>` |

---

## 11 Integration with Proxmox Features

* **Clustering** – templates replicate with `proxmox-template-manager.sh replicate`.  
* **Backup** – nightly vzdump snapshot → PBS; automated in manager script.  
* **HA** – convert tenant VMs to HA resources (`ha-manager add vm:<id> --group <group>`).  
* **Live Migration** – supported out-of-box; ensure shared storage (Ceph, NFS, ZFS-replica).  
* **Metrics** – Node Exporter (port 9100) scraped by Proxmox Grafana or external Prometheus.

---

## 12 Cloud-Init Customization Examples

### 12.1 Basic DHCP

```yaml
#cloud-config
hostname: acme-siem
ssh_authorized_keys:
  - ssh-rsa AAAA...
```

```bash
qm clone 9002 120 --name acme-siem
qm set 120 --ipconfig0 ip=dhcp
qm set 120 --cicustom "user=local:snippets/acme-user.yaml"
qm start 120
```

### 12.2 Static IP & Tenant Vars

```yaml
#cloud-config
hostname: soc-alpha
afcyber:
  tenant_name: alpha
  plan: enterprise
manage_etc_hosts: true
runcmd:
  - [ bash, -c, "/opt/afcyber-siem-saas/bin/create-tenant.sh alpha enterprise admin@alpha.com $(openssl rand -base64 12)" ]
```

```bash
qm set 130 --ipconfig0 ip=192.168.50.200/24,gw=192.168.50.1
qm set 130 --nameserver 192.168.50.10
```

---

## 13 Enterprise Deployment Patterns

| Pattern | Description |
|---------|-------------|
| **Hub-and-Spoke** | Central “large” SIEM template in core DC; smaller collectors at branch sites replicate events. |
| **Blue-Green Upgrades** | Keep stable template tag `prod`, build new version with `candidate`; do rolling tenant migration. |
| **Capacity Tiering** | Small template for low-EPS tenants, medium for mid-range, large for VIPs – cloned on demand. |
| **Disaster Recovery** | PBS-based template backups replicated to second datacenter; restore & re-provision tenants via script. |
| **Charge-Back** | Manager script `report-usage` outputs vCPU/RAM/GB per tenant for billing. |

---

## 14 Quick Commands Reference

```bash
# Build templates
./proxmox-template-manager.sh build

# Validate a template (vmid 9002)
./proxmox-template-manager.sh validate 9002

# Deploy 5 test VMs from template
./proxmox-template-manager.sh deploy 9002 5 testlab

# Provision an enterprise tenant
./proxmox-template-manager.sh provision-tenant acme enterprise

# List templates
./proxmox-template-manager.sh list

# Tag template as deprecated
./proxmox-template-manager.sh lifecycle tag 9001 deprecated

# Backup template
./proxmox-template-manager.sh backup 9002
```

---

### Support  
For commercial support and consultancy, contact **AfCyber Labs** – `support@afcyber.example.com`.

© 2025 AfCyber Labs ‑ Apache 2.0 License
