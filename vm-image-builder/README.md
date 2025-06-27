# AfCyber SIEM VM-Image Builder  
Create production-ready VM images with the full AfCyber SIEM multi-tenant SaaS stack pre-installed.

---

## 1  Overview
This builder uses **HashiCorp Packer** plus shell & Ansible provisioners to bake an **Alma Linux 9** virtual-machine image containing:

* Wazuh, Graylog, TheHive + Cortex, OpenCTI, MISP, Velociraptor, Grafana  
* SaaS control-plane (API, tenant-manager, React UI)  
* K3s + Docker runtime, pre-pulled container images  
* Hardened OS, SELinux policies, firewall rules, cloud-init & first-boot automation

The same template produces **VMware (vmdk/ova)**, **VirtualBox (vdi/ova)** and **QEMU (qcow2)** artefacts.

---

## 2  Prerequisites

| Item | Minimum version | Notes |
|------|-----------------|-------|
| Packer | 1.8 | `brew install packer` / `dnf install packer` |
| VirtualBox | 7.0 | For `virtualbox-iso` builds |
| VMware Workstation/Fusion | 17 | For `vmware-iso` builds |
| qemu-kvm | 6.x | For `qemu` builder on Linux |
| Ansible | 2.15 | Used for security-hardening role |
| 40 GB free disk | – | Image building is I/O heavy |
| 16 GB RAM | – | Packer spins a full VM during build |
| Internet access | – | ISO + packages + container layers |

---

## 3  Folder Structure

```
vm-image-builder/
├─ http/                 # Kickstart & preseed files
├─ scripts/              # Shell provisioners (00-99)
├─ ansible/              # Playbooks & roles
├─ packer-config.pkr.hcl # Main Packer template
└─ README.md             # ← you are here
```

---

## 4  Quick Start

```bash
cd afcyber-siem-saas/vm-image-builder

# Validate template
packer init .
packer validate packer-config.pkr.hcl

# Build for all hypervisors
packer build -only="virtualbox-iso.afcyber-siem,vmware-iso.afcyber-siem,qemu.afcyber-siem" \
             -var "iso_url=<alternative_iso>" \
             -var "vm_name=afcyber-siem-$(date +%Y%m%d)"
```

The finished images land under `builds/`:

```
builds/
  ├─ vmware/afcyber-siem-saas-v1.0.0/afcyber-siem-saas-v1.0.0.vmdk
  ├─ virtualbox/afcyber-siem-saas-v1.0.0/afcyber-siem-saas-v1.0.0.ova
  └─ qemu/afcyber-siem-saas-v1.0.0/afcyber-siem-saas-v1.0.0.qcow2
```

---

## 5  Configuration Options

All knobs live in **local variables** inside `packer-config.pkr.hcl`; override with `-var` or a `*.auto.pkrvars.hcl` file.

| Variable | Default | Purpose |
|----------|---------|---------|
| `vm_name` | `afcyber-siem-saas-v1.0.0` | Output artefact name |
| `os_version` | `9.3` | Alma Linux release |
| `cpu_cores` | `16` | vCPU count inside guest |
| `memory_mb` | `32768` | RAM (MiB) |
| `disk_size_mb` | `512000` | System disk size |
| `docker_version` | `24.0.5` | Engine installed in guest |
| `k3s_version` | `v1.27.4+k3s1` | Kubernetes distro |
| `ssh_username/password` | `packer / a_very_secure_packer_password` | Used only during build |

---

## 6  Step-by-Step Build Process

| Phase | Provisioner | Description |
|-------|-------------|-------------|
| 1 | **Kickstart** | Automated Alma Linux install with LVM partitions and SELinux enforcing |
| 2 | `file` | Project source, scripts & configs copied into guest |
| 3 | `shell` `00-main-setup.sh` | Updates OS, installs Docker, K3s, pulls images, tunes kernel, configures firewall & SELinux |
| 4 | **Ansible** | Runs `ansible/security-hardening.yml` (CIS baseline) |
| 5 | `shell` `99-cleanup.sh` | Removes temp files, truncates logs, zero-fills free space |
| 6 | **Post-processors** | Creates manifests & SHA-256 checksums |

Total build time ≈ 25-35 minutes on a modern workstation.

---

## 7  First-Boot Configuration

During the first boot of a **new VM cloned from the image**:

1. `cloud-init` injects SSH keys, hostname & user data  
2. `afcyber-siem-first-boot.service` regenerates SSH host keys, runs DB migrations  
3. `afcyber-siem.service` starts the full Docker/K3s application stack  
4. Health-check cron (`/opt/afcyber-siem-saas/bin/health-check.sh`) begins monitoring  

You can supply custom `user-data` to cloud-init for further automation.

---

## 8  Customization Guide

| Need | How |
|------|-----|
| Change hypervisor | Pass `-only="qemu.afcyber-siem"` etc. |
| Smaller image | Override `disk_size_mb`, comment components in `00-main-setup.sh` |
| Different OS | Swap `iso_url` & kickstart, adjust packages |
| Inject corporate CA | Add file provisioner & update `update-ca-trust` in script |
| Pre-create tenants | Modify `create-tenant.sh` or run via cloud-init |

---

## 9  Cloud Deployment

### VMware vSphere
```bash
ovftool builds/vmware/*.ova "vi://user@vcenter/DC/host/Cluster/Datastore"
```

### Proxmox VE
```bash
qm create 9001 --name afcyber-siem --memory 32768 --cores 16 --scsihw virtio-scsi-pci
qm importdisk 9001 builds/qemu/afcyber-siem-saas-v1.0.0.qcow2 local-lvm
qm set 9001 --scsi0 local-lvm:vm-9001-disk-0,discard=on --boot c --bootdisk scsi0
```

### Public Clouds
Produce a **raw** or **qcow2** image then:

* **AWS EC2 AMI** – `aws ec2 import-image --disk-container file://disk.json`  
* **Azure** – `az image create --source afcyber-siem.vhd ...`  
* **GCP** – `gcloud compute images import ... --source-file=gs://bucket/afcyber-siem.tar.gz`

---

## 10  Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| `SSH timeout` during packer | ISO download slow | Increase `ssh_timeout`, verify network |
| `failed to start k3s` | Low RAM or nested virt | Allocate ≥ 8 GB, ensure VT-x/AMD-V enabled |
| Container images not found | Registry blocked | Pre-pull images to local registry & tweak script |
| SELinux denials in `/var/log/audit/audit.log` | New ports/paths | Add policies via `semanage`, rebuild image |
| Build fails at Ansible step | Ansible not in PATH | Check `ansible` plugin install, `packer init` |

---

## 11  Security Considerations

* SELinux **enforcing** with custom policy `afcyber_siem.pp`  
* Passwords & secrets auto-generated during build → rotate on first boot via cloud-init  
* Firewall opens minimal required ports, IDS/NIDS ports optionally disabled  
* SSH root login disabled after first-boot script, only key-based auth for `afcyber` user  
* Docker uses `userns-remap`, seccomp, rootless containers where possible  
* Image signed with **Packer manifest**; verify SHA-256 before distribution  

---

## 12  Performance Optimisation Tips

* Allocate at least **32 vCPU / 64 GB RAM** for production load (10 k EPS)  
* Store `/var/lib/afcyber-siem` on NVMe SSD; enable `discard=on` for thin-provisioning  
* Adjust `vm.swappiness=10`, `vm.max_map_count=262144` already set in image  
* For GPU-accelerated ML, install NVIDIA drivers in a derived image layer  
* Scale vertically by increasing `cpu/memory` env vars, or horizontally via K3s HPA  

---

## 13  License & Support
This builder and resulting images are provided under the **Apache 2.0** license.  
Commercial support & customisation available from **AfCyber Labs** (sales@afcyber.example.com).

Happy image building! 🚀
