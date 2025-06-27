# AfCyber SIEM – Single-Node Ubuntu 22.04 Deployment Guide  
`Version 1.0  |  Proxmox VE host 172.16.0.43:8006`

---

## 0  Executive Summary  
This guide walks you through deploying the **entire AfCyber SIEM stack (Wazuh, Graylog, TheHive + Cortex, OpenCTI + MISP, Velociraptor, Grafana, SaaS control-plane, ML services)** on **one Ubuntu 22.04 LTS VM** running on your Proxmox VE node `172.16.0.43:8006`. Target capacity: **≤ 10 000 EPS / 1 000 agents**.

---

## 1  Create Ubuntu VM on Proxmox  

| Setting | Recommended |
|---------|-------------|
| VM ID   | 110 |
| Name    | afcyber-siem-single |
| ISO     | `ubuntu-22.04.4-live-server-amd64.iso` (upload to *local* → *ISO Images*) |
| Storage | `local-lvm` thin-LVM |
| Disk    | **1 TB** (`scsi0`, VirtIO-SCSI-single, `discard=on`) |
| CPU     | **16 cores**, `host` type, NUMA **off** |
| Memory  | **32 GB** (ballooning **disabled**) |
| Network | Bridge `vmbr0`, Model **VirtIO** |
| BIOS    | OVMF (UEFI), add EFI disk (32 MB) |
| Agent   | **QEMU Guest Agent (enable)** |

### CLI one-liner
```bash
qm create 110 --name afcyber-siem-single --memory 32768 --cores 16 --sockets 1 \
  --cpu host --net0 virtio,bridge=vmbr0 --scsihw virtio-scsi-single \
  --ostype l26 --bios ovmf --efidisk0 local-lvm:1,pre-enrolled-keys=0 \
  --ide2 local:iso/ubuntu-22.04.4-live-server-amd64.iso,media=cdrom
qm set 110 --scsi0 local-lvm:0,discard=on,size=1024G
qm set 110 --agent enabled=1
```
Start VM and open **Console** to install Ubuntu.

---

## 2  Ubuntu 22.04 Installation & Initial Config  

1. *Language*: **English**  
2. *Keyboard*: match yours  
3. *Networking*: ensure DHCP / correct IP  
4. *Proxy/Mirror*: leave default  
5. *Storage*: **Use Entire Disk & set up LVM** – leave proposed sizes (we’ll resize later).  
6. *User*:  
   * name `afcyber`  
   * strong password  
   * **Install OpenSSH server: Yes**  
7. *Snap selection*: skip.  
8. Reboot → remove ISO.

### Post-install
```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y qemu-guest-agent curl wget git gnupg lsb-release htop ufw net-tools
sudo systemctl enable --now qemu-guest-agent
```

---

## 3  System Hardening & Security  

### 3.1 Kernel / sysctl  
```bash
cat <<'EOF' | sudo tee /etc/sysctl.d/99-afcyber-siem.conf
fs.file-max = 2097152
vm.max_map_count = 262144
vm.swappiness = 10
net.core.somaxconn = 65535
net.ipv4.tcp_fin_timeout = 30
EOF
sudo sysctl --system
```

### 3.2 Limits  
```bash
echo "* hard nofile 1048576" | sudo tee -a /etc/security/limits.conf
echo "* soft nofile 1048576" | sudo tee -a /etc/security/limits.conf
```

### 3.3 Firewall (UFW)  
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22               # SSH
sudo ufw allow 443/tcp          # Wazuh Dashboard
sudo ufw allow 3000/tcp         # Grafana
sudo ufw allow 5601/tcp         # OpenSearch Dash
sudo ufw allow 9000/tcp 9001/tcp 8080/tcp 8889/tcp
sudo ufw allow 514/udp 1514/tcp 1515/tcp 12201/udp
sudo ufw enable
```

---

## 4  Install Docker & Container Runtime  

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
# Docker Compose plugin
sudo apt install -y docker-compose-plugin
docker compose version
```

Logout/login to apply group membership.

---

## 5  Clone & Configure AfCyber SIEM  

```bash
git clone https://github.com/ativoj/afcyber-siem-saas.git
cd afcyber-siem-saas
cp .env.example .env
# generate secrets
pwgen 32 1  # repeat → replace placeholders in .env
```

Minimum edits in `.env`:
```
ENVIRONMENT=production
WAZUH_API_PASSWORD=<gen>
POSTGRES_PASSWORD=<gen>
REDIS_PASSWORD=<gen>
GRAYLOG_PASSWORD_SECRET=<gen64>
GRAYLOG_ROOT_PASSWORD_SHA2=$(echo -n '<Password>' | sha256sum | cut -d' ' -f1)
```

---

## 6  Deploy the Complete Stack  

```bash
cd 04_Docker_Helm_Packaging
docker compose pull          # ~10 GB images
docker compose up -d
```

Verify containers:
```bash
docker compose ps
```
Expect ~35 services **Up**.

---

## 7  Network & Reverse Proxy (optional)  
If you need single port 443 entry:

```bash
sudo apt install -y nginx
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
 -keyout /etc/ssl/private/afcyber.key \
 -out /etc/ssl/certs/afcyber.crt \
 -subj "/CN=siem.local"
cat >/etc/nginx/sites-available/afcyber.conf <<EOF
server {
  listen 443 ssl;
  server_name siem.local;
  ssl_certificate /etc/ssl/certs/afcyber.crt;
  ssl_certificate_key /etc/ssl/private/afcyber.key;

  location /wazuh/ { proxy_pass https://localhost:5601/; }
  location /grafana/ { proxy_pass http://localhost:3000/; }
  location /graylog/ { proxy_pass http://localhost:9000/; }
  location /thehive/ { proxy_pass http://localhost:9001/; }
  location /opencti/ { proxy_pass http://localhost:8080/; }
}
EOF
sudo ln -s /etc/nginx/sites-available/afcyber.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl restart nginx
```

---

## 8  Service Verification & Testing  

| Component | URL | Default Creds |
|-----------|-----|--------------|
| **Wazuh Dashboard** | `https://<VM_IP>:5601` → *Wazuh* tab | admin / AfCyberSecretPassword |
| **Grafana** | `http://<VM_IP>:3000` | admin / admin |
| **Graylog** | `http://<VM_IP>:9000` | admin / admin |
| **TheHive** | `http://<VM_IP>:9001` | create on first run |
| **OpenCTI** | `http://<VM_IP>:8080` | admin@siem.local / AfCyberChangeMe |
| **Velociraptor** | `https://<VM_IP>:8889` | admin / set at first boot |

Check logs:
```bash
docker compose logs wazuh-manager | tail -20
docker compose logs graylog         | tail -20
```

---

## 9  Monitoring & Maintenance  

**Resource check**
```bash
htop
watch -n5 docker stats
```

**Update**
```bash
cd afcyber-siem-saas/04_Docker_Helm_Packaging
docker compose pull
docker compose up -d
```

**Health script**
```bash
cat >/usr/local/bin/siem-health.sh <<'EOF'
#!/bin/bash
echo "=== $(date) ==="
docker compose -f /home/afcyber/afcyber-siem-saas/04_Docker_Helm_Packaging/docker-compose.yml ps
EOF
chmod +x /usr/local/bin/siem-health.sh
(crontab -l; echo "*/15 * * * * /usr/local/bin/siem-health.sh >>/var/log/siem-health.log") | crontab -
```

---

## 10  Troubleshooting  

| Symptom | Fix |
|---------|-----|
| **Port conflict** on 5601/3000 | change exposed ports in `docker-compose.yml`. |
| Graylog “`Couldn't get master node`” | wait for ES container; ensure `vm.max_map_count` set. |
| Wazuh agents cannot connect | open `1514/tcp 1515/tcp 514/udp` on UFW; ensure VM IP reachable. |
| High CPU load | disable unused analyzers in Cortex; review ML services. |

Logs: `docker compose logs <service>`, system: `journalctl -u docker`.

---

## 11  Performance Optimisation Tips  

* Store **/var/lib/docker** on SSD/NVMe.  
* Increase `ulimit -n 1048576`.  
* Dedicate 8 GB JVM heap to OpenSearch (`ES_JAVA_OPTS`).  
* Load dashboards only when needed in Grafana.  
* For EPS > 10 k, scale **Graylog + ES** to separate nodes.

---

## 12  Backup & Recovery  

### 12.1 Volumes Backup
```bash
docker compose down
tar -czf /backup/siem-volumes-$(date +%F).tgz /var/lib/docker/volumes
docker compose up -d
```

### 12.2 Config Backup
```bash
tar czf /backup/siem-config-$(date +%F).tgz ~/afcyber-siem-saas/.env ~/afcyber-siem-saas
```

### 12.3 Restore
```bash
docker compose down
tar -xzf siem-volumes-YYYY-MM-DD.tgz -C /
docker compose up -d
```

Automate with cron + `restic`, `rsnapshot`, or Proxmox vzdump of the whole VM.

---

## 13  Decommission / Scale-out Paths  

* Convert VM to **Proxmox template** once tuned, clone for staging.  
* Migrate **Elasticsearch & Graylog** to dedicated nodes for >10 k EPS.  
* Add Velociraptor collectors on endpoints, point to central server.

---

**Your AfCyber SIEM single-node deployment is now operational – happy hunting!** 🛡️
