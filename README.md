# AfCyber SIEM – Multi-Tenant SaaS Platform  
Enterprise-Grade Security Analytics & Incident Response for Modern Clouds
---

## 1  Project Overview
AfCyber SIEM is a cloud-native, multi-tenant Security Information & Event Management (SIEM) solution that unifies log management, real-time threat detection, incident response and threat-intelligence into a single subscription service. Built on Alma Linux for long-term enterprise stability, the platform delivers end-to-end security visibility for MSSPs, large enterprises, and government agencies while ensuring strict tenant isolation and regulatory compliance.

### High-Level Architecture
```
┌─────────────────────────────── SaaS Control Plane ───────────────────────────────┐
│  • Identity & Access Mgmt  • Billing  • Tenant Provisioning  • API Gateway      │
└──────────────────────────────────────────────────────────────────────────────────┘
               ▲                         ▲                         ▲
               │                         │                         │
┌──────────────┴──────────────┐  ┌───────┴────────┐   ┌────────────┴────────────┐
│  Data Ingestion & Streaming │  │  Core Analytics│   │    SOC UX & Reporting   │
│  (Kafka + Fluent Bit)       │  │  (Wazuh, ML)   │   │  (Grafana, TheHive UI)  │
└──────────────┬──────────────┘  └───────┬────────┘   └────────────┬────────────┘
               │                         │                         │
          ┌────▼────┐              ┌────▼────┐               ┌────▼────┐
          │ Storage │              │ TI & DF │               │  Alerts │
          │(Graylog│              │(OpenCTI │               │ & Cases │
          │ /ES)   │              │ + MISP) │               │         │
          └────────┘              └─────────┘               └─────────┘
```

## 2  Core Technical Stack
| Layer | Technology | Purpose |
|-------|------------|---------|
| Endpoint Security | **Wazuh** | Real-time host-based intrusion detection, FIM, vulnerability assessment |
| Log Management | **Graylog** (Elasticsearch backend) | Centralized log collection, parsing, search, alerting |
| Incident Response | **TheHive v5** + **Cortex** | Case & task management, automated response jobs |
| Threat Intelligence | **OpenCTI** & **MISP** | Ingest, curate, share CTI; IOC enrichment for detections |
| Visualization | **Grafana** | Multi-tenant dashboards, SLA boards, executive reporting |
| DFIR | **Velociraptor** | Remote live forensics, hunt & response at scale |
| Messaging | **Apache Kafka** | High-throughput event bus connecting collectors to analytics |
| Container Runtime | **Docker / containerd** | Immutable packaging of every service |
| Orchestration | **Kubernetes** (K3s or full) | Automated rollout, scaling & self-healing |
| OS Base | **Alma Linux ≥9** | Stable, RHEL-compatible foundation |

## 3  AI / ML Integration Modules
| Module | Technique | Description |
|--------|-----------|-------------|
| Time-Series Anomaly Detection | Seasonal-Hybrid ESD, Prophet, LSTM | Detect volume & behavioural deviations across log streams |
| Threat Scoring Engine | Gradient Boosting / LightGBM | Prioritises events using CTI, MITRE ATT&CK stage, asset criticality |
| Alert Clustering & Deduplication | DBSCAN, MinHash | Groups similar alerts to reduce analyst fatigue |
| Context-Aware Enrichment | NLP (spaCy + transformers) | Extracts entities, correlates with CTI & asset DB to auto-populate case data |

All ML pipelines are delivered as micro-services exposing REST/GRPC endpoints and support GPU acceleration when available.

## 4  Multi-Tenant Architecture
* **Namespace Isolation:** Each tenant is deployed into its own Kubernetes namespace with dedicated PVCs and PostgreSQL/Elasticsearch indices.  
* **Schema-Per-Tenant:** Shared DB clusters use schema separation with row-level security.  
* **RBAC & ABAC:** SaaS control-plane enforces org / team / role scopes.  
* **Resource Quotas & HPA:** CPU/memory caps per namespace plus auto-scaling.  
* **Cross-Tenant Guardrails:** NetworkPolicies, service mesh isolation, and per-tenant KMS keys ensure zero data leakage.

## 5  Deployment on Alma Linux
1. **Prerequisites**  
   ```bash
   AlmaLinux 9.x minimal  
   16-core CPU • 64 GB RAM (control-plane)  
   Docker 24 • kubectl • helm ≥3.12 • git
   ```
2. **Bootstrap Kubernetes**  
   ```bash
   curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--disable traefik" sh -
   export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
   ```
3. **Clone Repository**  
   ```bash
   git clone https://github.com/your-org/afcyber-siem-saas.git
   cd afcyber-siem-saas
   ```
4. **Install CRDs & Operators**  
   ```bash
   make bootstrap        # installs cert-manager, prometheus-operator etc.
   ```
5. **Deploy Core Stack**  
   ```bash
   helm repo add afcyber https://charts.afcyber.io
   helm upgrade --install afcyber-platform afcyber/siem \
     -f deploy/alma-values.yaml
   ```
6. **Provision First Tenant**  
   ```bash
   ./scripts/create_tenant.sh --name acme --plan enterprise
   ```
7. **Access UI**  
   ```
   https://console.<your-domain>    # SaaS admin
   https://acme.<your-domain>       # Tenant portal
   ```

See `deploy/README.md` for bare-metal, air-gapped and multi-node instructions.

## 6  Key Features & Capabilities
* 10 s log-to-alert latency @ >150 k EPS  
* MITRE ATT&CK & SIGMA rule packs pre-installed  
* Threat intel auto-correlation with STIX 2.1 support  
* Case orchestration with automated Cortex analyzers & responders  
* Self-service tenant onboarding & usage metering  
* SOC KPI dashboards: MTTD, MTTR, coverage heat-maps  
* Live forensic triage via Velociraptor hunts  
* HA active-active Wazuh cluster with agent auto-registration  
* SAML 2.0 / OIDC SSO + SCIM user provisioning

## 7  Security Considerations
| Control | Implementation |
|---------|----------------|
| Encryption in Transit | mTLS (Istio) + TLS 1.3 everywhere |
| Encryption at Rest | LUKS + per-tenant Vault-managed keys |
| Secrets Management | HashiCorp Vault sidecars |
| Least Privilege | PSP/OPA Gatekeeper + namespace RBAC |
| Compliance | Built-in mappings for PCI-DSS 4, HIPAA, ISO 27001 |
| Auditing | Immutable Loki stack for platform & tenant audit logs |
| Supply-Chain | SLSA level 3 images, Cosign signatures, Trivy scans |

## 8  API Documentation Overview
* **Control-Plane API** `https://api.<domain>/v1`  
  * Tenant CRUD, billing, license usage  
* **Analytics API** `https://api.<domain>/v1/analytics`  
  * Query logs, fetch anomalies, push custom rules  
* **Incident API** `https://api.<domain>/v1/cases`  
  * Create / update cases, attach observables, trigger responders  
* **Webhooks** – alert, case-state, usage events  
* **OpenAPI 3.1 spec** available under `docs/openapi.yaml` (Swagger UI hosted at `/docs`).

## 9  Development Setup
```bash
git clone https://github.com/your-org/afcyber-siem-saas.git
cd afcyber-siem-saas
cp .env.example .env          # adjust variables

# Start minimal dev stack
docker compose -f docker-compose.dev.yml pull
docker compose -f docker-compose.dev.yml up -d

# Launch frontend
cd ui
pnpm install
pnpm dev
```
* Unit tests: `make test`  
* Lint & fmt: `make lint`  
* Local ML pipelines require Python 3.11 + Poetry (`cd ml && poetry install`)

## 10  Contributing
1. Fork the repo and create a feature branch (`git checkout -b feat/my-cool-thing`)  
2. Ensure `make precommit` passes (lint, tests, SBOM scan)  
3. Submit a pull request following the PR template  
4. One maintainer + one security reviewer must approve before merge  
5. All contributions are licensed under Apache 2.0

For major changes, open a GitHub Discussion first to align on scope & design.

---

© 2025 AfCyber Labs. Licensed under the Apache License 2.0.
