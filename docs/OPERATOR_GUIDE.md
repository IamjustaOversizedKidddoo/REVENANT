# REVENANT v2.0 Operator Guide & Mission Playbook

Welcome to the **REVENANT v2.0 Operator Guide**. This manual details deployment, configuration, mission profiling, execution commands, and enterprise integration workflows for the REVENANT Autonomous Full-Spectrum AI Red Teaming and Security Operations Platform.

---

## Table of Contents
1. [Platform Architecture](#1-platform-architecture)
2. [Turn-Key Appliance Deployment (Docker Compose)](#2-turn-key-appliance-deployment-docker-compose)
3. [Scope Enforcement & Rules of Engagement](#3-scope-enforcement--rules-of-engagement)
4. [Unified CLI Subcommands & Syntax](#4-unified-cli-subcommands--syntax)
5. [Standard Mission Profiles](#5-standard-mission-profiles)
6. [Attack Graph Synthesis & Choke Point Analysis](#6-attack-graph-synthesis--choke-point-analysis)
7. [Autonomous Remediation Engine](#7-autonomous-remediation-engine)
8. [External Attack Surface Management (ASM) & Continuous Monitoring](#8-external-attack-surface-management-asm--continuous-monitoring)
9. [SOAR Alerting & Live Webhook Integration](#9-soar-alerting--live-webhook-integration)
10. [Multi-Format Enterprise Reporting Exporters](#10-multi-format-enterprise-reporting-exporters)
11. [Standard of Proof & Evidence Classification](#11-standard-of-proof--evidence-classification)

---

## 1. Platform Architecture

REVENANT operates as a distributed, decoupled, multi-domain offensive security appliance:

```
                  ┌──────────────────────────────────────────────┐
                  │          Operator CLI (revenant.py)          │
                  │   scan | profiles | remediate | asm | serve  │
                  └───────────────────────┬──────────────────────┘
                                          │ HTTP / REST / OpenAPI 3.1
                                          ▼
                  ┌──────────────────────────────────────────────┐
                  │          FastAPI Control Plane (Port 8000)   │
                  │  - Scope Manifest Engine (Layer 1 Gate)      │
                  │  - Campaign Stigmergic Blackboard            │
                  │  - Mission Profiler & Attack Graph Engine     │
                  └──────────────┬───────────────────────────────┘
                                 │
                 ┌───────────────┴────────────────┐
                 ▼                                ▼
       ┌───────────────────┐            ┌───────────────────┐
       │ Redis 7 Broker    │            │ PostgreSQL 16 +   │
       │ (Queue / PubSub)  │            │ pgvector Extension│
       └─────────┬─────────┘            └───────────────────┘
                 │
                 ▼
       ┌────────────────────────────────────────────────────────┐
       │ Celery Worker Engine (Multi-Domain Security Swarm)     │
       │ - Recon (Subfinder, Nmap, FFuf)                        │
       │ - Web/API (Semgrep, Nuclei, Katana, DastAdapter, FFuf) │
       │ - Cloud & K8s (Trivy, Prowler, Checkov, Kubescape)     │
       │ - Identity (NetExec, BloodHound, Certipy)              │
       │ - Purple & Emulation (Atomic Red Team, Caldera)        │
       │ - Mobile (MobSF, Mobsfscan)                            │
       │ - Forensics & IR (Volatility 3, Velociraptor)          │
       │ - Malware & Firmware (YARA, CAPEv2, Binwalk, AFL++)    │
       │ - Remediation (Terraform, Ansible, Sigma, YARA)        │
       └────────────────────────────────────────────────────────┘
```

---

## 2. Turn-Key Appliance Deployment (Docker Compose)

REVENANT includes pre-packaged, hardened OCI container definitions and Docker Compose manifests in `deployments/docker-compose.yml`.

### Prerequisites
- Docker Engine 24.0+ and Docker Compose v2.20+
- 4+ CPU cores, 8GB+ RAM recommended
- Host access to the networks and clouds designated in your Scope Manifest

### Quickstart
```bash
# 1. Clone repository and navigate to deployments directory
cd /path/to/REVENANT/deployments

# 2. Copy the environment configuration template
cp .env.example .env

# 3. Configure platform secrets (API keys, DB passwords, HMAC tokens)
nano .env

# 4. Start the appliance in detached daemon mode
docker compose up -d

# 5. Verify service health and container status
docker compose ps
curl -s http://localhost:8000/api/v1/health | jq
```

### Appliance Containers
- `revenant-postgres`: PostgreSQL 16 with pgvector extension for vulnerability embeddings and graph storage.
- `revenant-redis`: Redis 7 in-memory broker and Blackboard pub/sub bus.
- `revenant-control-plane`: FastAPI application running on port `8000` as non-root user `revenant` (UID 10001).
- `revenant-worker`: Worker node with offensive security tools installed and persistence volumes for `/app/evidence` and `/app/data`.

---

## 3. Scope Enforcement & Rules of Engagement

Safety and authorized operation are enforced through the **Layer 1 Scope Manifest Engine** (`control_plane/schemas/scope.py`). Before any scanning tool or agent is executed, the target must pass strict boundary validation.

### Manifest File Format (`scope.json` or `scope.yaml`)
```yaml
allowed_hosts:
  - "portal.corp.local"
  - "192.168.1.50"
allowed_domains:
  - "corp.local"
allowed_cidrs:
  - "192.168.1.0/24"
  - "10.10.0.0/16"
allowed_cloud_accounts:
  - "123456789012"
  - "sub-prod-enterprise"
allowed_identity_domains:
  - "CORP.LOCAL"
excluded_hosts:
  - "192.168.1.1" # Default gateway excluded
  - "dc-backup.corp.local"
time_window_utc:
  start: "2026-09-19T00:00:00Z"
  end: "2026-09-20T23:59:59Z"
max_requests_per_second: 150
```

> **Warning**: Any scan targeting an IP or domain outside the scope manifest immediately triggers a `ScopeViolationError` and halts execution.

---

## 4. Unified CLI Subcommands & Syntax

REVENANT provides a unified CLI entrypoint: `python revenant.py [SUBCOMMAND] [OPTIONS]`.

### 1. Execute Security Scan (`scan`)
Runs an autonomous security assessment against a target using a selected mission profile.

```bash
# Full-spectrum assessment
python revenant.py scan http://portal.corp.local --profile full-spectrum --scope scope.yaml --output ./evidence/

# Targeted Web DAST scan
python revenant.py scan http://api.corp.local --profile web-dast --scope scope.yaml

# Cloud infrastructure posture review
python revenant.py scan aws://123456789012 --profile cloud-native --scope scope.yaml
```

### 2. List Mission Profiles (`profiles`)
Inspect all available mission profiles, descriptions, and active tools.

```bash
python revenant.py profiles
```

### 3. Generate Autonomous Remediation (`remediate`)
Generate Terraform, Ansible, YARA, and Sigma remediation artifacts from existing findings.

```bash
python revenant.py remediate ./evidence/findings.json --output ./remediations/
```

### 4. External Attack Surface Management (`asm`)
Track asset discovery deltas and compute attack surface expansion.

```bash
# Baseline initial assets
python revenant.py asm --target corp.local --inventory ./assets/current_assets.json

# Detect newly exposed ports or endpoints against previous baseline
python revenant.py asm --target corp.local --inventory ./assets/new_assets.json --baseline ./assets/baseline.json
```

### 5. Launch FastAPI Control Plane (`serve`)
Start the REST API server locally for remote orchestration and Webhook receivers.

```bash
python revenant.py serve --host 0.0.0.0 --port 8000 --reload
```

---

## 5. Standard Mission Profiles

REVENANT v2.0 standardizes offensive campaigns into five hardened mission profiles:

| Profile Name | Target Type | Active Tools & Engines | Primary Focus |
|:---|:---|:---|:---|
| `recon` | Domain, Subnet, Host | Subfinder, Nmap, FFuf | Surface mapping, port scanning, subdomain enumeration, directory fuzzing. |
| `web-dast` | HTTP/HTTPS URL, API | Semgrep, Nuclei, Katana, DastAdapter, FFuf, Schemathesis | Web/API vulnerability discovery, XSS, open redirect, path traversal, stateful OpenAPI fuzzing. |
| `cloud-native` | Cloud Account, K8s Cluster | Trivy, Prowler, Checkov, Kubescape, Kube-bench, Falco | Cloud posture (AWS/Azure), container image CVEs, CIS benchmarks, K8s runtime anomalies. |
| `ad-identity` | Active Directory Domain / DC | NetExec, BloodHound, Certipy | Domain enumeration, Kerberoasting, AS-REP roasting, AD CS certificate misconfigurations (ESC1-ESC8). |
| `full-spectrum` | Enterprise Target / Hybrid | All Swarm Adapters + Attack Graph + Autonomous Remediation + SOAR | End-to-end multi-domain simulation: external discovery to lateral movement, choke points, and remediation. |

---

## 6. Attack Graph Synthesis & Choke Point Analysis

During full-spectrum campaigns, the **Attack Graph Engine** (`intelligence/graph/attack_graph.py`) correlates cross-domain findings into directed multi-hop attack paths:

- **Ingestion**: Discovered host assets, cloud accounts, AD entities, and validated vulnerabilities.
- **Node Classification**: `ASSET` (Hosts, Cloud Accounts, Endpoints), `VULNERABILITY` (CVEs, Misconfigs), `CREDENTIAL` (Tokens, Passwords, Kerberos Tickets).
- **Choke Point Analysis**: Identifies nodes with high betweenness centrality where applying a single remediation severs the adversary's lateral movement path to the Crown Jewels (Domain Controller, Database, S3 PII bucket).

---

## 7. Autonomous Remediation Engine

REVENANT goes beyond vulnerability discovery to generate fully deployable remediation code across 4 engineering domains:

1. **Terraform (`.tf`)**:
   - Automated S3 Bucket lockdowns (`PublicAccessBlock`, AES-256 SSE).
   - AWS Security Group ingress restrictions (converting `0.0.0.0/0` on SSH/RDP to internal RFC1918 CIDR).
   - IAM least-privilege policies with mandatory MFA conditions.
2. **Kubernetes (`.yaml`)**:
   - Zero-trust default-deny ingress/egress `NetworkPolicy` manifests.
   - PodSecurityStandards patches (`runAsNonRoot: true`, `drop: [ALL]`, `readOnlyRootFilesystem: true`).
3. **Ansible Playbooks (`.yml`)**:
   - Windows SMBv1 protocol deprecation and mandatory SMB packet signing (`RequireSecuritySignature`).
   - Linux SSH server hardening (`PermitRootLogin no`, `PasswordAuthentication no`) and Telnet daemon removal.
4. **Detection Engineering (`.yml` / `.yar`)**:
   - **Sigma Rules**: Behavioral detection for process injection, memory allocation (`VirtualAllocEx`), and privilege escalation.
   - **YARA Rules**: Signature detection for uploaded webshells, base64 payloads, and backdoors.

---

## 8. External Attack Surface Management (ASM) & Continuous Monitoring

The **ASM Engine** (`orchestrator/asm_monitor.py`) provides continuous external attack surface visibility:
- **Baseline Ingestion**: Stores known host assets, open ports, and API routes.
- **Delta Tracking**: Calculates added assets, newly opened ports, removed services, and risk score adjustments.
- **Drift Alerting**: Emits critical alerts whenever newly exposed attack surface is discovered without prior change authorization.

---

## 9. SOAR Alerting & Live Webhook Integration

The **SOAR Webhook Adapter** (`orchestrator/soar_webhook.py`) dispatches verified security findings directly into enterprise SOC / SOAR platforms (Splunk SOAR / Phantom, Palo Alto Cortex XSOAR, Generic Webhook):

- **Payload Format**: Standardized JSON containing campaign metadata, target, asset information, and finding array.
- **Authentication**: Cryptographic message integrity via `X-REVENANT-Signature: sha256=<HMAC_HEX>`.
- **Automatic Retry**: Built-in exponential backoff for network resilience.

---

## 10. Multi-Format Enterprise Reporting Exporters

REVENANT v2.0 exports mission findings into all major enterprise documentation and ticketing formats:

1. **Executive Markdown / PDF Report** (`report.md`): Formatted vulnerability breakdown with CVSS scores, executive summary, and remediation roadmaps.
2. **OASIS SARIF v2.1.0** (`report.sarif`): Static and dynamic analysis results standard compatible with GitHub Advanced Security and CI/CD pipelines.
3. **MITRE ATT&CK Navigator Layer v4.5** (`report.attack_nav.json`): Heatmap visualizing mapped enterprise tactics and techniques (Reconnaissance to Impact).
4. **Faraday Vulnerability Management JSON** (`faraday.json`): Native JSON export compatible with Faraday v3/v4 server ingestion.
5. **Dradis Project Gateway JSON** (`dradis.json`): Project package template with structured issue nodes, evidence blocks, and remediation fields.

---

## 11. Standard of Proof & Evidence Classification

To ensure zero hallucination and complete auditability, REVENANT strictly enforces the following standard of proof across all reports and test suites:

- **`REAL-TOOL-vs-REAL-ENDPOINT`**: Tool binary was executed directly against a live target or live test server (e.g., Nmap against localhost, Velociraptor VQL queries against real endpoint).
- **`REAL-TOOL-vs-TEST-FILE`**: Tool binary was executed against a verified local file fixture (e.g., YARA against `sample_webshell.php`, Binwalk against synthetic firmware binary).
- **`PARSER-vs-SPEC`**: Parser and correlation logic tested against an official vendor schema/spec without spawning a multi-GB binary process (e.g., Volatility 3 memory dump analysis, CAPEv2 sandbox report intake, AFL++ crash triage).
- **Explicit Inclusions**: All supported tools are listed verbatim in this documentation; tools that were not integrated (e.g., Masscan, Amass, SQLmap, PyRIT, APKTool, Frida) are never reported.
