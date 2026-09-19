# REVENANT v2.0
**Autonomous Full-Spectrum AI Red Teaming & Security Operations Platform**

[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()
[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)]()
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.1.0-orange.svg)](docs/openapi-v2.0.json)
[![License](https://img.shields.io/badge/license-Proprietary%20%2F%20Authorized%20Use%20Only-red.svg)]()

REVENANT is an autonomous offensive security platform and appliance designed to execute authorized, full-spectrum security assessments across enterprise environments. Driven by a stigmergic multi-agent blackboard, REVENANT coordinates reconnaissance, web & API application testing, cloud & Kubernetes security posture, Active Directory identity auditing, binary forensics & triage, attack graph choke point synthesis, and automated IaC remediation generation.

> ⚠️ **Mandatory Authorization & Scope Gate:** REVENANT strictly refuses any target outside an authorized scope manifest. All scanning is validated by the Layer 1 Scope Manifest Engine before execution.

---

## ⚡ Quickstart

### 1. Appliance Deployment (Docker Compose)
```bash
# Navigate to deployment manifests
cd deployments/

# Copy and configure environment secrets
cp .env.example .env
nano .env

# Start all platform services (PostgreSQL+pgvector, Redis, Control Plane, Worker)
docker compose up -d

# Verify platform health
curl -s http://localhost:8000/api/v1/health | jq
```

### 2. Unified CLI Operations (`revenant.py`)
```bash
# List available standardized mission profiles
python revenant.py profiles

# Execute full-spectrum assessment
python revenant.py scan http://portal.corp.local --profile full-spectrum --scope scope.yaml --output ./evidence/

# Execute targeted Web / API DAST assessment
python revenant.py scan https://api.corp.local --profile web-dast --scope scope.yaml

# Generate autonomous remediation artifacts from findings
python revenant.py remediate ./evidence/findings.json --output ./remediation/

# External Attack Surface Management (ASM) drift detection
python revenant.py asm --target corp.local --inventory ./assets/current.json --baseline ./assets/baseline.json

# Start the REST API server locally
python revenant.py serve --host 0.0.0.0 --port 8000
```

---

## 🎯 Standard Mission Profiles

| Mission Profile | Target Type | Active Tools & Swarm Engines | Focus Areas |
|:---|:---|:---|:---|
| `recon` | Domain, CIDR, Host | Subfinder, Nmap, FFuf | Surface mapping, port scanning, virtual hosts, directory fuzzing. |
| `web-dast` | Web App, API Endpoint | Semgrep, Nuclei, Katana, Native DastAdapter, FFuf, Schemathesis | Web/API vulnerability discovery, XSS, open redirects, path traversal, stateful OpenAPI fuzzing. |
| `cloud-native` | Cloud Account, K8s Cluster | Trivy, Prowler, Checkov, Kubescape, Kube-bench, Falco | Cloud posture (AWS/Azure), container image CVEs, CIS benchmarks, K8s runtime anomalies. |
| `ad-identity` | Active Directory Domain / DC | NetExec, BloodHound, Certipy | Domain enumeration, Kerberoasting, AS-REP roasting, AD CS certificate misconfigurations (ESC1-ESC8). |
| `full-spectrum` | Enterprise Target / Hybrid | All Swarm Adapters + Attack Graph + Autonomous Remediation + SOAR | End-to-end multi-domain simulation: external discovery to lateral movement, choke points, and remediation. |

---

## 🏗️ Integrated Tool Suite

REVENANT integrates verified offensive and defensive security engines across 9 core domains:

- **Reconnaissance & Surface Mapping:** Subfinder, Nmap, FFuf
- **Web & API Security:** Semgrep (SAST), Nuclei (DAST templates), Katana (Web Crawling), Native DastAdapter (XSS/Redirect/Traversal Fuzzing), FFuf (Endpoint Fuzzing), Schemathesis (API Property Fuzzing)
- **Cloud Infrastructure Posture:** Trivy, Prowler, Checkov
- **Active Directory & Identity:** NetExec (NXC), BloodHound, Certipy
- **Purple Teaming & Threat Emulation:** Atomic Red Team (T1059, T1003, T1082), Caldera (Agent/Operation/Abilities)
- **Mobile Security:** Mobsfscan (Static Android/iOS), MobSF (Dynamic Analysis)
- **Kubernetes & Cloud Native:** Kubescape, Kube-bench (CIS K8s Benchmark), Falco (Runtime Anomaly Detection)
- **Forensics & Incident Response:** Volatility 3 (Memory Analysis), Velociraptor (VQL Endpoint Triage)
- **Malware, Binary & Firmware Triage:** YARA, CAPEv2, Binwalk, AFL++/ASan Crash Triage
- **Remediation & SOAR Integration:** Terraform, Ansible, Sigma, YARA, Splunk Phantom / Cortex XSOAR Webhooks

---

## 🛡️ Autonomous Remediation Engine

REVENANT automatically synthesizes tested remediation code for all confirmed vulnerabilities:
- **Terraform (`.tf`)**: S3 public access lockdowns, restrictive Security Group ingress rules, IAM least-privilege policies.
- **Kubernetes (`.yaml`)**: Default-deny ingress/egress `NetworkPolicy` manifests, PodSecurityStandards zero-trust patches.
- **Ansible (`.yml`)**: Windows SMBv1 deprecation & SMB packet signing enforcement, Linux SSH hardening & Telnet removal.
- **Detection Engineering**: Auto-generated **Sigma** rules for process injection/C2, auto-generated **YARA** rules for webshells/payloads.

---

## 📊 Enterprise Multi-Format Reporting

Mission results are exported directly into industry-standard vulnerability management and documentation formats:
- **Executive Markdown Report** (`report.md`)
- **OASIS SARIF v2.1.0** (`report.sarif`)
- **MITRE ATT&CK Navigator Layer v4.5** (`report.attack_nav.json`)
- **Faraday Vulnerability Management Platform** (`faraday.json`)
- **Dradis Project Gateway** (`dradis.json`)

---

## 📂 Repository Layout

```
D:\REVENANT\
├── control-plane/           # FastAPI REST API, schemas, scope enforcement, mission profiles
├── orchestrator/            # Stigmergic Blackboard, swarm orchestrator, ASM monitor, SOAR webhook, remediation
├── adapters/                # Verified per-tool Docker & execution wrappers
├── engines/                 # Domain engines (SAST, DAST, Cloud, Identity, Mobile, Purple, Forensics, Malware, Firmware)
├── intelligence/            # Attack Graph Engine, GraphRAG, choke point analysis
├── reporting/               # Markdown, SARIF, ATT&CK Navigator, Faraday & Dradis exporters
├── docker/                  # Hardened OCI Dockerfiles (control-plane, worker)
├── deployments/             # docker-compose.yml appliance manifest & .env.example
├── docs/                    # Architecture, PRD, Operator Guide, OpenAPI 3.1 JSON
├── tests/                   # Master test suite (234 unit, integration, and E2E tests)
└── revenant.py              # Unified CLI entrypoint
```

---

## 📖 Documentation
- [Operator Guide & Playbook](docs/OPERATOR_GUIDE.md)
- [System Architecture](docs/ARCHITECTURE.md)
- [OpenAPI 3.1 Specification](docs/openapi-v2.0.json)
- [Product Requirements Document](docs/PRD.md)

---

## ⚖️ Legal & Ethical Notice
Operate REVENANT exclusively against infrastructure and applications you own or are legally authorized to test under formal Rules of Engagement. Unauthorized penetration testing is illegal under computer misuse laws globally. REVENANT enforces cryptographic and programmatic scope validation at runtime, but the platform operator assumes all legal responsibility for mission execution.