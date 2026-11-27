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

### 2. Simple CLI — give a target, it attacks
```bash
pip install -e .                       # core install (just pydantic + requests)

revenant quickstart                    # zero-config demo against a bundled lab
revenant http://portal.corp.local      # give a target -> full-spectrum attack
revenant 10.0.0.0/24                   # works for a host, IP, or CIDR too
revenant doctor                        # what tools/capabilities this host has
```
Naming a target authorizes it: REVENANT auto-builds the scope from the target and
still refuses metadata/link-local/multicast ranges. Narrow or extend when you need to:
```bash
revenant web-target.local --profile web-dast          # pick a single profile
revenant scan https://api.corp.local --profile web-dast --allowed-domains api.corp.local

revenant remediate ./evidence/report.json --output-dir ./remediation/   # fixes from findings
revenant serve --host 0.0.0.0 --port 8000                               # REST API (needs [api] extra)
```

---

## 🧭 Two ways to run REVENANT

Both modes drive the **same `revenant` CLI** — only who types the commands differs.

### A) Manually in the terminal
```powershell
# Windows PowerShell, from the repo root:
.\.venv\Scripts\Activate.ps1          # activate the project venv  (prompt shows (.venv))
python -m pip install -e .            # first time only — installs the `revenant` command
revenant doctor
revenant <authorized-target> --profile recon --output-dir evidence/<name>-recon
```
If `revenant` is "not recognized", the venv isn't activated or the editable install
hasn't run. Either re-do the two steps above, or call the shim directly:
`.\.venv\Scripts\revenant.exe doctor`. On a fresh venv without `pip`, bootstrap it once
with `python -m ensurepip --upgrade`.

### B) Driven by an AI agent (Claude Code, Antigravity, Codex, Cursor)
The agent runs the exact same commands, reads the report files, and proposes next steps.
Each agent reads its instruction file on startup:

| Agent | Reads | 
|:---|:---|
| Claude Code | `CLAUDE.md` → points to `AGENTS.md` |
| Codex / Antigravity / Cursor | `AGENTS.md` (cross-agent standard) |

[`AGENTS.md`](AGENTS.md) is the single operator contract: setup, the canonical workflow,
profiles, env vars, and the **mandatory authorization gate** (agents must only scan a
target you own or are authorized to test, and must not bypass a scope refusal). Open the
repo in the agent and ask it to follow the workflow against an **authorized** target —
or `revenant quickstart` for a safe demo.

---

## 🧠 AI Reasoning Layer (optional)

REVENANT's core is deterministic and free. An **optional** LLM layer adds reasoning on
top — and it **degrades gracefully**: with no API key and the `anthropic` package not
installed, both features fall back to a deterministic template engine, never crash, and
never block a scan (same philosophy as the native fuzzers working without a binary).

```bash
pip install -e .[llm]          # adds the anthropic SDK (core stays pydantic + requests)
export ANTHROPIC_API_KEY=...    # optional — without it, deterministic fallback is used
```

**1. Analyst / Narrator** — post-campaign enrichment. After any scan with findings,
REVENANT writes `analysis.md` + `analysis.json` next to the report with four sections:
per-finding **Mechanism / Impact / Fix**, **attack-path prediction** (findings chained
into kill-chains with confidence + blast radius), **prioritized next steps**, and a
CISO-language **executive summary**. Run it standalone over any findings export:

```bash
revenant analyze evidence/quickstart/report.json          # prints + writes analysis.md/json
```

**2. LLM Planner agent** — in-swarm reasoning. An opt-in agent that triggers on
high-signal events (confirmed vulns, misconfigurations, privesc paths, new endpoints)
and on campaign completion, asks the model for the single best next action, and records
it as an informational finding in the report. It **never invents targets** — any action
it suggests must reference an asset already on the blackboard and still passes the
3-layer scope gate.

```bash
revenant web-target.local --profile ai-reasoning          # web-dast + the planner
revenant scan https://api.corp.local --llm-planner        # add the planner to any scan
revenant doctor                                           # shows the LLM layer status
```

| Env var | Default | Purpose |
|:---|:---|:---|
| `ANTHROPIC_API_KEY` | *(unset)* | Enables the LLM path; unset → deterministic fallback. |
| `REVENANT_LLM_MODEL` | `claude-sonnet-4-5` | Model id for both features. |
| `REVENANT_PLANNER_BUDGET` | `5` | Max planner reasoning calls per campaign (cost cap). |

---

## 🎯 Standard Mission Profiles

| Mission Profile | Target Type | Active Tools & Swarm Engines | Focus Areas |
|:---|:---|:---|:---|
| `recon` | Domain, CIDR, Host | Subfinder, Nmap, FFuf | Surface mapping, port scanning, virtual hosts, directory fuzzing. |
| `web-dast` | Web App, API Endpoint | Semgrep, Nuclei, Katana, Native DastAdapter, FFuf, Schemathesis | Web/API vulnerability discovery, XSS, open redirects, path traversal, stateful OpenAPI fuzzing. |
| `cloud-native` | Cloud Account, K8s Cluster | Trivy, Prowler, Checkov, Kubescape, Kube-bench, Falco | Cloud posture (AWS/Azure), container image CVEs, CIS benchmarks, K8s runtime anomalies. |
| `ad-identity` | Active Directory Domain / DC | NetExec, BloodHound, Certipy | Domain enumeration, Kerberoasting, AS-REP roasting, AD CS certificate misconfigurations (ESC1-ESC8). |
| `ai-reasoning` | Web App, API Endpoint | web-dast swarm + LLM Planner agent | Dynamic web testing augmented with in-swarm LLM next-action reasoning (opt-in; needs `[llm]` + key, else heuristic). |
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