# REVENANT — Product Requirements Document

**Version:** 1.0
**Date:** 2026-09-15
**Status:** Draft
**Author:** REVENANT Team

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Solution Overview](#3-solution-overview)
4. [User Personas](#4-user-personas)
5. [Core Objectives & Success Metrics](#5-core-objectives--success-metrics)
6. [Scope & Capability Domains](#6-scope--capability-domains)
7. [Platform Architecture](#7-platform-architecture)
8. [Feature Requirements](#8-feature-requirements)
9. [Integration Map — Tool → Domain](#9-integration-map--tool--domain)
10. [Technical Requirements](#10-technical-requirements)
11. [Security & Authorization Model](#11-security--authorization-model)
12. [Phased Rollout](#12-phased-rollout)
13. [Risks & Mitigations](#13-risks--mitigations)
14. [Dependencies](#14-dependencies)
15. [Open Questions](#15-open-questions)
16. [Appendix](#16-appendix)

---

## 1. Executive Summary

**REVENANT** is an AI-driven autonomous red teaming platform that unifies 66 security tools across 37 capability domains under a single, intelligent orchestration layer. It autonomously plans, executes, and reports security assessments — from reconnaissance through exploitation and reporting — while strictly enforcing authorization scope.

REVENANT transforms how security assessments are conducted by combining:

- **A multi-agent AI brain** (stigmergic swarm architecture) that autonomously decides what to test, why, and with which tool
- **66 integrated security tools** covering every discipline a white-hat hacker needs
- **37 capability domains** spanning the full attack lifecycle
- **Strict scope enforcement** — tested, authorized targets only — enforced at three layers
- **An autonomous security loop** that continuously discovers, maps, analyzes, tests, validates, and reports

The platform is built on a fork of [Pentest Swarm AI](https://github.com/Armur-Ai/Pentest-Swarm-AI), extending its existing 35+ tool adapters and stigmergic swarm with additional agents and tools to achieve full-spectrum coverage.

---

## 2. Problem Statement

### The current state of security testing

Security assessments today suffer from:

1. **Tool fragmentation.** A typical engagement requires 15-30 separate tools, each with its own interface, output format, and workflow. Correlating results across tools is manual, error-prone, and time-consuming.

2. **Expertise bottleneck.** Autonomous pentesting requires deep knowledge across dozens of disciplines (network, web, cloud, AD, mobile, firmware, AI). Finding and retaining professionals who can operate across all these domains is difficult and expensive.

3. **Repeatability crisis.** Manual assessments are inconsistent. Two testers with different skill sets will find different things. There's no standard for ensuring comprehensive coverage.

4. **Speed.** A thorough engagement takes weeks to months. Attack surfaces change faster than assessments can be completed.

5. **Scope management.** Without automated enforcement, scope creep is a constant risk — both under-testing (missing assets) and over-testing (touching unauthorized targets).

### What the market needs

An autonomous platform that:

- **Thinks like an attacker** — uses AI to plan attack chains, not just run individual tools
- **Works at machine speed** — parallel scanning, automated correlation, instant triage
- **Covers everything** — network, web, cloud, AD, mobile, firmware, AI/LLM, and more
- **Stays authorized** — enforces scope at every layer, refuses unauthorized actions
- **Produces actionable reports** — evidence-backed findings with remediation guidance

---

## 3. Solution Overview

### What REVENANT is

REVENANT is an **AI-driven autonomous red teaming platform** that:

1. **Takes a target scope** (domains, IPs, CIDRs, URLs, cloud accounts, or bug bounty programs)
2. **Autonomously plans** a comprehensive assessment strategy using AI
3. **Dispatches specialized agents** that run the right tools at the right time
4. **Correlates and triages** findings across all tools using AI
5. **Validates findings** to eliminate false positives
6. **Generates comprehensive reports** with evidence, risk scores, and remediation

### What REVENANT is NOT

- A vulnerability scanner (it's an orchestration platform that uses scanners)
- A replacement for human judgment (it augments and accelerates)
- A weapon (it enforces authorization at every layer)
- A SaaS-only product (it can run locally, on-prem, or in the cloud)

### Core Concept: The Autonomous Security Loop

REVENANT operates on a continuous loop:

```
DISCOVER → MAP → ANALYZE → PRIORITIZE → TEST → VALIDATE
    ↕                                              ↕
 RETEST ← REMEDIATE ← REPORT ← DETECT ← CORRELATE ← EXPLOIT-SIMULATE
```

Each phase is an **engine** that owns a family of tools. The AI orchestrator decides when to move between phases, when to dig deeper, and when to move on.

---

## 4. User Personas

### 4.1 Security Consultant / Pentester

**Role:** Professional conducting authorized assessments
**Needs:** Comprehensive coverage, evidence-backed findings, fast turnaround, multi-domain expertise
**How REVENANT helps:** Automates reconnaissance, tool execution, and initial triage. Frees the tester to focus on judgment, complex exploitation, and client communication.

### 4.2 Bug Bounty Hunter

**Role:** Independent researcher finding vulnerabilities in scope
**Needs:** Fast recon, automated scanning, program scope compliance, reproducible PoCs
**How REVENANT helps:** Ingests program scopes (HackerOne/Bugcrowd/Intigriti), runs full recon + scanning + validation pipelines, generates reproducible evidence packages.

### 4.3 Security Team Lead / CISO

**Role:** Managing organizational security posture
**Needs:** Continuous visibility, coverage metrics, risk quantification, compliance evidence
**How REVENANT helps:** Continuous attack surface monitoring, MITRE ATT&CK coverage mapping, executive dashboards, compliance reporting.

### 4.4 Red Team Operator

**Role:** Adversary emulation and purple team exercises
**Needs:** ATT&CK-mapped attack paths, adversary emulation, detection validation
**How REVENANT helps:** Caldera/Atomic Red Team integration, attack graph generation, detection gap analysis, purple team automation.

### 4.5 Security Researcher

**Role:** Vulnerability research and zero-day discovery
**Needs:** Deep tool access, fuzzing capabilities, custom tool integration
**How REVENANT helps:** AFL++/libFuzzer integration, custom tool support, full evidence capture, reproducible environments.

### 4.6 AI/ML Security Engineer

**Role:** Testing AI/LLM systems for vulnerabilities
**Needs:** Prompt injection testing, jailbreak evaluation, agent security, RAG testing
**How REVENANT helps:** PyRIT, garak, AgentDojo, promptfoo, DeepTeam integration. Dedicated AI/LLM red teaming agent.

---

## 5. Core Objectives & Success Metrics

### 5.1 Primary Objectives

| # | Objective | Metric | Target |
|---|---|---|---|
| O1 | **Comprehensive coverage** | Capability domains covered (out of 37) | 37/37 at v2.0 |
| O2 | **Autonomous operation** | % of assessment completed without human intervention | ≥80% at v1.0, ≥95% at v2.0 |
| O3 | **Speed** | Time for full assessment (medium target) | <2 hours at v1.0, <30 min at v2.0 |
| O4 | **Accuracy** | False positive rate in reported findings | ≤10% at v1.0, ≤5% at v2.0 |
| O5 | **Scope compliance** | Unauthorized actions attempted | 0 — always |
| O6 | **Actionability** | Findings with evidence + remediation | 100% |
| O7 | **Tool breadth** | Security tools integrated | 30+ at v1.0, 60+ at v2.0 |

### 5.2 Secondary Metrics

| Metric | Target |
|---|---|
| MITRE ATT&CK technique coverage | ≥60% at v1.0 |
| Mean time to first finding | <5 minutes |
| Findings per assessment (medium target) | 5-50 (high precision, not noise) |
| Report generation time | <2 minutes |
| Platform cold start (Docker) | <3 minutes |
| Resource usage (idle) | <2GB RAM |
| Resource usage (active) | <8GB RAM |

### 5.3 Non-Goals (explicitly NOT building at v1.0)

- Real-time network intrusion detection (not an IDS)
- Commercial product pricing/licensing (open platform first)
- Mobile app (web UI only at v1.0)
- SOC/SIEM replacement (feeds data INTO existing SIEMs)
- Physical security testing
- Social engineering automation (out of scope for v1.0)

---

## 6. Scope & Capability Domains

REVENANT covers 37 capability domains across the full security assessment lifecycle. Each domain maps to one or more specialized agents and tool families.

### Domain Inventory

| # | Domain | Description | Key Tools |
|---|---|---|---|
| 1 | **Reconnaissance** | Passive/active recon, OSINT, domain/subdomain enumeration | Amass, Subfinder, Katana, Shodan |
| 2 | **Network Security** | Port scanning, service enumeration, network mapping | Nmap, Naabu, httpx |
| 3 | **Web Application Security** | Web vulns, injection, auth, business logic | Nuclei, ZAP, ffuf, sqlmap |
| 4 | **API Security** | REST/GraphQL/SOAP testing, JWT, OAuth, schema fuzzing | Schemathesis, ffuf, custom |
| 5 | **Cloud Security** | AWS/Azure/GCP posture, IAM, storage, attack paths | Prowler, ScoutSuite, CloudFox |
| 6 | **Active Directory / Windows** | AD enumeration, Kerberos, privilege escalation paths | BloodHound, NetExec, Certipy |
| 7 | **Linux Security** | Privilege escalation, kernel exposure, capability analysis | PEASS-ng, Linux Exploit Suggester |
| 8 | **Mobile Security** | Android/iOS static/dynamic analysis | MobSF, mobsfscan |
| 9 | **Source Code Security** | SAST, secrets, dependencies, supply chain | Semgrep, CodeQL, Gitleaks |
| 10 | **Vulnerability Intelligence** | CVE correlation, CVSS, exploitability, prioritization | Nuclei templates, custom engine |
| 11 | **Fuzzing** | HTTP/API/protocol/binary fuzzing | AFL++, libFuzzer, ffuf, Schemathesis |
| 12 | **Exploit Validation** | PoC generation, exploitability verification | Metasploit, Impacket, Shannon |
| 13 | **Red Team Operations** | Target profiling, attack planning, full-chain simulation | Caldera, Atomic Red Team, custom |
| 14 | **Adversary Emulation** | MITRE ATT&CK-based emulation, TTP simulation | Caldera, Atomic Red Team, attack-stix-data |
| 15 | **Social Engineering Sim** | Phishing, pretexting, awareness testing | Out of scope v1.0 |
| 16 | **Wireless Security** | Wi-Fi recon, rogue AP, Bluetooth | Out of scope v1.0 (tooling constraint) |
| 17 | **IoT / Embedded** | Firmware analysis, extraction, emulation | Binwalk, FirmAE |
| 18 | **Container / K8s Security** | Image scanning, K8s posture, runtime detection | Trivy, Kubescape, Falco, kube-bench |
| 19 | **CI/CD / DevSecOps** | Pipeline security, secret detection, IaC scanning | Trivy, Gitleaks, Checkov |
| 20 | **Credential Security** | Secret exposure, credential reuse, hash analysis | Gitleaks, TruffleHog, custom |
| 21 | **AI / LLM Red Teaming** | Prompt injection, jailbreak, agent hijacking, RAG testing | PyRIT, garak, AgentDojo, promptfoo, DeepTeam |
| 22 | **Autonomous Security Agents** | Individual specialist agents for each domain | Custom per domain |
| 23 | **Multi-Agent Operations** | Agent delegation, collaboration, memory, task queues | Pentest Swarm AI swarm engine |
| 24 | **Attack-Path Intelligence** | Attack graphs, privilege chains, critical path ID | BloodHound, CloudFox, custom graph |
| 25 | **Detection Engineering** | SIEM/EDR/XDR testing, rule validation, gap analysis | Sigma, YARA, Falco |
| 26 | **Purple Team Automation** | Attack + detection verification loops | Caldera + Sigma + custom |
| 27 | **Digital Forensics** | Log analysis, timeline, artifact analysis | Velociraptor, Volatility3 |
| 28 | **Malware Analysis** | Static/dynamic analysis, behavioral analysis, sandbox | CAPEv2, YARA |
| 29 | **Threat Intelligence** | IOC collection, threat actor profiling, campaign tracking | MISP, OpenCTI (optional) |
| 30 | **Security Automation** | Automated scanning, evidence collection, reporting | Platform core |
| 31 | **Workflow Orchestration** | Tool integration, parallel execution, result correlation | Pentest Swarm AI coordinator |
| 32 | **Evidence & Reporting** | Vulnerability/exec/technical reports, PoC evidence | Faraday/Dradis/custom |
| 33 | **Compliance Validation** | OWASP/MITRE/NIST/CIS/PCI mapping | Custom engine |
| 34 | **Continuous ASM** | Asset monitoring, exposure detection, drift alerts | Pentest Swarm AI ASM module |
| 35 | **CTF / Lab Automation** | CTF challenge solving, lab environment testing | Playbooks |
| 36 | **Bug Bounty Operations** | Program scope import, automated recon-to-report | Scope module + playbooks |
| 37 | **Security Research** | Zero-day research, custom tool execution, reproducibility | Custom + full tool access |

---

## 7. Platform Architecture

### 7.1 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    REVENANT CONTROL PLANE                            │
│   Web Dashboard (Next.js 15) · REST API (GoFiber) · AuthN/AuthZ    │
│   Job Queue · Scope Enforcement · Evidence Store · Audit Log        │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────────┐
│              AI ORCHESTRATOR (STIGMERGIC SWARM)                     │
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │
│  │  Planner    │  │  Delegator  │  │  Correlator │                │
│  │  (LLM)      │  │  (Scheduler)│  │  (LLM)      │                │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                │
│         │                │                │                         │
│  ┌──────▼────────────────▼────────────────▼──────┐                 │
│  │              BLACKBOARD (Postgres + pgvector)   │                 │
│  │   Findings · Pheromone Decay · Cursor Delivery  │                 │
│  └────────────────────────────────────────────────┘                 │
│                                                                     │
│  ┌───────────────────────────────────────────────────────┐         │
│  │              SPECIALIST AGENTS                         │         │
│  │  recon · classifier · exploit · web · api · cloud     │         │
│  │  ad · linux · mobile · code · ai-llm · fuzzing        │         │
│  │  forensics · malware · purple · detection · report    │         │
│  │  confirm · nuclei-author · burp · attack-path · osint │         │
│  └───────────────────────────────────────────────────────┘         │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────────┐
│              TOOL ADAPTER LAYER                                      │
│   Uniform JSON-in / JSON-out wrappers · Docker isolation             │
│   Scope enforcement · Resource limits · Egress policy                │
│                                                                     │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐          │
│  │ RECON  │ │ WEB/   │ │ CLOUD  │ │   AD   │ │ AI/LLM │          │
│  │        │ │ API    │ │        │ │        │ │        │           │
│  │Amass   │ │Nuclei  │ │Prowler │ │BloodHd │ │PyRIT   │          │
│  │Subfndr │ │ZAP     │ │ScoutSq │ │NetExec │ │garak   │          │
│  │httpx   │ │ffuf    │ │CloudFox│ │Certipy │ │AgentDj │          │
│  │naabu   │ │Katana  │ │Trivy   │ │PEASS   │ │promptf │          │
│  │Nmap    │ │Schemth │ │Checkov │ │LnxExpS │ │DeepTm  │          │
│  │Katana  │ │sqlmap  │ │        │ │        │ │        │           │
│  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘          │
│                                                                     │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐          │
│  │FUZZING │ │ FOREN  │ │MALWARE │ │DETECT  │ │ PURPLE │          │
│  │AFL++   │ │Veloci  │ │CAPEv2  │ │Sigma   │ │Caldera │          │
│  │libFuz  │ │Volat3  │ │YARA    │ │YARA    │ │AtmcRedT│          │
│  │        │ │        │ │        │ │Falco   │ │        │           │
│  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘          │
│                                                                     │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐                      │
│  │MOBILE  │ │  IoT   │ │  K8s   │ │REPORT  │                      │
│  │MobSF   │ │Binwalk │ │Trivy   │ │Faraday │                      │
│  │mobsfsca│ │FirmAE  │ │Kubescp │ │Dradis  │                      │
│  │        │ │        │ │kube-bn │ │custom  │                      │
│  │        │ │        │ │Falco   │ │        │                      │
│  └────────┘ └────────┘ └────────┘ └────────┘                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 7.2 Component Responsibilities

| Component | Technology | Responsibility |
|---|---|---|
| **Control Plane** | Go (GoFiber v2) | API, auth, job management, scope enforcement, evidence storage, audit |
| **Web Dashboard** | Next.js 15 + shadcn/ui | Mission management, live progress, reports, attack graphs |
| **AI Orchestrator** | Pentest Swarm AI swarm engine | Autonomous planning, agent dispatch, correlation, triage |
| **Blackboard** | PostgreSQL 16 + pgvector | Shared state, findings, pheromone decay, cursor delivery |
| **Tool Adapter Layer** | Go + Docker | Tool execution, isolation, scope enforcement, result normalization |
| **Evidence Store** | PostgreSQL + object storage | Tamper-evident findings, screenshots, HTTP captures, terminal logs |

### 7.3 The Stigmergic Swarm Model

The AI brain uses a **stigmergic** (environment-mediated) communication pattern:

1. The orchestrator seeds the blackboard with a `TARGET_REGISTERED` finding
2. Each agent watches the blackboard for findings matching its trigger predicate
3. When a matching finding appears, the agent processes it and writes new findings back
4. New findings trigger downstream agents — creating autonomous, emergent workflows
5. Pheromone decay ensures stale paths lose priority and naturally die
6. Budget limits and idle timeouts prevent runaway execution

**Agents never call each other directly.** All communication flows through the shared blackboard.

### 7.4 Tool Adapter Contract

Every tool implements a standard interface:

```json
{
  "id": "tool-name",
  "version": "1.0.0",
  "kind": "scanner|exploiter|analyzer|generator",
  "capabilities": ["web", "network", "cloud", ...],
  "scope_required": true,
  "max_concurrent": 5,
  "timeout_seconds": 300,
  "inputs": { "schema": "..." },
  "outputs": { "schema": "..." }
}
```

The adapter handles: Docker image lifecycle, TTL enforcement, resource limits, non-root execution, network egress policy, scope validation, and artifact upload.

### 7.5 Standard Finding Schema

All tools normalize their output into a single finding schema:

```json
{
  "id": "uuid",
  "tool_id": "nuclei",
  "target": "https://example.com",
  "type": "vulnerability|misconfiguration|exposure|info",
  "severity": "critical|high|medium|low|info",
  "confidence": 0.95,
  "cwe": "CWE-89",
  "cve": "CVE-2024-xxxx",
  "attck_technique": "T1190",
  "attck_tactic": "initial-access",
  "title": "SQL Injection in login endpoint",
  "description": "...",
  "evidence": {
    "raw_output": "...",
    "request": "GET /api/login?q=' OR 1=1...",
    "response": "HTTP/1.1 200 OK...",
    "screenshot": "path/to/screenshot.png",
    "reproduction_steps": ["..."]
  },
  "remediation": "...",
  "references": ["..."],
  "metadata": {},
  "created_at": "2026-09-15T12:00:00Z"
}
```

---

## 8. Feature Requirements

### 8.1 Mission Management

| ID | Feature | Priority | Phase |
|---|---|---|---|
| F-001 | Create mission with target scope (domains, IPs, URLs, CIDRs) | P0 | v1.0 |
| F-002 | Import program scopes from HackerOne/Bugcrowd/Intigriti | P0 | v1.0 |
| F-003 | Define assessment type (full, recon-only, web, cloud, AD, etc.) | P0 | v1.0 |
| F-004 | Set budget limits (time, tokens, cost) | P0 | v1.0 |
| F-005 | Pause/resume missions | P1 | v1.0 |
| F-006 | Mission templates (repeatable assessment profiles) | P1 | v1.1 |
| F-007 | Scheduled/continuous assessments | P2 | v2.0 |

### 8.2 Scope Enforcement

| ID | Feature | Priority | Phase |
|---|---|---|---|
| F-010 | Scope manifest validation (3 layers) | P0 | v1.0 |
| F-011 | Refuse actions against out-of-scope targets | P0 | v1.0 |
| F-012 | Scope diff/change detection | P1 | v1.0 |
| F-013 | Scope import from program platforms | P0 | v1.0 |
| F-014 | Scope audit log | P0 | v1.0 |

### 8.3 Autonomous Scanning

| ID | Feature | Priority | Phase |
|---|---|---|---|
| F-020 | Autonomous recon (passive + active) | P0 | v1.0 |
| F-021 | Autonomous web vulnerability scanning | P0 | v1.0 |
| F-022 | Autonomous API security testing | P1 | v1.0 |
| F-023 | Autonomous cloud security assessment | P1 | v1.1 |
| F-024 | Autonomous AD security assessment | P1 | v1.1 |
| F-025 | Autonomous source code analysis | P1 | v1.1 |
| F-026 | Autonomous container/K8s scanning | P2 | v1.2 |
| F-027 | Autonomous mobile app analysis | P2 | v1.2 |
| F-028 | Autonomous AI/LLM red teaming | P2 | v1.2 |
| F-029 | Autonomous firmware analysis | P3 | v2.0 |
| F-030 | Autonomous purple team exercises | P3 | v2.0 |

### 8.4 AI Intelligence

| ID | Feature | Priority | Phase |
|---|---|---|---|
| F-040 | AI-driven attack path planning | P0 | v1.0 |
| F-041 | AI-driven finding correlation | P0 | v1.0 |
| F-042 | AI-driven false positive elimination | P0 | v1.0 |
| F-043 | AI-driven severity/priority scoring | P0 | v1.0 |
| F-044 | AI-driven remediation generation | P1 | v1.0 |
| F-045 | AI-driven attack graph construction | P1 | v1.1 |
| F-046 | Multi-model support (Claude, GPT, Gemini, Ollama) | P0 | v1.0 |
| F-047 | Budget-aware LLM usage (prompt caching, model selection) | P1 | v1.0 |

### 8.5 Reporting

| ID | Feature | Priority | Phase |
|---|---|---|---|
| F-050 | Technical vulnerability report (per finding) | P0 | v1.0 |
| F-051 | Executive summary report | P0 | v1.0 |
| F-052 | Evidence package (raw output, screenshots, repro steps) | P0 | v1.0 |
| F-053 | SARIF output | P1 | v1.1 |
| F-054 | MITRE ATT&CK coverage report | P1 | v1.1 |
| F-055 | Compliance mapping (OWASP/NIST/CIS) | P2 | v1.2 |
| F-056 | Attack graph visualization | P2 | v1.2 |
| F-057 | JSON/CSV export | P1 | v1.0 |

### 8.6 Dashboard & UI

| ID | Feature | Priority | Phase |
|---|---|---|---|
| F-060 | Mission overview dashboard | P0 | v1.0 |
| F-061 | Real-time scan progress | P0 | v1.0 |
| F-062 | Findings browser (filter, sort, search) | P0 | v1.0 |
| F-063 | Agent activity view (what each agent is doing) | P1 | v1.0 |
| F-064 | Attack graph visualization | P2 | v1.2 |
| F-065 | Historical mission comparison | P2 | v2.0 |
| F-066 | Dark/light theme | P1 | v1.0 |

### 8.7 Security & Access Control

| ID | Feature | Priority | Phase |
|---|---|---|---|
| F-070 | Role-based access control (admin/operator/auditor) | P0 | v1.0 |
| F-071 | API key authentication | P0 | v1.0 |
| F-072 | Audit logging (who/what/when/target/result) | P0 | v1.0 |
| F-073 | Tamper-evident evidence hashing | P1 | v1.1 |
| F-074 | SSO/OIDC integration | P2 | v2.0 |

---

## 9. Integration Map — Tool → Domain

### 9.1 Tools by Domain

#### Reconnaissance (Domain 1)
| Tool | Type | Phase |
|---|---|---|
| OWASP Amass | Attack surface mapping, DNS, OSINT | v1.0 |
| Subfinder | Passive subdomain enumeration | v1.0 |
| httpx | HTTP probing, technology detection | v1.0 |
| Naabu | Port scanning, network discovery | v1.0 |
| Katana | Web crawling, endpoint discovery | v1.0 |
| Nmap | Network discovery, service enumeration | v1.0 |

#### Web / API Security (Domains 3, 4)
| Tool | Type | Phase |
|---|---|---|
| Nuclei | Template-based vulnerability detection | v1.0 |
| OWASP ZAP | Web proxy, active/passive scanning | v1.0 |
| ffuf | Web fuzzing, directory/parameter discovery | v1.0 |
| Schemathesis | API fuzzing, property-based testing | v1.0 |
| Shannon | White-box web/API pentesting | v1.1 |
| Strix | Autonomous AI pentesting, browser testing | v1.1 |

#### Exploitation / Validation (Domain 12)
| Tool | Type | Phase |
|---|---|---|
| Metasploit Framework | Exploit research, vulnerability validation | v1.0 |
| Impacket | Windows/network protocol testing | v1.0 |

#### Active Directory / Windows (Domain 6)
| Tool | Type | Phase |
|---|---|---|
| BloodHound | Identity mapping, attack path analysis | v1.0 |
| NetExec | AD assessment, enumeration | v1.0 |
| Certipy | AD Certificate Services assessment | v1.1 |

#### Cloud Security (Domain 5)
| Tool | Type | Phase |
|---|---|---|
| Prowler | AWS security posture, compliance | v1.0 |
| ScoutSuite | Multi-cloud security auditing | v1.1 |
| CloudFox | Cloud attack surface analysis | v1.1 |

#### Source Code Security (Domain 9)
| Tool | Type | Phase |
|---|---|---|
| Semgrep | Static analysis, vulnerability detection | v1.0 |
| CodeQL | Deep semantic source analysis | v1.1 |
| Gitleaks | Git secret detection | v1.0 |
| TruffleHog | Secret discovery | v1.0 |

#### Container / Kubernetes (Domain 18)
| Tool | Type | Phase |
|---|---|---|
| Trivy | Container, dependency, K8s scanning | v1.0 |
| Kubescape | K8s security posture | v1.2 |
| kube-bench | K8s CIS benchmarks | v1.2 |
| Falco | Runtime threat detection | v2.0 |

#### Mobile Security (Domain 8)
| Tool | Type | Phase |
|---|---|---|
| MobSF | Android/iOS static/dynamic analysis | v1.2 |
| mobsfscan | Mobile source-code scanning | v1.2 |

#### AI / LLM Red Teaming (Domain 21)
| Tool | Type | Phase |
|---|---|---|
| PyRIT | AI/LLM red teaming, adversarial testing | v1.2 |
| garak | LLM vulnerability probing | v1.2 |
| AgentDojo | LLM agent security evaluation | v1.2 |
| DeepTeam | LLM red-team testing | v1.2 |
| promptfoo | LLM security testing, CI/CD regression | v1.2 |

#### Adversary Emulation / Purple Team (Domains 13, 14, 26)
| Tool | Type | Phase |
|---|---|---|
| MITRE Caldera | Automated adversary emulation | v2.0 |
| Atomic Red Team | ATT&CK-based simulations | v2.0 |
| attack-stix-data | Machine-readable ATT&CK knowledge | v1.1 |

#### Detection Engineering (Domain 25)
| Tool | Type | Phase |
|---|---|---|
| Sigma | SIEM detection rules | v2.0 |
| YARA | Malware/file pattern detection | v2.0 |

#### Digital Forensics (Domain 27)
| Tool | Type | Phase |
|---|---|---|
| Velociraptor | Endpoint forensics, incident investigation | v2.0 |
| Volatility3 | Memory forensics | v2.0 |

#### Malware Analysis (Domain 28)
| Tool | Type | Phase |
|---|---|---|
| CAPEv2 | Automated malware sandboxing | v2.0 |

#### Fuzzing (Domain 11)
| Tool | Type | Phase |
|---|---|---|
| AFL++ | Coverage-guided binary fuzzing | v2.0 |
| libFuzzer / LLVM | In-process fuzzing | v2.0 |

#### IoT / Embedded (Domain 17)
| Tool | Type | Phase |
|---|---|---|
| Binwalk | Firmware analysis, extraction | v2.0 |
| FirmAE | Firmware emulation | v2.0 |

#### Linux Security (Domain 7)
| Tool | Type | Phase |
|---|---|---|
| PEASS-ng | Privilege escalation enumeration | v1.1 |
| Linux Exploit Suggester | Local vulnerability enumeration | v1.1 |

#### Threat Intelligence (Domain 29)
| Tool | Type | Phase |
|---|---|---|
| MISP | Threat intelligence sharing | v2.0 |
| OpenCTI | Threat intelligence knowledge graph | v2.0 |

#### Security Reporting (Domain 32)
| Tool | Type | Phase |
|---|---|---|
| Faraday | Collaborative pentest management | v1.1 |
| Dradis CE | Pentest collaboration, reporting | v1.1 |

#### Security Knowledge (Cross-cutting)
| Tool | Type | Phase |
|---|---|---|
| Anthropic Cybersecurity Skills | Security methodologies for AI agents | v1.0 |
| Claude-Red | Offensive security skills for AI | v1.0 |

### 9.2 Tool Count by Phase

| Phase | New Tools | Cumulative |
|---|---|---|
| v1.0 | ~25 (Pentest Swarm AI baseline + key additions) | ~25 |
| v1.1 | ~10 (cloud, AD, code, reporting depth) | ~35 |
| v1.2 | ~10 (mobile, AI/LLM, K8s) | ~45 |
| v2.0 | ~15 (forensics, malware, fuzzing, IoT, purple team, threat intel) | ~60+ |

---

## 10. Technical Requirements

### 10.1 Infrastructure

| Requirement | Specification |
|---|---|
| **Minimum server** | 4 vCPU, 16GB RAM, 100GB SSD |
| **Recommended server** | 8 vCPU, 32GB RAM, 500GB SSD |
| **Operating system** | Ubuntu 22.04 LTS (primary), Debian 12, AlmaLinux 9 |
| **Container runtime** | Docker 24+ with Docker Compose v2 |
| **Kubernetes** | Supported for v2.0 (Helm charts available) |
| **Network** | Outbound internet access required (tool downloads, API calls) |

### 10.2 Software Dependencies

| Component | Version | Purpose |
|---|---|---|
| Go | 1.24+ | Core platform (Pentest Swarm AI) |
| Python | 3.11+ | Tool wrappers, ML components |
| Node.js | 20+ | Next.js dashboard |
| PostgreSQL | 16+ | Blackboard, evidence store |
| pgvector | 0.7+ | Semantic search, finding similarity |
| Redis | 7+ | Caching, job queue |
| Docker | 24+ | Tool isolation |

### 10.3 Performance Requirements

| Metric | Target |
|---|---|
| Platform startup | <3 minutes (Docker Compose) |
| Mission creation to first finding | <5 minutes |
| Full recon scan (medium target) | <15 minutes |
| Full assessment (medium target) | <2 hours |
| Findings processing throughput | 100+ findings/minute |
| Dashboard refresh rate | <5 seconds (WebSocket) |
| API response time (p95) | <200ms |
| Concurrent missions | 3-5 (depending on server size) |

### 10.4 Reliability Requirements

| Requirement | Target |
|---|---|
| Platform availability | 99.5% (self-hosted) |
| Mission completion rate | >95% (no crashes mid-mission) |
| Data durability | PostgreSQL backups + WAL archiving |
| Graceful degradation | If an agent fails, others continue |
| Recovery time | <5 minutes (restart from checkpoint) |

---

## 11. Security & Authorization Model

### 11.1 Scope Enforcement (3-Layer Defense)

```
┌─────────────────────────────────────────┐
│ LAYER 1: Control Plane                   │
│ Mission scope manifest validated on      │
│ creation. Targets added to allowlist.    │
│ Out-of-scope targets → refused.          │
└──────────────────────┬──────────────────┘
                       │
┌──────────────────────▼──────────────────┐
│ LAYER 2: Orchestrator                    │
│ AI agent trigger predicates include      │
│ scope filter. Agent won't dispatch to    │
│ targets not in scope.                    │
└──────────────────────┬──────────────────┘
                       │
┌──────────────────────▼──────────────────┐
│ LAYER 3: Tool Adapter                    │
│ Every tool adapter validates target      │
│ against scope before execution.          │
│ Defense in depth — even if layers 1-2    │
│ fail, the tool won't run.                │
└─────────────────────────────────────────┘
```

### 11.2 Authorization Principles

1. **Explicit authorization required.** Every mission requires a scope manifest declaring allowed targets.
2. **No implicit trust.** Being in scope for one mission doesn't grant scope for another.
3. **Defense in depth.** Scope checked at control plane, orchestrator, AND adapter.
4. **Audit everything.** Every scope check result is logged (allowed or denied).
5. **Safe by default.** Destructive actions (exploitation) require explicit opt-in.

### 11.3 Non-Destructive Mode

By default, REVENANT operates in **safe mode**:

- No exploitation of live systems (detection/analysis only)
- No credential theft outside scope
- No persistence mechanisms
- No data exfiltration
- No denial-of-service actions
- All actions logged with full evidence

Destructive/safe mode can be toggled per-mission by authorized operators.

### 11.4 Data Security

| Concern | Mitigation |
|---|---|
| Evidence at rest | PostgreSQL encryption + disk encryption |
| Evidence in transit | TLS 1.3 for all connections |
| API authentication | API keys + RBAC |
| Audit log tampering | Hash chain verification |
| LLM API keys | Stored in OS keychain (go-keyring) |
| Tool credentials | Scoped per-mission, revoked after |

---

## 12. Phased Rollout

### Phase 1 — Foundation (Weeks 1-4)

**Goal:** Working platform with autonomous recon + web scanning + reporting.

| Week | Deliverable |
|---|---|
| 1 | Fork Pentest Swarm AI, Docker environment, verify against lab targets |
| 1 | Scope enforcement hardening, control plane API |
| 2 | Add missing tool adapters (Metasploit, Impacket, ZAP integration) |
| 2 | Enhanced reporting engine (evidence packages, executive summary) |
| 3 | Dashboard polish (live progress, findings browser, agent activity) |
| 3 | Playbook library expansion (CTF, bug bounty, internal network) |
| 4 | Integration testing, documentation, deployment scripts |
| 4 | **v1.0 Alpha release** |

**v1.0 capabilities:**
- Full reconnaissance (subdomain, DNS, port, HTTP, crawling)
- Web vulnerability scanning (Nuclei + ffuf + ZAP)
- Basic API testing (Schemathesis)
- AI-driven triage and correlation
- Scope enforcement
- Technical + executive reporting
- CLI + web dashboard

### Phase 2 — Breadth (Weeks 5-8)

**Goal:** Cloud, AD, source code, and extended reporting.

| Week | Deliverable |
|---|---|
| 5 | Cloud agent (Prowler, ScoutSuite, CloudFox, Checkov) |
| 5 | AD agent (BloodHound, NetExec, Certipy, PEASS-ng) |
| 6 | Code analysis agent (Semgrep, CodeQL, Gitleaks, TruffleHog) |
| 6 | Container/K8s agent (Trivy, Kubescape, kube-bench) |
| 7 | Linux agent (PEASS-ng, Linux Exploit Suggester) |
| 7 | Attack graph visualization |
| 8 | MITRE ATT&CK coverage reporting |
| 8 | **v1.1 Beta release** |

**v1.1 capabilities:**
- Everything in v1.0
- Cloud security assessment (AWS/Azure/GCP)
- Active Directory security assessment
- Source code security scanning
- Container and K8s security
- Linux privilege escalation analysis
- Attack graph visualization
- ATT&CK coverage mapping

### Phase 3 — Intelligence (Weeks 9-12)

**Goal:** AI/LLM red teaming, mobile, and advanced intelligence.

| Week | Deliverable |
|---|---|
| 9 | AI/LLM red team agent (PyRIT, garak, AgentDojo, promptfoo, DeepTeam) |
| 9 | Mobile agent (MobSF, mobsfscan) |
| 10 | Purple team agent (Caldera, Atomic Red Team integration) |
| 10 | Detection agent (Sigma rule testing, Falco integration) |
| 11 | Threat intelligence integration (MISP/OpenCTI optional) |
| 11 | SARIF output, compliance mapping (OWASP/NIST/CIS) |
| 12 | Security methodology knowledge base (Anthropic Skills, Claude-Red) |
| 12 | **v1.2 Release candidate** |

**v1.2 capabilities:**
- Everything in v1.1
- AI/LLM vulnerability testing
- Mobile app security analysis
- Purple team automation
- Detection gap analysis
- SARIF output for CI/CD integration
- Compliance mapping

### Phase 4 — Depth (Weeks 13-16+)

**Goal:** Forensics, malware, fuzzing, IoT, and full autonomy.

| Deliverable |
|---|
| Forensics agent (Velociraptor, Volatility3) |
| Malware analysis agent (CAPEv2) |
| Binary fuzzing agent (AFL++, libFuzzer) |
| IoT/firmware agent (Binwalk, FirmAE) |
| Continuous attack surface monitoring |
| Full purple team automation loop |
| Custom tool plugin system |
| **v2.0 General availability** |

---

## 13. Risks & Mitigations

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | **Scope enforcement bypass** | Low | Critical | 3-layer defense in depth, continuous audit, automated testing |
| R2 | **Tool incompatibility** | Medium | High | Docker isolation, standard adapter contract, graceful degradation |
| R3 | **AI hallucination in triage** | Medium | Medium | Human-in-the-loop for critical findings, confidence thresholds, evidence-backed only |
| R4 | **Performance bottleneck** | Medium | Medium | Agent concurrency limits, budget caps, resource monitoring |
| R5 | **LLM API cost overruns** | High | Medium | Budget enforcement, prompt caching, model selection based on task complexity |
| R6 | **Upstream tool breakage** | High | Medium | Pinned versions, automated testing, adapter version management |
| R7 | **Legal liability** | Low | Critical | Strict scope enforcement, audit logs, authorization verification |
| R8 | **Data breach of findings** | Low | Critical | Encryption at rest/transit, access controls, data retention policies |
| R9 | **Pentest Swarm AI maturity** | Medium | Medium | Keep sequential runner as fallback, contribute fixes upstream |
| R10 | **Scope creep in development** | High | Medium | Phased rollout, clear phase gates, MVP-first mentality |

---

## 14. Dependencies

### External Dependencies

| Dependency | Type | Risk |
|---|---|---|
| Pentest Swarm AI | Open source (AGPL-3.0) | Active project, 2.5k stars, needs monitoring |
| LLM APIs (Claude, GPT, etc.) | Commercial APIs | Cost, rate limits, availability |
| Security tool upstreams | Open source | Maintenance, compatibility |
| PostgreSQL + pgvector | Open source | Stable, well-maintained |
| Docker ecosystem | Open source | Stable, well-maintained |

### Internal Dependencies

| Component | Depends On |
|---|---|
| Control Plane | PostgreSQL, Redis |
| AI Orchestrator | LLM APIs, PostgreSQL (blackboard) |
| Tool Adapters | Docker, tool binaries (auto-downloaded) |
| Dashboard | Control Plane API |
| Reporting | Evidence Store, AI Orchestrator |

---

## 15. Open Questions

| # | Question | Decision Needed By | Current Lean |
|---|---|---|---|
| Q1 | Should REVENANT support commercial licensing or stay fully open source? | End of Phase 1 | Open source (AGPL) |
| Q2 | Cloud-native deployment (K8s) vs Docker Compose only? | Phase 1 | Docker Compose first, K8s in v2.0 |
| Q3 | How to handle tools requiring GUI (Burp Suite, MobSF)? | Phase 2 | Headless mode / API-only where possible |
| Q4 | Multi-user concurrent missions or single-user first? | Phase 1 | Single-user v1.0, multi-user v1.1 |
| Q5 | Self-hosted only or SaaS option? | Phase 2 | Self-hosted v1.0, SaaS evaluation v2.0 |
| Q6 | Integration with existing SIEM/SOAR platforms? | Phase 2 | SARIF output + webhook for v1.0 |
| Q7 | How to handle tool licensing (Metasploit Pro vs Community)? | Phase 1 | Community editions only |

---

## 16. Appendix

### A. Full Repository List (66 repos)

See [architecture.md](ARCHITECTURE.md) § "Potential Integrations" for the complete catalog organized by domain.

### B. Capability Domain Coverage Matrix

See Section 6 for the full 37-domain inventory with tool mappings.

### C. Pentest Swarm AI Deep Dive

See [PENTEST-SWARM-AI-ANALYSIS.md](PENTEST-SWARM-AI-ANALYSIS.md) for the complete technical analysis of the base platform.

### D. Architecture Decision Records

| Decision | Rationale | Status |
|---|---|---|
| Fork Pentest Swarm AI | 35+ tools already wired, swarm architecture exists, saves months | Approved |
| Go as primary language | Pentest Swarm AI is Go; performance, Docker ecosystem | Approved |
| Postgres + pgvector for blackboard | Already in Pentest Swarm AI, supports semantic search | Approved |
| Docker-first deployment | Tool isolation, reproducibility, easy updates | Approved |
| Stigmergic swarm over centralized orchestration | Emergent behavior, fault tolerance, natural parallelism | Approved |
| 3-layer scope enforcement | Defense in depth for the most critical safety feature | Approved |
| YAML playbooks for attack sequences | Accessible, version-controllable, no code changes needed | Approved |

### E. Glossary

| Term | Definition |
|---|---|
| **Stigmergic** | Communication through modification of shared environment (the blackboard), not direct messaging |
| **Pheromone** | A decaying priority weight on findings — high-priority findings last longer, low-priority fades |
| **Blackboard** | Shared data structure where agents read and write findings |
| **Finding** | A structured record of something discovered during a mission (vulnerability, subdomain, misconfiguration, etc.) |
| **Mission** | A complete security assessment against a defined scope |
| **Scope Manifest** | JSON document declaring allowed targets and policies for a mission |
| **Adapter** | A standardized wrapper that makes a tool conform to the platform's input/output contract |
| **Agent** | A specialized AI component that knows how to use one family of tools and interpret their output |
| **ATT&CK** | MITRE's Adversarial Tactics, Techniques, and Common Knowledge framework |
| **SARIF** | Static Analysis Results Interchange Format — a standard for sharing security scan results |

---

*This PRD is a living document. It will be updated as development progresses and decisions are made.*
