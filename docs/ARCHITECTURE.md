# REVENANT — AI Red Teaming Platform

**The world's best autonomous AI red teaming platform.** A single roof over 66 security tools, 37 capability domains, and a multi-agent AI brain that decides what to test, why, and with which tool — always within authorized scope.

---

## TL;DR

| | |
|---|---|
| **AI Brain** | Pentest Swarm AI (multi-agent blackboard architecture) |
| **Integration** | Every tool runs as an isolated Docker service with a standard JSON wrapper |
| **Deployment** | Linux VPS, Docker-first |
| **Authorization** | Enforced at orchestrator level. Out-of-scope targets are **refused**, not tested |
| **North star** | Autonomous Security Loop: DISCOVER → MAP → ANALYZE → PRIORITIZE → TEST → VALIDATE → EXPLOIT-SIMULATE → CORRELATE → DETECT → REPORT → REMEDIATE → RETEST |

---

## The Autonomous Security Loop

REVENANT's core operating cycle. Each phase is an engine; each engine owns a family of tools.

```
DISCOVER → MAP → ANALYZE → PRIORITIZE → TEST → VALIDATE
    ↕                                              ↕
 RETEST ← REMEDIATE ← REPORT ← DETECT ← CORRELATE ← EXPLOIT-SIMULATE
```

| Phase | Engine | Example tools |
|---|---|---|
| DISCOVER | Recon + OSINT | Amass, Subfinder, Katana, Odin/Shodan |
| MAP | Attack Surface | httpx, naabu, Nmap, CloudFox |
| ANALYZE | Vulnerability | Nuclei, Semgrep, Trivy, CodeQL, Prowler |
| PRIORITIZE | Triage | CVSS/EPSS + AI severity engine |
| TEST | Web/API/AI | ZAP, ffuf, Schemathesis, PyRIT, garak |
| VALIDATE | Exploitation | Metasploit, Impacket, Certipy, Shannon |
| EXPLOIT-SIMULATE | Red Team | Caldera, Atomic Red Team, NetExec, BloodHound |
| CORRELATE | ATT&CK | attack-stix-data, MITRE mapping |
| DETECT | Detection | Sigma, YARA, Falco |
| REPORT | Reporting | Faraday, Dradis, custom evidence store |
| REMEDIATE / RETEST | ASM loop | Continuous Attack Surface Management |

---

## High-Level Architecture

```
                        ┌──────────────────────────────────────────┐
                        │            REVENANT CONTROL PLANE          │
                        │   API (FastAPI) · Web UI · AuthN/AuthZ     │
                        │   Job Queue · Scope Enforcement · Evidence │
                        └──────────────────────┬─────────────────────┘
                                               │
                        ┌──────────────────────▼─────────────────────┐
                        │         AI ORCHESTRATOR (SWARM)             │
                        │   Planner → Delegator → Correlator →        │
                        │   Verifier                                  │
                        └──────────────────────┬─────────────────────┘
                                               │
                        ┌──────────────────────▼─────────────────────┐
                        │         TOOL ADAPTER LAYER                  │
                        │   uniform JSON-in / JSON-out wrappers       │
                        │   Autodiscovery · Schema registry · TTL     │
                        └──────┬──────┬──────┬──────┬──────┬──────────┘
                               ▼      ▼      ▼      ▼      ▼
                          ┌────────┐┌──────┐┌───────┐┌──────┐┌────────┐
                          │ RECON  ││ WEB  ││ CLOUD ││  AD  ││ AI/LLM │
                          │ swarms ││ brown ││   │   │ teams ││  red    │
                          └────────┘└──────┘└───────┘└──────┘└────────┘
```

---

## Component Specs

### 1. Control Plane
- **API**: FastAPI. REST + (later) WebSocket for live stream views.
- **Auth**: Keycloak or basic JWT (start simple, harden later). RBAC: admin / operator / auditor.
- **Job Queue**: Celery + Redis, or a local queue at v1. Every mission = a job with a declared **scope manifest**.
- **Scope Manifest**: JSON of allowed CIDRs/hostnames/regexes + policy (e.g., `max_parallel_active=20`, `no_exploit=true`). The orchestrator **cannot** invoke a tool against a target outside this manifest — enforced at the adapter layer too (defense in depth).
- **Evidence Store**: Every tool result, screenshot, raw HTTP req/resp, terminal capture goes to a timestamped, tamper-evident store (PostgreSQL JSONB + object storage at scale).

### 2. AI Orchestrator (Swarm)
Based on **Pentest Swarm AI** blackboard architecture:
- **Blackboard** = shared mission state (targets, findings, dedup keys, ATT&CK tags, priorities).
- **Specialist agents** (each owns a tool family):
  - Recon Agent *(Amass, Subfinder, httpx, naabu, Katana, Nmap)*
  - OSINT Agent *(CT logs, GitHub, Shodan/ODIN)*
  - Web Agent *(Nuclei, ZAP, ffuf, Katana)*
  - API Agent *(Schemathesis, custom)*
  - Exploit-Validation Agent *(Metasploit, Impacket, Shannon)*
  - Cloud Agent *(Prowler, ScoutSuite, CloudFox, Trivy)*
  - AD Agent *(BloodHound, NetExec, Certipy, PEASS-ng)*
  - Code-Analysis Agent *(Semgrep, CodeQL, Gitleaks, TruffleHog)*
  - AI/LLM Agent *(PyRIT, garak, AgentDojo, promptfoo, DeepTeam)*
  - Fuzzing Agent *(AFL++, libFuzzer, ffuf*)*
  - Triage/Prioritize Agent *(CVSS/EPSS, ATT&CK)*
  - Attack-Path Agent *(BloodHound, cloudfox, custom graph)*
  - Reporting Agent *(evidence → docx/pdf/html)*
  - Detection Agent *(Sigma, YARA, Falco)*
  - **Orchestrator Agent** — planner/delegator that reads blackboard, picks next action, resolves conflicts.
- **Communication**: agents publish structured messages to the blackboard; orchestrator consumes and coordinates.

### 3. Tool Adapter Layer (THE engineering core)
Every tool (66 of them) becomes a **Docker service** exposing a standard contract:

```jsonc
{
  // ToolAdapter
  "id": "nuclei",
  "version": "3.3.1",
  "kind": "vuln-scanner",
  "capabilities": ["web", "template", "http"],
  "inputs": {   // JSON Schema
    "targets": ["https://example.com"],
    "templates": ["cves", "default"],
    "severity": ["critical", "high"]
  },
  "outputs": {  // normalized finding schema
    "findings": [{
      "tool_id": "nuclei",
      "template_id": "CVE-2024-xxxx",
      "target": "https://example.com",
      "severity": "high",
      "cwe", "cve", "att&ck_technique",
      "evidence": {"raw": "...", "screenshot": "..."},
      "confidence": 0.9
    }]
  }
}
```

The wrapper handles: image lifecycle, TTL, resource limits, non-root execution, network egress policy, artifact upload to evidence store.

**Standard finding schema** is the keystone — every adapter normalizes into it so Correlate / Report engines see one shape.

---

## Rollout Plan

### Phase 1 — Skeleton (the spine)
- Stand up Pentest Swarm AI on Linux VPS (Docker).
- Control plane: API + scope enforcement + job queue + evidence store.
- Adapters (baseline ~7): **Amass, Subfinder, httpx, naabu, Nmap, Nuclei, ffuf**.
- Ingress intelligence: how swarm agents decode the normalized schema.
- **Smoke test**: run a full DISCOVER→REPORT loop against a sanctioned lab target.

### Phase 2 — Breadth
- Exploit/validation: **Metasploit, Impacket, BloodHound, NetExec, Certipy, PEASS-ng**
- Cloud: **Prowler, ScoutSuite, CloudFox, Trivy, Checkov**
- SAST/secrets: **Semgrep, CodeQL, Gitleaks, TruffleHog**
- Web depth: **ZAP, Katana, Schemathesis**

### Phase 3 — AI-native + intelligence
- **PyRIT, garak, AgentDojo, promptfoo, DeepTeam** (LLM red teaming)
- **Caldera + Atomic Red Team + attack-stix-data** (ATT&CK correlation everywhere)
- Reporting: **Faraday/Dradis** integration or evidence → docx/pdf.
- Threat intel plumbing: **MISP/OpenCTI** (optional v3).

### Phase 4 — Depth
- Mobile: **MobSF, mobsfscan**
- Forensics: **Velociraptor, Volatility3**
- Malware: **CAPEv2, YARA**
- Fuzzing: **AFL++, libFuzzer**
- Firmware/IoT: **Binwalk, FirmAE**
- K8s: **Kubescape, kube-bench, Falco**
- Purple team automation loop.

---

## Pentest Swarm AI — Real Architecture (updated 2026-09-15)

**Full analysis:** [PENTEST-SWARM-AI-ANALYSIS.md](PENTEST-SWARM-AI-ANALYSIS.md)

Key discovery: Pentest Swarm AI already has **35+ tool adapters, 7 playbooks, scope enforcement, LLM integration, a stigmergic swarm, and a Next.js dashboard**. Phase 1 recon/web baseline is essentially done. REVENANT's Phase 1 work is: fork → verify → extend.

**Agents already in the swarm:**
- `recon` — runs subfinder, httpx, nuclei, naabu, katana, dnsx, gau, nmap
- `classifier` — LLM-based CVE/misconfig classification
- `exploit` — LLM-planned attack chains, BOLA/IDOR sweeps
- `report` — final report generation (MD/HTML/JSON/SARIF)
- `confirm` — false-positive re-checking (reruns reproduction)
- `burp` — Burp Suite MCP integration
- `nuclei-author` — LLM-authored nuclei templates for novel findings

**Tool interface:** implement `Name()`, `Run()`, `IsAvailable()` in `internal/tools/`, or use YAML `CustomToolDef`.

**Agent interface:** implement `Name()`, `Trigger()`, `MaxConcurrency()`, `Handle()` in `internal/swarm/agents/`.

**Blackboard:** stigmergic (agents communicate via shared `Finding` objects with pheromone decay). Postgres-backed with pgvector. Cursor-based exactly-once delivery.

---

## Non-Negotiables

1. **Authorization is enforced in code.** Scope manifest checked at 3 layers: control plane, orchestrator, adapter. Anything out of scope → job refused with reason logged.
2. **Every action logged.** Full audit trail: who/what/when/which tool/targets/result. Tamper-evident hashes.
3. **Safe-by-default.** `no_destructive=true` unless explicitly lifted in scope. No DoS anchors, no persistence/exfiltration outside sanctioned labs.
4. **Evidence is reproducible.** Every finding ships with raw evidence, not just a summary.
5. **Everything maps to ATT&CK.** If a finding can't be pinned to MITRE ATT&CK, it's flagged as unclassified and goes through triage.

---

## Product Requirements

**Live product requirements document:** [PRD.md](PRD.md) — v1.0, dated 2026-09-15

The PRD defines: user personas (security consultants, bug bounty hunters, CISOs, red teamers, researchers, AI/ML engineers), 8 primary success metrics, 37 capability domains, phased rollout across 4 phases (Foundation → Breadth → Intelligence → Depth), 10 risk registrations with mitigations, and 7 open questions requiring decisions during build.

---

## What this doc does NOT decide (open questions, to resolve during build)
- Language for control plane + wrappers (Python first; Rust for hot-path fuzz wrappers if needed).
- UI framework (React vs Next.js vs plain SSR).
- Shodan/ODIN API keys for OSINT depth; NASI (network ASN info) source.
- Whether Pentest Swarm stays as-is (fork) or is heavily rewritten vs built-from-scratch-compatible.