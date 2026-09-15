# REVENANT
**Autonomous AI Red Teaming Platform**

A single roof over 66 security tools and 37 capability domains, driven by a multi-agent AI brain. REVENANT autonomously runs the full security lifecycle — recon, attack-surface mapping, vulnerability analysis, exploitation validation, red-team simulation, reporting — always within an explicitly enforced authorized scope.

> ⚠️ **Authorization is mandatory.** REVENANT refuses any target outside an explicit scope manifest. It is designed for your own assets, sanctioned labs, and authorized bug bounty scopes only.

## Quick Start
*(coming soon — Phase 1)*

## Architecture
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full blueprint.

## Roadmap
- **Phase 1 — Skeleton**: orchestration brain + control plane + recon/web baseline (Amass, Subfinder, httpx, naabu, Nmap, Nuclei, ffuf)
- **Phase 2 — Breadth**: Metasploit, Impacket, BloodHound, NetExec, Certipy, PEASS-ng, Prowler, CloudFox, Trivy, Semgrep, CodeQL, Gitleaks, TruffleHog, ZAP, Katana, Schemathesis
- **Phase 3 — AI-native**: PyRIT, garak, promptfoo, AgentDojo, DeepTeam, Caldera, ATT&CK correlation, reporting
- **Phase 4 — Depth**: MobSF, Velociraptor, Volatility3, CAPEv2, YARA, AFL++, Binwalk, FirmAE, Kubescape, kube-bench, Falco

## Repository Layout
```
D:\REVENANT\
├── docs/                # architecture, plans, runbooks
├── control-plane/       # API, auth, scope enforcement, job queue, evidence
├── orchestrator/        # AI swarm agents (Pentest Swarm base)
├── adapters/            # per-tool Docker wrappers (JSON-in/JSON-out)
├── engines/             # per-domain logic (recon, web, cloud, ad, ai, ...)
├── reporting/           # evidence → docx/pdf/html
└── deployments/         # docker-compose / k8s manifests
```

## Legal & Ethical
Operate only against hosts you own or are explicitly authorized to test. Unauthorized testing is illegal in most jurisdictions — REVENANT enforces scope in code, but the operator holds ultimate responsibility.