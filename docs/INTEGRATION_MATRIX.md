# REVENANT — Module Integration Matrix

> How each of the 10 repos plugs into REVENANT, what it contributes,
> what it needs, and what to watch out for.

| # | Repo | Role | Integration surface | What it gives REVENANT | External deps | License | Notes / risks |
|---|---|---|---|---|---|---|---|
| 1 | **Shannon** | Autonomous web/API pentest pipeline | CLI subprocess + JSON/SARIF output | Full 6-stage pipeline (recon→code analysis→exploit→validate→report), authenticate flows, CI-friendly | Node 18+, pnpm, Docker, LLM keys (Anthropic/OpenAI/xAI/Ollama) | AGPL-3.0 (Enterprise option) | 1–1.5h per target; requires source code access; findings need human review. Best as scheduled deep-dive, not default scanner. |
| 2 | **Strix** | Multi-agent pentester w/ PoC validation | CLI headless (`strix -n`) + MCP; SARIF/JSON | 20+ vuln classes, exploit-confirmed findings, auto-fix patches, exit-code gating | Python 3.12+, Docker (hard dep), LLM key | Apache-2.0 | First run pulls sandbox image; alpha status → pin versions. Best default for webapp/bug-bounty scans. |
| 3 | **Nightcrawler** | Mobile/field autonomous agent | REST (Flask :8888) + config push; ThOR-export JSON | Stealth recon, 24k CVE DB, 27 playbooks, WiFi breach, per-network isolation | Android device w/ Kali NetHunter, local LLM | MIT | Hardware-specific; no Metasploit; 30-obs host memory cap. Used as "field agent fleet", not on desktop. |
| 4 | **HexStrike AI** | Tool bridge (MCP) | MCP server (`hexstrike_mcp.py`) | 150+ offensive tools behind MCP, decision engine, fallback chains, 15 attack patterns | All tools installed on host (Kali), no Docker yet | MIT | 734KB single-file monolith; no auth on Flask API → wrap + restrict to localhost. Fastest capability win. |
| 5 | **HackBot** | Research / triage agent team | ACP (HTTP :8000) + MCP (stdio) | Typed research agents, SARIF triage, doc analysis, citations | Python + uv, OpenAI key | (see repo) | OpenAI-centric; defense-only guardrails in prompts → overridable. Best for research/digest mode. |
| 6 | **HackerGPT** (fork, unmaintained) | Chat + embedded tools UI | REST `/api/chat` + extract streaming gateway | Chat UX w/ tool calls, RAG (Pinecone), 8 tools wired | OpenRouter + OpenAI keys, Firebase backend, GKE tool sandbox | GPL-3.0 | **Fork is stale** — prefer upstream `Hacker-GPT/HackerGPT`. CORS hardcoded; reuse streaming endpoints, not the app shell. |
| 7 | **HacxGPT-CLI** | Multi-provider LLM routing + persona | reimplemented client (endpoints + persona) | Zero-dep OpenAI-compatible client pattern, provider catalog, persona prompt | Provider API keys only | **Non-commercial (PUOL/CC BY-NC-SA)** | License prevents bundling into paid product → do NOT vendor code, reimplement endpoints; keep persona opt-in + gated + logged. |
| 8 | **USB-Uncensored-LLM** | Local air-gapped inference | Local Ollama/llama.cpp server (`/ollama/*` proxy) | Fully offline LLM for sensitive/air-gapped ops; portable deployment | Models on USB (GGUF), no network | (see repo) | **Repo archived** → use successor Uncensored-Local-Studio. No auth on proxy; single-threaded. |
| 9 | **Claude-Red** | Offensive skills (Claude) | SKILL.md content + `claude-skills.json` index | 78 methodology skills (web/wireless/AD/exploit-dev/C2/AI/LLM) | None (content only) | MIT | ~⅓ of index descriptions empty → normalize before routing; single maintainer → pin a version. |
| 10 | **Anthropic-Cybersecurity-Skills** | Skill library (engine-neutral) | `index.json` + `skills/*/SKILL.md` + `.claude-plugin` | 818 skills, 34 domains, MITRE ATT&CK/NIST/OWASP mappings, tooling | None (content only); agent harness runs them | Apache-2.0 | Content not capability — needs an executor; ~55 near-duplicate pairs → dedupe on ingest. |

---

## Integration ordering (recommended build sequence)

1. **HexStrike AI (MCP)** — instant 150+ tool surface for the brain.
2. **Skill registry** — both skill libraries (Claude-Red + Anthropic-Cybersecurity-Skills) ingested for methodology.
3. **HackBot (ACP/MCP)** — typed research + SARIF triage agents.
4. **Strix (CLI/MCP)** — full pentest engine w/ PoC validation.
5. **Shannon (CLI)** — deep code-informed exploitation + Temporal workflow pattern.
6. **HackerGPT (streaming gateway only)** — chat UX + embedded tools.
7. **Nightcrawler (REST)** — mobile field fleet.
8. **USB-Uncensored-LLM** → successor **Uncensored-Local-Studio** — air-gapped LLM provider.
9. **HacxGPT (endpoints reimplemented)** — optional persona + multi-provider routing (gated).

---

## Interface standards everyone conforms to

| Interface | Producers | Consumers |
|---|---|---|
| **MCP (Model Context Protocol)** | HexStrike, HackBot, Strix | Orchestrator, Tool Router, agent LLMs |
| **REST + JSON** | Nightcrawler, Shannon (JSON), HackerGPT gateway | Orchestrator, UI |
| **CLI subprocess** | Strix, Shannon, HexStrike tools | Tool Router executors |
| **SARIF 2.1.0** | Shannon, Strix, HackBot (triage) | Findings pipeline, DefectDojo/GitHub export |
| **SKILL.md (+YAML frontmatter)** | Claude-Red, Anthropic-Cybersecurity-Skills | Skill Engine → agent prompts |
| **OpenAI-compatible chat API** | HacxGPT providers, USB/Uncensored-local, HackBot, HackerGPT | LLM abstraction layer, any agent |