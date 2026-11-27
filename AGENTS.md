# AGENTS.md — Operator contract for REVENANT

This file tells an AI coding/ops agent (Codex, Antigravity/Gemini, Cursor, Claude Code,
etc.) how to drive REVENANT correctly and safely. Humans: see `README.md` and
`docs/OPERATOR_GUIDE.md`. Both the agent workflow and the manual workflow use the **same
`revenant` CLI** — the only difference is who types the commands and reads the reports.

REVENANT is an autonomous red-teaming platform: a stigmergic multi-agent swarm that runs
real security tooling against an **authorized** target and writes multi-format reports.

---

## 🔒 RULE 0 — Authorization gate (never skip)

**Only scan a target the operator is authorized to test.** Before running `scan`,
`quickstart` excepted, confirm with the human operator that one of these is true:

- They **own** the target, or
- They hold **written authorization** (signed scope / Rules of Engagement / a public
  bug-bounty scope that lists it).

Naming a target in chat is **not** authorization. If authorization is unclear, **stop
and ask** — do not scan. REVENANT still enforces this in code (3-layer scope gate +
refusal of cloud-metadata/link-local/multicast), but the agent must not try to work
around a scope refusal. Never aim to cause damage or run destructive actions; authorized
testing assesses impact **non-destructively**.

For demos/learning, use the bundled safe lab instead of any third-party target:
`revenant quickstart`.

---

## Setup (once per machine)

```powershell
# From the repo root (D:\REVENANT). Windows PowerShell shown; bash is analogous.
.\.venv\Scripts\Activate.ps1        # activate the project venv
python -m pip install -e .          # installs the `revenant` command (first time only)
revenant doctor                     # verify: tools, Python extras, AI layer, state backend
```

- If `revenant` is "not recognized": the venv isn't activated, or `pip install -e .`
  hasn't run. Either activate and reinstall, or call the shim directly:
  `.\.venv\Scripts\revenant.exe doctor`.
- Optional AI reasoning layer: `python -m pip install -e .[llm]` then set
  `ANTHROPIC_API_KEY`. Without it everything still runs via a deterministic fallback.

Core install is intentionally light (just `pydantic` + `requests`); the native fuzzers
need no external binary. Depth tools (subfinder, nmap, nuclei, ffuf, …) are optional and
reported by `revenant doctor`.

---

## Canonical workflow (both modes run these)

```powershell
revenant doctor                                             # 1. capability probe
revenant <target> --profile recon   --output-dir evidence/<name>-recon    # 2. map surface
#   -> READ evidence/<name>-recon/report.md before continuing
revenant https://<target> --profile ai-reasoning --output-dir evidence/<name>-attack  # 3. test
revenant analyze evidence/<name>-attack/report.json        # 4. AI intelligence brief
revenant remediate evidence/<name>-attack/report.json --output-dir evidence/<name>-fixes  # 5. fixes
#   -> apply fixes, then re-run step 3 to confirm closure
```

Agent loop contract: after each `scan`, **read the generated `report.json` / `report.md`
/ `analysis.md`** from the `--output-dir`, summarize findings for the operator, and
propose the next step. Do not fabricate findings — only report what the artifacts
contain. `web-dast` / `ai-reasoning` require a full `http(s)://` URL; `recon` accepts a
bare host/IP/CIDR.

### Artifacts written to every `--output-dir`
`report.md` (executive), `report.html`, `report.sarif` (CI), `report.json` (raw),
`report.attack_nav.json` (MITRE), `analysis.md`+`analysis.json` (AI brief, when findings
exist), and `remediation/` (IaC/Ansible/YARA fixes) via `remediate`.

### Profiles
`recon`, `web-dast`, `cloud-native`, `ad-identity`, `ai-reasoning` (web-dast + opt-in LLM
planner), `full-spectrum`. List with `revenant profiles`.

### Useful env vars
| Var | Effect |
|---|---|
| `REVENANT_STATE` | `memory` (default) / `sqlite` (durable) / `postgres` (appliance). |
| `REVENANT_RUNNER` | `local` (default) / `docker` / `wsl` — run tools containerized. |
| `ANTHROPIC_API_KEY`, `REVENANT_LLM_MODEL`, `REVENANT_PLANNER_BUDGET` | AI reasoning layer. |

Set `REVENANT_RUNNER=docker` **only if Docker Desktop is running** — otherwise leave it
unset and rely on native fuzzers.

---

## Running under specific agents

- **Claude Code** reads `CLAUDE.md` (which points here). Just open the repo and ask it to
  follow the canonical workflow against an authorized target.
- **Codex / Antigravity / Cursor** read this `AGENTS.md` natively. Same contract applies.
- All agents: honor **Rule 0**, read the artifacts rather than guessing, and keep scans
  scoped to `--output-dir evidence/<name>-*` so runs don't collide.

---

## Tests & dev

```powershell
.\.venv\Scripts\python.exe -m pytest -m "not live"   # self-contained suite (no external tools)
.\.venv\Scripts\python.exe -m pytest                 # everything (needs real tools installed)
```

Keep the core dependency list minimal; new heavy deps go in an optional extra in
`pyproject.toml`, never in `dependencies`. New code degrades gracefully when a tool/key
is absent (mirror the native-fuzzer and LLM-fallback patterns).
