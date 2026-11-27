# CLAUDE.md

Operating instructions for Claude Code in this repository.

**Follow [`AGENTS.md`](AGENTS.md)** — it is the single source of truth for how to drive
REVENANT (setup, the canonical scan workflow, profiles, env vars, and the mandatory
authorization gate). Everything there applies to Claude Code unchanged.

## Non-negotiables (summary of AGENTS.md)
- **Authorization first.** Only scan a target the operator owns or is authorized to test.
  Naming a target is not authorization — if unclear, stop and ask. Use
  `revenant quickstart` (bundled safe lab) for demos. Never try to bypass a scope refusal
  or aim to cause damage.
- **Read the artifacts, don't invent them.** After a scan, read `report.json` /
  `report.md` / `analysis.md` from the `--output-dir` and report only what they contain.
- **Keep the core light.** New heavy dependencies go in an optional extra in
  `pyproject.toml`, never in `dependencies`. New features degrade gracefully when a tool
  or API key is absent (mirror the native-fuzzer / LLM-fallback patterns).
- **Tests:** `.\.venv\Scripts\python.exe -m pytest -m "not live"` must stay green.

## Quick reference
```powershell
.\.venv\Scripts\Activate.ps1
revenant doctor
revenant <authorized-target> --profile recon --output-dir evidence/<name>-recon
revenant https://<authorized-target> --profile ai-reasoning --output-dir evidence/<name>-attack
revenant analyze evidence/<name>-attack/report.json
```
