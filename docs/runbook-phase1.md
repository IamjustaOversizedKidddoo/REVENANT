# REVENANT — Phase 1 Deployment Runbook

> Goal: a working autonomous pentester within a day, against **sanctioned lab targets only**.

---

## Prerequisites

- A **Linux VPS** — Ubuntu 22.04 LTS, **8 vCPU / 32 GB RAM / 100 GB SSD** (4/16 minimum)
  - Providers: Hetzner, DigitalOcean, Vultr, Linode, AWS EC2, Azure, Google Cloud
  - The platform *will* run on 4/16 but you'll feel it.
- An **Anthropic API key** (the AI brain). The fork also supports OpenAI, Gemini, Ollama, Together.
- SSH access to the box (`root` or a sudo user).

---

## The two-phase flow

```
                    ┌──────────────────────────┐
  YOU RUN           │  1. provision-vps.sh      │  ← one-shot, idempotent
                    └──────────┬───────────────┘
                    ┌──────────▼───────────────┐
  YOU RUN           │  2. build-and-verify.sh   │  ← clone + build + test lab
                    └──────────┬───────────────┘
                    ┌──────────▼───────────────┐
  YOU CONFIRM       │  3. test-scope-enf.sh     │  ← proves authorization
                    └──────────┬───────────────┘
                    ┌──────────▼───────────────┐
  YOU + ME          │  4. live assessment       │  ← we watch it work together
                    └──────────────────────────┘
```

---

## Step 1 — Provision the VPS

To get the script onto the box, either:

```bash
# Option A: copy it up from this repo
scp D:\REVENANT\scripts\provision-vps.sh user@YOUR_VPS_IP:/tmp/
ssh user@YOUR_VPS_IP
sudo bash /tmp/provision-vps.sh
```

or

```bash
# Option B: pull it from a raw URL if you host this repo on GitHub/GitLab
sudo bash -c "$(curl -sL https://raw.githubusercontent.com/YOUR_ORG/REVENANT/main/scripts/provision-vps.sh)"
```

**What it does:** system packages, UFW firewall (only SSH + web ports open), Docker + Compose, Go 1.24, Python 3, Node 20, PostgreSQL 16 + pgvector, Redis, the `/opt/revenant` directory scaffold, and a `revenant` database.

> Change the default DB password (`revenant_dev`) before production.

---

## Step 2 — Build & verify against lab targets

```bash
cd /opt/revenant
# bring up the sanctioned lab targets (crAPI, Juice Shop, VAmPI, DVGA)
sudo bash scripts/lab-targets.sh start

# clone, build, and run the baseline against crAPI
sudo ANTHROPIC_API_KEY=sk-ant-xxx bash scripts/build-and-verify.sh
```

The script will:
1. Clone [Armur-Ai/Pentest-Swarm-AI](https://github.com/Armur-Ai/Pentest-Swarm-AI) → `/opt/revenant/repos/pentest-swarm-ai`
2. Build the `pentestswarm` binary
3. Run the sequential 5-phase pipeline against crAPI
4. Write reports to `/opt/revenant/evidence/crapi/`

> The CLI flags in the script (`--target/--scopes/--provider/...`) are the documented
> interface; we'll tune them to the exact binary surface during verification.

---

## Step 3 — Prove scope enforcement (safety gate)

```bash
sudo bash scripts/test-scope-enforcement.sh
```

Three tests:
1. In-scope target → accepted
2. Out-of-scope target → **refused**
3. No scope → **refused**

**All three must pass before REVENANT touches any real assessment.** If the platform
ever accepts an out-of-scope target, we stop and fix that first. Non-negotiable.

---

## Step 4 — Run a live assessment (with me)

Once the safety gate passes, we'll:
- Pick a sanctioned target (lab app, or an authorized program scope you control)
- Run the full loop: `recon → classify → plan → execute → report`
- Watch the agents work, then review the report together

---

## What success looks like at the end of Phase 1

- [ ] `build-and-verify.sh` completes with zero hard errors
- [ ] Evidence + reports generated for a lab target
- [ ] Scope enforcement: all 3 tests PASS
- [ ] UFW active, only expected ports open
- [ ] Mission runs start → finish with a real report
- [ ] We have the sequential runner + starting evidence the swarm works

---

## Troubleshooting cheatsheet

| Problem | Fix |
|---|---|
| `go: not found` after provision | `source /etc/profile.d/go.sh` (or re-login) |
| crAPI image pulls slow | It's ~1.5 GB; first boot takes a few minutes. Use `juiceshop` (smaller) to test timing |
| Port 3000 already in use (Juice Shop vs dashboard) | lab targets bind localhost; change with `-p` in `lab-targets.sh` |
| LLM errors → no response from provider | Double-check `ANTHROPIC_API_KEY`; confirm outbound HTTPS (443) is allowed |
| Postgres not accepting connections | `docker compose ps`; check `revenant-postgres` is healthy |
| Nothing listens on 8080/3000 | Phase 2 — our control plane + dashboard aren't built yet; CLI works today |

---

## Where files live

| Path | Purpose |
|---|---|
| `/opt/revenant/bin/pentestswarm` | the built CLI |
| `/opt/revenant/repos/pentest-swarm-ai/` | the fork (our canonical baseline) |
| `/opt/revenant/evidence/` | all reports, raw evidence, screenshots |
| `/opt/revenant/configs/` | platform config |
| `/opt/revenant/playbooks/` | YAML attack sequences |

The same layout exists locally in `D:\REVENANT\` — the repo is the source of truth; the
VPS is the execution environment.