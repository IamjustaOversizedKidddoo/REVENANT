# Running REVENANT on Windows without fighting Defender

REVENANT drives real offensive-security tools. Windows is *supposed* to be suspicious
of those. This guide explains exactly what gets blocked, why, and how to run the
platform at a professional standard — **isolation first, scoped exclusions only when
you must.**

> We never recommend evading antivirus (obfuscating or fake-signing hacktools). That
> is what malware does and it makes your tooling indistinguishable from a threat. The
> correct answer is isolation and explicit, reversible exclusions on a lab host.

---

## What actually gets blocked (three different mechanisms)

| # | What you see | Mechanism | Not the same as |
|---|---|---|---|
| 1 | `nmap.exe`, `ncat.exe`, `nuclei.exe`, `ffuf.exe`, … quarantined / "threat found" | **Defender Antivirus** signature detections (`HackTool`, riskware) | — |
| 2 | *"An Application Control policy has blocked this file"* (`WinError 4551`) on `hypothesis._native` DLL or a tool `.exe` | **Smart App Control / WDAC** refusing **unsigned native code** | NOT antivirus — exclusions won't lift it |
| 3 | Purple-team / Atomic runs flagged mid-execution | **Defender behavior monitoring / ASR rules** reacting to ATT&CK emulation | NOT the file, the *behavior* |

None of this is a bug in REVENANT's Python. It is Windows correctly reacting to
genuine penetration-testing tooling.

---

## Option A — Run in isolation (recommended, "industry level")

Offensive tooling belongs in a Linux container or a dedicated VM, not on the bare
Windows host. Defender on Windows does **not** scan inside a Linux container, so all
three problems above disappear at once.

### A1. On-demand container runner (no tools on the host)

Set one environment variable and REVENANT runs each mapped tool in an ephemeral
`docker run --rm` container instead of a host binary:

```powershell
$env:REVENANT_RUNNER = "docker"
revenant scan http://127.0.0.1:3000 --profile web-dast
```

- Requires Docker Desktop (with its Linux engine / WSL2 backend).
- Mapped tools today: `nuclei, subfinder, httpx, katana, nmap, trufflehog, gitleaks,
  semgrep, trivy` (see `DOCKER_IMAGE_MAP` in `adapters/base.py`). Images are pulled on
  first use and the container is removed on exit — **nothing is installed on the host**,
  so there is nothing for Defender to flag.
- `localhost` / `127.0.0.1` targets are rewritten to `host.docker.internal` so a
  container can still reach a listener on your Windows host.
- A tool with no mapped image returns a clear error — install it locally and use
  `REVENANT_RUNNER=local`, or add the image to the map.

Runner selection order: explicit `runner=` argument → `REVENANT_RUNNER` env → `local`.

### A2. Full appliance (Postgres + Redis + workers)

For a durable, multi-tool deployment, use the shipped stack — everything runs in Linux
containers:

```powershell
cd deployments
docker compose up -d
```

Pair it with durable mission state: `REVENANT_STATE=sqlite` (file) or the appliance
Postgres backend. See the project README.

### A3. WSL2 bridge

The adapters also support a WSL2 execution bridge (`use_wsl=True` /
`REVENANT_RUNNER=wsl`): tools run inside your WSL Linux distro while REVENANT drives
them from Windows. Loopback targets are translated to the WSL gateway IP automatically.

---

## Option B — Bare-metal Windows lab host (when you can't isolate)

Only on a dedicated, authorized lab machine. Use scoped exclusions — never a blanket
"turn Defender off".

### B1. Defender exclusions (scoped, reversible)

Run from an **elevated** PowerShell:

```powershell
.\scripts\setup-defender-exclusions.ps1
```

This excludes the `bin/` folder and the specific tool executables only. Undo at any
time:

```powershell
.\scripts\setup-defender-exclusions.ps1 -Remove
```

### B2. Smart App Control (the `WinError 4551` blocker)

Exclusions do **not** lift Application-Control blocks. On a security workstation,
Smart App Control should be off:

`Settings > Privacy & security > Windows Security > App & browser control > Smart App
Control > Off`

⚠️ Turning Smart App Control **off is one-way** — Windows requires a clean reinstall to
turn it back on. Treat it as a deliberate "this is a lab machine" decision.

### B3. Signed / pure-Python dependencies

The `hypothesis._native` DLL block is the same Application-Control mechanism. If you
need the property-based tests, install a `hypothesis` build whose native module is
signed/allowed, or run the self-contained suite which doesn't need it:

```powershell
pytest -m "not live"
```

---

## Quick decision guide

- **CI, a laptop, or a shared machine** → Option A1 (`REVENANT_RUNNER=docker`) or A2.
- **A dedicated, authorized pentest host you control** → Option B (exclusions + Smart
  App Control off).
- **Never** → disabling Defender globally, or obfuscating tools to evade detection.
