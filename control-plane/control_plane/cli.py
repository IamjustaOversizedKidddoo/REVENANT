"""
REVENANT — Unified Platform CLI Runner
Executes autonomous security missions from the command line with live terminal logging,
Layer 1-3 scope enforcement, mission profile selection, and automatic multi-format report generation.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import socket
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional

from control_plane.profiles import get_profile, list_profiles, validate_profile_target
from control_plane.schemas.models import Finding
from control_plane.schemas.scope import ScopeEngine, ScopeManifest, ScopeViolationError
from orchestrator.asm_daemon import ASMDaemon
from orchestrator.blackboard import Blackboard, EventType, blackboard_from_env
from orchestrator.engine import Orchestrator
from orchestrator.remediation.remediation_engine import RemediationEngine
from reporting.generator import ReportGenerator

# The intelligence layer is optional and degrades gracefully; import defensively so a
# packaging variant without it can never break the core CLI.
try:
    from intelligence.analyst import AnalystNarrator
    from intelligence.llm_client import LlmClient
    from intelligence.reconblade_brief import ReconBladeBrief
except Exception:  # pragma: no cover - only if intelligence/ is absent
    AnalystNarrator = None  # type: ignore
    LlmClient = None  # type: ignore
    ReconBladeBrief = None  # type: ignore


# --------------------------------------------------------------------------- #
# Terminal presentation                                                        #
# One width (matching the ASCII banner) and two rule weights, so every block   #
# frames flush with the logo and the eye can tell a top-level section from a   #
# sub-section at a glance.                                                     #
# --------------------------------------------------------------------------- #
UI_WIDTH = 73
HR = "═" * UI_WIDTH   # heavy rule — top-level section frames
HRL = "─" * UI_WIDTH  # light rule — sub-dividers within a section


def _kv(label: str, value: object, width: int = 16) -> None:
    """Print one aligned key/value row (value column starts at `width`)."""
    print(f"  {label:<{width}}{value}")


def run_mission(
    target: str,
    scope: ScopeManifest,
    profile_name: str = "full-spectrum",
    output_dir: str = "evidence",
    max_iterations: Optional[int] = None,
    verbose: bool = True,
    llm_planner: bool = False,
) -> int:
    """
    Execute a full autonomous security mission against a sanctioned target.
    Returns 0 on success, 1 on error/scope violation.
    """
    profile = get_profile(profile_name) or get_profile("full-spectrum")
    effective_iterations = max_iterations if max_iterations is not None else profile.max_iterations

    if verbose:
        print(HR)
        print("   ██████╗ ███████╗██╗   ██╗███████╗███╗   ██╗ █████╗ ███╗   ██╗████████╗")
        print("   ██╔══██╗██╔════╝██║   ██║██╔════╝████╗  ██║██╔══██╗████╗  ██║╚══██╔══╝")
        print("   ██████╔╝█████╗  ██║   ██║█████╗  ██╔██╗ ██║███████║██╔██╗ ██║   ██║   ")
        print("   ██╔══██╗██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██╔══██║██║╚██╗██║   ██║   ")
        print("   ██║  ██║███████╗ ╚████╔╝ ███████╗██║ ╚████║██║  ██║██║ ╚████║   ██║   ")
        print("   ╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ")
        print("            AUTONOMOUS AI RED TEAMING & CYBER WARFARE PLATFORM           ")
        print(HR)
        _kv("Target", target)
        _kv("Profile", profile.name.upper())
        _kv("", profile.description)
        _kv("Agents", ", ".join(profile.active_agents))
        _kv("Iterations", effective_iterations)
        _kv("Output", output_dir)
        print(HRL)

    # 1. LAYER 1 SCOPE CHECK (CLI Intake Gate)
    scope_engine = ScopeEngine(scope)
    try:
        scope_engine.validate_or_raise(target)
        if verbose:
            print("[+] [Layer 1 Scope Check] PASS: Target authorized within scope boundary.")
    except ScopeViolationError as exc:
        print(f"[-] [Layer 1 Scope Check] CRITICAL REFUSAL: {exc}", file=sys.stderr)
        return 1

    # 2. Validate Target against Profile
    valid, reason = validate_profile_target(profile, target)
    if not valid:
        print(f"[-] [Profile Validation Warning] {reason}", file=sys.stderr)

    # 3. Initialize Blackboard & Orchestrator.
    #    State backend is env-selected (in-memory by default; SQLite/appliance when set),
    #    and only the profile's declared agents are instantiated — not all 16.
    blackboard = blackboard_from_env()
    # Opt-in LLM Planner: append (once) without mutating the shared profile object.
    active_agents = list(profile.active_agents)
    if llm_planner and "llm-planner" not in active_agents:
        active_agents.append("llm-planner")
    orchestrator = Orchestrator(blackboard=blackboard, active_agents=active_agents)

    if verbose:
        print(f"[*] Active state backend:  {os.environ.get('REVENANT_STATE', 'memory')}")
        print(f"[*] Starting stigmergic multi-agent swarm [{profile.name}] "
              f"({len(orchestrator.agents)} agents)...")

    # 4. Run Campaign Loop
    summary = orchestrator.start_campaign(
        target=target,
        scope=scope,
        max_iterations=effective_iterations,
    )

    if verbose:
        print()
        print("  MISSION COMPLETE")
        print(HRL)
        _kv("Iterations", summary.get("iterations_run", 0))
        _kv("Assets", summary.get("total_assets", 0))
        _kv("Findings", summary.get("total_findings", 0))
        sev_counts = {s: c for s, c in summary.get("findings_by_severity", {}).items() if c > 0}
        if sev_counts:
            breakdown = "   ".join(f"{s} {c}" for s, c in sev_counts.items())
            _kv("", breakdown)

    # 5. Generate & Save Multi-Format Reports
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    generator = ReportGenerator(
        campaign_id=blackboard.campaign_id,
        target=target,
        assets=blackboard.get_assets(),
        findings=blackboard.get_findings(),
        metadata={"iterations": summary.get("iterations_run"), "profile": profile.name},
    )

    # Markdown report
    md_file = out_path / "report.md"
    md_file.write_text(generator.generate_markdown(), encoding="utf-8")

    # HTML report
    html_file = out_path / "report.html"
    html_file.write_text(generator.generate_html(), encoding="utf-8")

    # SARIF v2.1.0 (CI/CD)
    sarif_file = out_path / "report.sarif"
    sarif_file.write_text(json.dumps(generator.generate_sarif(), indent=2), encoding="utf-8")

    # Raw JSON
    json_file = out_path / "report.json"
    json_file.write_text(json.dumps(generator.generate_json(), indent=2), encoding="utf-8")

    # MITRE ATT&CK Navigator Layer
    nav_file = out_path / "report.attack_nav.json"
    nav_file.write_text(json.dumps(generator.generate_attack_navigator(), indent=2), encoding="utf-8")

    # Autonomous Remediation Code Generation (if findings exist)
    findings = blackboard.get_findings()
    if findings:
        remed_engine = RemediationEngine(output_dir=str(out_path / "remediation"))
        remed_artifacts = remed_engine.remediate_campaign(findings)
        remed_engine.export_artifacts(remed_artifacts)
        if verbose:
            print(f"[+] Autonomous Remediation: Generated {len(remed_artifacts)} IaC/Ansible/YARA fixes.")

    # AI Analyst / Narrator enrichment — non-fatal, only when findings exist.
    if findings and AnalystNarrator is not None:
        try:
            analyst = AnalystNarrator(
                findings=findings,
                assets=blackboard.get_assets(),
                summary=summary,
                target=target,
            )
            brief = analyst.run_and_save(str(out_path))
            if verbose:
                mode = brief.get("mode", "fallback")
                print(f"[+] AI Analyst Brief: analysis.md written ({mode} mode).")
        except Exception as exc:  # enrichment must never fail a scan
            if verbose:
                print(f"[!] AI Analyst enrichment skipped: {exc}")

    # ReconBLADE-style findings brief — purely additive, writes a NEW file only,
    # never touches the existing reports. Non-fatal.
    if findings and ReconBladeBrief is not None:
        try:
            ReconBladeBrief(findings=findings, target=target).run_and_save(str(out_path))
            if verbose:
                print("[+] ReconBLADE Brief: findings_brief.md written.")
        except Exception as exc:
            if verbose:
                print(f"[!] ReconBLADE brief skipped: {exc}")

    if verbose:
        print()
        print("  ARTIFACTS")
        print(HRL)
        _kv("Saved to", out_path.resolve())
        print()
        _kv("  report.md", "Executive summary (Markdown)", 26)
        _kv("  report.html", "Interactive dashboard", 26)
        _kv("  report.sarif", "CI/CD code scanning (SARIF 2.1)", 26)
        _kv("  report.json", "Raw findings + attack graph", 26)
        _kv("  report.attack_nav.json", "MITRE ATT&CK Navigator layer", 26)
        print(HR)

    return 0


def auto_scope(target: str) -> ScopeManifest:
    """Authorize exactly the target the operator named - so `revenant <target>` just works.

    Naming a target IS the authorization. We build the tightest scope that still lets the
    swarm do its job: a URL/host authorizes that host (and its subdomains for a domain),
    an IP authorizes that IP, a CIDR authorizes that block. The scope engine still refuses
    cloud-metadata/link-local/multicast ranges.
    """
    import ipaddress
    from urllib.parse import urlparse

    t = (target or "").strip()
    host = t
    if t.startswith("http://") or t.startswith("https://"):
        host = urlparse(t).hostname or t

    # CIDR block
    if "/" in host:
        try:
            ipaddress.ip_network(host, strict=False)
            return ScopeManifest(allowed_cidrs=[host])
        except ValueError:
            pass

    # Single IP
    try:
        ipaddress.ip_address(host)
        return ScopeManifest(allowed_hosts=[host], allowed_cidrs=[f"{host}/32"])
    except ValueError:
        pass

    # Hostname / domain (+ its subdomains for recon)
    return ScopeManifest(
        allowed_domains=[host],
        allowed_wildcards=[f"*.{host}"],
        allowed_hosts=[host],
    )


# Key external tool per domain, used by `revenant doctor` to report real capability.
# The native fuzzers (DAST, AI probe) need no binary, so those domains are always ready.
TOOL_MATRIX = {
    "recon": ["subfinder", "nmap", "ffuf", "httpx"],
    "web / dast": ["nuclei", "katana", "semgrep"],
    "code / sast": ["semgrep", "gitleaks", "trufflehog"],
    "cloud": ["trivy", "prowler", "checkov"],
    "kubernetes": ["kubescape", "kube-bench"],
    "identity (AD)": ["nxc", "netexec", "bloodhound-python", "certipy"],
    "forensics": ["vol", "velociraptor"],
    "malware": ["yara", "capa", "binwalk"],
    "mobile": ["mobsfscan"],
}


def cmd_doctor() -> int:
    """Report what REVENANT can actually do on this host: tools, deps, state backend."""
    print(HR)
    print("  REVENANT DOCTOR - host capability probe")
    print(HR)

    # 1. External security tools (present on PATH)
    print("\n[ External tools on PATH ]")
    for domain, tools in TOOL_MATRIX.items():
        found = [t for t in tools if shutil.which(t)]
        mark = "+" if found else "-"
        detail = ", ".join(found) if found else "none found"
        print(f"  [{mark}] {domain:<16} {detail}")
    print("  [+] native fuzzers      dast-fuzzer, ai-probe (no binary required)")

    # 2. Optional Python runtime deps
    print("\n[ Python runtime extras ]")
    for mod, label in [("requests", "core HTTP (scan)"),
                       ("fastapi", "API server"),
                       ("uvicorn", "API server")]:
        ok = importlib.util.find_spec(mod) is not None
        print(f"  [{'+' if ok else '-'}] {mod:<16} {label}")

    # 2b. AI reasoning layer (optional [llm] extra)
    print("\n[ AI reasoning layer ]")
    if LlmClient is not None:
        client = LlmClient()
        sdk_ok = client.sdk_installed()
        key_ok = bool(client.api_key)
        print(f"  [{'+' if sdk_ok else '-'}] anthropic SDK   "
              f"{'installed' if sdk_ok else 'not installed (pip install -e .[llm])'}")
        print(f"  [{'+' if key_ok else '-'}] ANTHROPIC_API_KEY "
              f"{'present' if key_ok else 'not set (deterministic fallback in use)'}")
        print(f"  [i] model            {client.model}")
        ready = "LLM" if client.available() else "deterministic fallback"
        print(f"  [{'+' if client.available() else '-'}] planner/analyst  {ready}")
    else:
        print("  [-] intelligence layer not importable (deterministic fallback only)")
    brief_ok = ReconBladeBrief is not None
    print(f"  [{'+' if brief_ok else '-'}] findings brief   "
          f"{'ReconBLADE-style triage (always on; LLM optional)' if brief_ok else 'unavailable'}")

    # 3. State backend
    state = os.environ.get("REVENANT_STATE", "memory")
    print("\n[ Mission state backend ]")
    print(f"  REVENANT_STATE = {state}"
          f"{'  (ephemeral - set to sqlite for durability)' if state == 'memory' else ''}")

    # 4. Profile readiness
    print("\n[ Profile readiness ]  (native capability always available)")
    for p in list_profiles():
        print(f"  - {p.name}")
    print("\n" + HR)
    print("  Tip: missing tools can run containerized at work — core install stays light.")
    print(HR)
    return 0


def _find_lab_server() -> Optional[Path]:
    """Locate the bundled sanctioned vulnerability lab server, if present."""
    here = Path(__file__).resolve()
    for root in list(here.parents):
        candidate = root / "tests" / "sanctioned_lab_server.py"
        if candidate.exists():
            return candidate
    return None


def _port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.25)
        return s.connect_ex((host, port)) == 0


def cmd_quickstart(output_dir: str = "evidence/quickstart") -> int:
    """Zero-config demo: boot the bundled vuln lab and run a web-dast mission against it."""
    host, port = "127.0.0.1", 3000
    print("[*] REVENANT quickstart — booting the sanctioned local lab and scanning it.\n")

    if not _port_open(host, port):
        lab = _find_lab_server()
        if lab is None:
            print("[-] Bundled lab server not found (tests/sanctioned_lab_server.py).",
                  file=sys.stderr)
            print("    Point `revenant scan` at your own authorized target instead.",
                  file=sys.stderr)
            return 1
        spec = importlib.util.spec_from_file_location("sanctioned_lab_server", lab)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        server = module.ThreadedHTTPServer((host, port), module.LabServerHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        for _ in range(40):
            if _port_open(host, port):
                break
            time.sleep(0.2)
        print(f"[+] Lab server listening on http://{host}:{port}\n")
    else:
        print(f"[+] Reusing lab server already on http://{host}:{port}\n")

    scope = ScopeManifest(allowed_hosts=["127.0.0.1", "localhost"],
                          allowed_cidrs=["127.0.0.1/32"])
    return run_mission(
        target=f"http://{host}:{port}",
        scope=scope,
        profile_name="web-dast",
        output_dir=output_dir,
    )


def _load_findings_file(path: Path) -> List[Finding]:
    """Load findings from a report.json (or a raw findings list) into Finding models."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw_findings = raw.get("findings", raw) if isinstance(raw, dict) else raw
    findings: List[Finding] = []
    for item in raw_findings or []:
        if isinstance(item, dict):
            try:
                findings.append(Finding.model_validate(item))
            except Exception:
                pass
    return findings


def cmd_analyze(findings_file: str, output_dir: Optional[str] = None) -> int:
    """Run the AI Analyst / Narrator over a findings export and write analysis.{md,json}."""
    if AnalystNarrator is None:
        print("[-] Intelligence layer unavailable in this install.", file=sys.stderr)
        return 1
    f_path = Path(findings_file)
    if not f_path.exists():
        print(f"[-] Findings file not found: {f_path}", file=sys.stderr)
        return 1

    raw = json.loads(f_path.read_text(encoding="utf-8"))
    target = raw.get("target") if isinstance(raw, dict) else None
    findings = _load_findings_file(f_path)
    out_dir = output_dir or str(f_path.parent)

    analyst = AnalystNarrator(findings=findings, target=target)
    brief = analyst.run_and_save(out_dir)

    print(HR)
    print("  REVENANT AI ANALYST — Intelligence Brief")
    print(HR)
    print(f"[*] Findings analyzed: {len(findings)}  (mode: {brief.get('mode', 'fallback')})")
    print(f"[*] Written to:        {Path(out_dir).resolve()}/analysis.md, analysis.json")
    print(HRL)
    print(analyst.render_markdown(brief))
    return 0


def cmd_brief(findings_file: str, output_dir: Optional[str] = None) -> int:
    """Render a ReconBLADE-style prioritized brief from an existing findings export."""
    if ReconBladeBrief is None:
        print("[-] Intelligence layer unavailable in this install.", file=sys.stderr)
        return 1
    f_path = Path(findings_file)
    if not f_path.exists():
        print(f"[-] Findings file not found: {f_path}", file=sys.stderr)
        return 1

    raw = json.loads(f_path.read_text(encoding="utf-8"))
    target = raw.get("target") if isinstance(raw, dict) else None
    findings = _load_findings_file(f_path)
    out_dir = output_dir or str(f_path.parent)

    brief_obj = ReconBladeBrief(findings=findings, target=target)
    brief = brief_obj.run_and_save(out_dir)

    print(HR)
    print("  REVENANT — ReconBLADE-style Findings Brief")
    print(HR)
    print(f"[*] Findings: {len(findings)}  (mode: {brief.get('mode', 'fallback')})")
    print(f"[*] Written to: {Path(out_dir).resolve()}/findings_brief.md, findings_brief.json")
    print(HRL)
    print(brief_obj.render_markdown(brief))
    return 0


# --------------------------------------------------------------------------- #
# Interactive mode: `revenant` (no args) or `revenant start`                   #
# Welcome screen first, then prompt for a target, then print what was found    #
# (severity-ranked) plus the attack-path escalation map, right in the terminal.#
# --------------------------------------------------------------------------- #

_BANNER = r"""   ██████╗ ███████╗██╗   ██╗███████╗███╗   ██╗ █████╗ ███╗   ██╗████████╗
   ██╔══██╗██╔════╝██║   ██║██╔════╝████╗  ██║██╔══██╗████╗  ██║╚══██╔══╝
   ██████╔╝█████╗  ██║   ██║█████╗  ██╔██╗ ██║███████║██╔██╗ ██║   ██║
   ██╔══██╗██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██╔══██║██║╚██╗██║   ██║
   ██║  ██║███████╗ ╚████╔╝ ███████╗██║ ╚████║██║  ██║██║ ╚████║   ██║
   ╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   """


# Last-resort mask if the generated asset files are missing.
_FALLBACK_MASK = r"""
                    ▄▄████████████▄▄
                 ▄██▀▀▀        ▀▀▀██▄
               ▄█▀▀   ▄▄▄    ▄▄▄   ▀▀█▄
              █▀    ◣█████◢  ◣█████◢    ▀█
             █          ╲   ▲   ╱          █
             █▄      ║ ║ ║ ║ ║ ║ ║      ▄█
                 ▀██▄▄  ╚═════════╝  ▄▄██▀
                    ▀▀████▄▄▄▄▄▄████▀▀"""


def _enable_windows_ansi() -> bool:
    """Turn on ANSI/VT processing so 24-bit color renders in a Windows console."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        k = ctypes.windll.kernel32
        handle = k.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not k.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        k.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return True
    except Exception:
        return False


def _load_mask() -> str:
    """Return the Doom-mask art: ANSI-colored on a real terminal, else plain, else fallback."""
    assets = Path(__file__).resolve().parent / "assets"
    use_color = sys.stdout.isatty() and _enable_windows_ansi()
    try:
        if use_color and (assets / "mask.ans").exists():
            return (assets / "mask.ans").read_text(encoding="utf-8")
        if (assets / "mask.txt").exists():
            return (assets / "mask.txt").read_text(encoding="utf-8")
    except Exception:
        pass
    return _FALLBACK_MASK


def _print_welcome() -> None:
    """Branded landing screen shown before any target is requested."""
    print(HR)
    print(_BANNER)
    print()
    print(_load_mask())
    print()
    print("          AUTONOMOUS AI RED TEAMING & SECURITY PLATFORM  v2.0")
    print(HR)
    print("  Give me a target and I will tell you:")
    print("    - what I found, ranked by criticality (CRITICAL -> INFO)")
    print("    - what each issue is, why it matters, and how to fix it")
    print("    - how an attacker could escalate it (the attack-path map)")
    print()
    print("  I only test targets you own or are authorized to test.")
    print("  (Press Enter with no target to run the safe bundled demo lab.)")
    print(HRL)


_SEV_MARK = {
    "CRITICAL": "!!!!",
    "HIGH": "!!! ",
    "MEDIUM": "!!  ",
    "LOW": "!   ",
    "INFO": "·   ",
}


def render_terminal_findings(findings: List[Finding], target: str) -> None:
    """Print a severity-ranked findings summary + attack-path escalation map."""
    print("\n" + HR)
    print(f"  WHAT REVENANT FOUND  —  {target}")
    print(HR)

    if not findings:
        print("  No confirmed findings on the tested surface.")
        print("  A static or well-hardened target often surfaces little — that is a")
        print("  real result, not a failure. Try a broader profile or a dynamic app.")
        print(HR)
        return

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    counts = {k: 0 for k in order}
    for f in findings:
        sev = str(getattr(f.severity, "value", f.severity)).upper()
        counts[sev] = counts.get(sev, 0) + 1
    print(f"  CRITICAL: {counts['CRITICAL']}    HIGH: {counts['HIGH']}    "
          f"MEDIUM: {counts['MEDIUM']}    LOW: {counts['LOW']}    INFO: {counts['INFO']}")

    # Per-finding detail from the ReconBLADE brief (what/why/fix/escalation).
    entries: List[dict] = []
    if ReconBladeBrief is not None:
        rb = ReconBladeBrief(findings=findings, target=target).build()
        entries = rb["entries"]
        print("\n  PRIORITY ORDER (fix worst first):")
        for p in rb["priority_order"]:
            print(f"    {p['rank']}. [{p['severity']}] {p['title']}")

    for e in entries:
        mark = _SEV_MARK.get(e["severity"], "    ")
        print("\n" + HRL)
        print(f"  {mark} [{e['severity']}] {e['title']}")
        print(f"       Where         : {e['endpoint']}")
        print(f"       What it is    : {e['what_it_is']}")
        print(f"       Why it matters: {e['why_it_matters']}")
        print(f"       Fix           : {e['fix']}")
        print(f"       If exploited  : {e['if_you_do_it']}")

    # Attack-path escalation map from the Analyst layer (if this -> then this).
    if AnalystNarrator is not None:
        try:
            chains = AnalystNarrator(findings=findings, target=target).build().get("attack_paths", [])
        except Exception:
            chains = []
        if chains:
            print("\n" + HR)
            print("  ATTACK-PATH ESCALATION MAP  (if this happens -> this follows)")
            print(HR)
            for i, c in enumerate(chains, 1):
                print(f"\n  Chain {i}: {c.get('name', 'Predicted escalation')}")
                print(f"     Path        : {c.get('chain', '')}")
                print(f"     Confidence  : {c.get('confidence', 'n/a')}")
                print(f"     Blast radius: {c.get('blast_radius', '')}")

    print("\n" + HR)
    print("  Full detail (HTML / Markdown / SARIF) saved in the output directory.")
    print(HR)


def _ask(prompt: str, default: str = "") -> str:
    """input() that is safe when stdin is closed (returns the default)."""
    try:
        val = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return default
    return val or default


def _target_slug(target: str) -> str:
    import re
    host = ScopeEngine.extract_host(target) or "target"
    slug = re.sub(r"[^A-Za-z0-9._-]", "_", host)[:40]
    return slug or "target"


def cmd_start() -> int:
    """Interactive session: welcome screen -> ask target -> scan -> print findings."""
    _print_welcome()

    target = _ask("  Target (URL / host / IP / CIDR): ")
    if not target:
        print("\n[*] No target entered — launching the bundled safe demo lab.\n")
        rc = cmd_quickstart()
        demo_report = Path("evidence/quickstart") / "report.json"
        if demo_report.exists():
            render_terminal_findings(_load_findings_file(demo_report), "http://127.0.0.1:3000 (demo lab)")
        return rc

    # Authorization gate — interactive confirmation before touching a real target.
    ok = _ask(f"  Do you own or have written authorization to test '{target}'? [y/N]: ", "n").lower()
    if ok not in ("y", "yes"):
        print("\n[-] Authorization not confirmed. REVENANT only tests targets you are",
              file=sys.stderr)
        print("    allowed to. Run with no target for the safe demo lab instead.", file=sys.stderr)
        return 1

    default_profile = "web-dast" if target.startswith(("http://", "https://")) else "recon"
    profile = _ask(
        f"  Profile [recon | web-dast | ai-reasoning | full-spectrum] (default {default_profile}): ",
        default_profile,
    )
    out_dir = f"evidence/{_target_slug(target)}"

    print()
    rc = run_mission(
        target=target,
        scope=auto_scope(target),
        profile_name=profile,
        output_dir=out_dir,
    )

    # Re-present what was found, in-terminal, ranked + escalation-mapped.
    report = Path(out_dir) / "report.json"
    if report.exists():
        render_terminal_findings(_load_findings_file(report), target)
    return rc


def build_parser() -> argparse.ArgumentParser:
    """Construct multi-command CLI parser."""
    parser = argparse.ArgumentParser(
        prog="revenant",
        description="REVENANT — Autonomous AI Red Teaming & Cyber Warfare Platform (v2.0)",
        epilog=(
            "Simple usage — give a target, it attacks:\n"
            "  revenant http://target.local        # full-spectrum attack, scope auto-built\n"
            "  revenant 10.0.0.5                    # same, for an IP\n"
            "  revenant quickstart                  # zero-config demo against the bundled lab\n"
            "  revenant doctor                      # what tools/capabilities this host has\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Available platform operations")

    # 0. START SUBCOMMAND — interactive welcome -> target -> findings in terminal
    subparsers.add_parser("start", help="Interactive mode: welcome screen, prompt for a target, print findings")

    # 1. SCAN SUBCOMMAND
    scan_parser = subparsers.add_parser("scan", help="Launch an autonomous security assessment mission")
    scan_parser.add_argument("target", help="Target URL, hostname, IP, CIDR, or manifest")
    scan_parser.add_argument("--profile", default="full-spectrum", help="Mission profile (recon, web-dast, cloud-native, ad-identity, full-spectrum)")
    scan_parser.add_argument("--allowed-hosts", nargs="*", default=["localhost", "127.0.0.1"], help="Allowed hosts")
    scan_parser.add_argument("--allowed-domains", nargs="*", default=[], help="Allowed domains")
    scan_parser.add_argument("--allowed-cidrs", nargs="*", default=[], help="Allowed CIDR blocks")
    scan_parser.add_argument("--allowed-repos", nargs="*", default=[], help="Allowed repository paths")
    scan_parser.add_argument("--allowed-cloud-accounts", nargs="*", default=[], help="Allowed cloud account IDs")
    scan_parser.add_argument("--allowed-container-images", nargs="*", default=[], help="Allowed container image patterns")
    scan_parser.add_argument("--allowed-identity-domains", nargs="*", default=[], help="Allowed Active Directory domains")
    scan_parser.add_argument("--output-dir", default="evidence", help="Report output directory")
    scan_parser.add_argument("--max-iterations", type=int, default=None, help="Maximum agent loop cycles")
    scan_parser.add_argument("--llm-planner", action="store_true",
                             help="Engage the opt-in LLM Planner agent (needs [llm] extra + ANTHROPIC_API_KEY; degrades to heuristic)")

    # 2. PROFILES SUBCOMMAND
    subparsers.add_parser("profiles", help="List available pre-configured assessment mission profiles")

    # 2b. DOCTOR SUBCOMMAND — host capability probe
    subparsers.add_parser("doctor", help="Probe host for installed tools, deps, and state backend")

    # 2c. QUICKSTART SUBCOMMAND — zero-config demo against the bundled lab
    qs_parser = subparsers.add_parser("quickstart", help="Boot the bundled vuln lab and run a demo web-dast scan")
    qs_parser.add_argument("--output-dir", default="evidence/quickstart", help="Report output directory")

    # 2d. ANALYZE SUBCOMMAND — AI Analyst / Narrator over a findings export
    analyze_parser = subparsers.add_parser("analyze", help="Run the AI Analyst over a findings JSON and write analysis.md/json")
    analyze_parser.add_argument("findings_file", help="Path to report.json (or a raw findings JSON list)")
    analyze_parser.add_argument("--output-dir", default=None, help="Where to write analysis.{md,json} (default: alongside the input)")

    # 2e. BRIEF SUBCOMMAND — ReconBLADE-style prioritized findings brief
    brief_parser = subparsers.add_parser("brief", help="Render a ReconBLADE-style prioritized brief from a findings JSON")
    brief_parser.add_argument("findings_file", help="Path to report.json (or a raw findings JSON list)")
    brief_parser.add_argument("--output-dir", default=None, help="Where to write findings_brief.{md,json} (default: alongside the input)")

    # 3. REMEDIATE SUBCOMMAND
    remed_parser = subparsers.add_parser("remediate", help="Generate automated remediation code from a JSON findings export")
    remed_parser.add_argument("findings_file", help="Path to JSON file containing findings")
    remed_parser.add_argument("--output-dir", default="evidence_remediation", help="Directory to export remediation code")

    # 4. ASM SUBCOMMAND
    asm_parser = subparsers.add_parser("asm", help="Run Continuous Attack Surface Management daemon")
    asm_parser.add_argument("action", choices=["daemon"], default="daemon", nargs="?", help="Action to perform")
    asm_parser.add_argument("--targets", nargs="*", default=["http://localhost:3000"], help="Targets to monitor")
    asm_parser.add_argument("--interval", type=int, default=300, help="Polling interval in seconds")
    asm_parser.add_argument("--soar-url", default=None, help="SOAR / Webhook alert URL")

    # 5. SERVE SUBCOMMAND
    serve_parser = subparsers.add_parser("serve", help="Launch REVENANT Control Plane REST API")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Binding host interface")
    serve_parser.add_argument("--port", type=int, default=8000, help="Listening TCP port")

    return parser


SUBCOMMANDS = {"start", "scan", "profiles", "doctor", "quickstart", "analyze", "brief", "remediate", "asm", "serve"}


def run_bare_target(argv: List[str]) -> int:
    """`revenant <target> [--profile ...]` — the simple path: give a target, it attacks.

    Auto-builds the authorized scope from the target and runs the full-spectrum swarm.
    """
    bp = argparse.ArgumentParser(
        prog="revenant",
        description="Give a target, REVENANT attacks it (full-spectrum by default).",
    )
    bp.add_argument("target", help="URL, hostname, IP, or CIDR to assess")
    bp.add_argument("--profile", default="full-spectrum",
                    help="Narrow the attack (recon, web-dast, cloud-native, ad-identity, full-spectrum)")
    bp.add_argument("--output-dir", default="evidence", help="Report output directory")
    bp.add_argument("--max-iterations", type=int, default=None, help="Cap agent loop cycles")
    args = bp.parse_args(argv)
    return run_mission(
        target=args.target,
        scope=auto_scope(args.target),
        profile_name=args.profile,
        output_dir=args.output_dir,
        max_iterations=args.max_iterations,
    )


def main():
    # Force UTF-8 output so the banner/box-drawing and em-dashes never crash or mojibake
    # on a Windows cp1252 console or when stdout is piped/redirected.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    # No arguments at all -> interactive welcome screen (not a usage error).
    argv = sys.argv[1:]
    if not argv:
        sys.exit(cmd_start())

    # Simple path: `revenant <target>` with no subcommand -> full attack on that target.
    if argv and not argv[0].startswith("-") and argv[0] not in SUBCOMMANDS:
        sys.exit(run_bare_target(argv))

    parser = build_parser()
    args = parser.parse_args()

    # Case 0: Subcommand START — interactive mode
    if args.subcommand == "start":
        sys.exit(cmd_start())

    # Case A: Subcommand PROFILES
    if args.subcommand == "profiles":
        print(HR)
        print("  REVENANT MISSION PROFILES")
        print(HR)
        for p in list_profiles():
            print(f"\n[•] Profile: {p.name.upper()}")
            print(f"    Description:    {p.description}")
            print(f"    Target Type:    {p.target_type}")
            print(f"    Active Agents:  {', '.join(p.active_agents)}")
            print(f"    Default Limit:  {p.max_iterations} iterations, {p.timeout_seconds}s timeout")
            for cap in p.capabilities:
                print(f"      - {cap}")
        print("\n" + HR)
        sys.exit(0)

    # Case A2: Subcommand DOCTOR
    elif args.subcommand == "doctor":
        sys.exit(cmd_doctor())

    # Case A3: Subcommand QUICKSTART
    elif args.subcommand == "quickstart":
        sys.exit(cmd_quickstart(output_dir=args.output_dir))

    # Case A4: Subcommand ANALYZE — AI Analyst / Narrator
    elif args.subcommand == "analyze":
        sys.exit(cmd_analyze(args.findings_file, output_dir=args.output_dir))

    # Case A5: Subcommand BRIEF — ReconBLADE-style findings brief
    elif args.subcommand == "brief":
        sys.exit(cmd_brief(args.findings_file, output_dir=args.output_dir))

    # Case B: Subcommand REMEDIATE
    elif args.subcommand == "remediate":
        f_path = Path(args.findings_file)
        if not f_path.exists():
            print(f"[-] Findings file not found: {f_path}", file=sys.stderr)
            sys.exit(1)
        raw_data = json.loads(f_path.read_text(encoding="utf-8"))
        findings_list = []
        raw_findings = raw_data.get("findings", raw_data) if isinstance(raw_data, dict) else raw_data
        for item in raw_findings:
            if isinstance(item, dict):
                try:
                    findings_list.append(Finding(**item))
                except Exception:
                    pass

        engine = RemediationEngine(output_dir=args.output_dir)
        artifacts = engine.remediate_campaign(findings_list)
        exported = engine.export_artifacts(artifacts)
        print(f"[+] Remediation Complete: Generated {len(artifacts)} fixes across {len(exported)} files in '{args.output_dir}'")
        sys.exit(0)

    # Case C: Subcommand ASM
    elif args.subcommand == "asm":
        daemon = ASMDaemon(poll_interval_seconds=args.interval, soar_url=args.soar_url)
        for t in args.targets:
            daemon.register_target(t)
        print(f"[*] Starting REVENANT Continuous ASM Daemon (Interval: {args.interval}s, Targets: {args.targets})...")
        res = daemon.execute_cycle()
        print(f"[+] ASM Baseline established: {res['drift']}")
        if args.action == "daemon":
            import asyncio
            try:
                asyncio.run(daemon.run_daemon())
            except (KeyboardInterrupt, SystemExit):
                pass
        sys.exit(0)

    # Case D: Subcommand SERVE
    elif args.subcommand == "serve":
        import uvicorn
        print(f"[*] Launching REVENANT Control Plane API on http://{args.host}:{args.port}")
        uvicorn.run("control_plane.api.main:app", host=args.host, port=args.port, reload=False)
        sys.exit(0)

    # Case E: Subcommand SCAN
    elif args.subcommand == "scan":
        target = args.target
        # Naming the target authorizes it; explicit --allowed-* flags extend the scope.
        scope = auto_scope(target)
        scope.allowed_hosts = sorted(set(scope.allowed_hosts) | set(args.allowed_hosts))
        scope.allowed_domains = sorted(set(scope.allowed_domains) | set(args.allowed_domains))
        scope.allowed_cidrs = sorted(set(scope.allowed_cidrs) | set(args.allowed_cidrs))
        scope.allowed_repos = sorted(set(scope.allowed_repos) | set(args.allowed_repos))
        scope.allowed_cloud_accounts = sorted(set(scope.allowed_cloud_accounts) | set(args.allowed_cloud_accounts))
        scope.allowed_container_images = sorted(set(scope.allowed_container_images) | set(args.allowed_container_images))
        scope.allowed_identity_domains = sorted(set(scope.allowed_identity_domains) | set(args.allowed_identity_domains))
        sys.exit(run_mission(
            target=target,
            scope=scope,
            profile_name=args.profile,
            output_dir=args.output_dir,
            max_iterations=args.max_iterations,
            llm_planner=args.llm_planner,
        ))

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
