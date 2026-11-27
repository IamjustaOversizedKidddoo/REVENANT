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


def run_mission(
    target: str,
    scope: ScopeManifest,
    profile_name: str = "full-spectrum",
    output_dir: str = "evidence",
    max_iterations: Optional[int] = None,
    verbose: bool = True,
) -> int:
    """
    Execute a full autonomous security mission against a sanctioned target.
    Returns 0 on success, 1 on error/scope violation.
    """
    profile = get_profile(profile_name) or get_profile("full-spectrum")
    effective_iterations = max_iterations if max_iterations is not None else profile.max_iterations

    if verbose:
        print("=" * 64)
        print("   ██████╗ ███████╗██╗   ██╗███████╗███╗   ██╗ █████╗ ███╗   ██╗████████╗")
        print("   ██╔══██╗██╔════╝██║   ██║██╔════╝████╗  ██║██╔══██╗████╗  ██║╚══██╔══╝")
        print("   ██████╔╝█████╗  ██║   ██║█████╗  ██╔██╗ ██║███████║██╔██╗ ██║   ██║   ")
        print("   ██╔══██╗██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██╔══██║██║╚██╗██║   ██║   ")
        print("   ██║  ██║███████╗ ╚████╔╝ ███████╗██║ ╚████║██║  ██║██║ ╚████║   ██║   ")
        print("   ╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ")
        print("            AUTONOMOUS AI RED TEAMING & CYBER WARFARE PLATFORM           ")
        print("=" * 64)
        print(f"[*] Target:             {target}")
        print(f"[*] Mission Profile:    {profile.name.upper()} ({profile.description})")
        print(f"[*] Active Agents:      {', '.join(profile.active_agents)}")
        print(f"[*] Max Iterations:     {effective_iterations}")
        print(f"[*] Output Directory:   {output_dir}")
        print("-" * 64)

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
    orchestrator = Orchestrator(blackboard=blackboard, active_agents=profile.active_agents)

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
        print("-" * 64)
        print("[+] Mission Complete!")
        print(f"    - Iterations Run:    {summary.get('iterations_run', 0)}")
        print(f"    - Discovered Assets: {summary.get('total_assets', 0)}")
        print(f"    - Confirmed Flaws:   {summary.get('total_findings', 0)}")
        for sev, count in summary.get("findings_by_severity", {}).items():
            if count > 0:
                print(f"      * {sev}: {count}")

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

    if verbose:
        print("-" * 64)
        print(f"[+] Mission artifacts saved to: {out_path.resolve()}")
        print(f"    - Executive Markdown:  {md_file.name}")
        print(f"    - Interactive HTML:    {html_file.name}")
        print(f"    - Static SARIF v2.1:   {sarif_file.name}")
        print(f"    - Raw Telemetry JSON:  {json_file.name}")
        print(f"    - MITRE ATT&CK Matrix: {nav_file.name}")
        print("=" * 64)

    return 0


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
    print("=" * 64)
    print("  REVENANT DOCTOR - host capability probe")
    print("=" * 64)

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

    # 3. State backend
    state = os.environ.get("REVENANT_STATE", "memory")
    print("\n[ Mission state backend ]")
    print(f"  REVENANT_STATE = {state}"
          f"{'  (ephemeral - set to sqlite for durability)' if state == 'memory' else ''}")

    # 4. Profile readiness
    print("\n[ Profile readiness ]  (native capability always available)")
    for p in list_profiles():
        print(f"  - {p.name}")
    print("\n" + "=" * 64)
    print("  Tip: missing tools can run containerized at work — core install stays light.")
    print("=" * 64)
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


def build_parser() -> argparse.ArgumentParser:
    """Construct multi-command CLI parser."""
    parser = argparse.ArgumentParser(
        prog="revenant",
        description="REVENANT — Autonomous AI Red Teaming & Cyber Warfare Platform (v2.0)",
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Available platform operations")

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

    # 2. PROFILES SUBCOMMAND
    subparsers.add_parser("profiles", help="List available pre-configured assessment mission profiles")

    # 2b. DOCTOR SUBCOMMAND — host capability probe
    subparsers.add_parser("doctor", help="Probe host for installed tools, deps, and state backend")

    # 2c. QUICKSTART SUBCOMMAND — zero-config demo against the bundled lab
    qs_parser = subparsers.add_parser("quickstart", help="Boot the bundled vuln lab and run a demo web-dast scan")
    qs_parser.add_argument("--output-dir", default="evidence/quickstart", help="Report output directory")

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

    # Backward compatibility: Root level target argument if no subcommand specified
    parser.add_argument("legacy_target", nargs="?", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--output-dir", default="evidence", help=argparse.SUPPRESS)
    parser.add_argument("--max-iterations", type=int, default=25, help=argparse.SUPPRESS)
    parser.add_argument("--profile", default="full-spectrum", help=argparse.SUPPRESS)

    return parser


def main():
    # Force UTF-8 output so the banner/box-drawing and em-dashes never crash or mojibake
    # on a Windows cp1252 console or when stdout is piped/redirected.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = build_parser()
    args = parser.parse_args()

    # Case A: Subcommand PROFILES
    if args.subcommand == "profiles":
        print("=" * 64)
        print("  REVENANT MISSION PROFILES")
        print("=" * 64)
        for p in list_profiles():
            print(f"\n[•] Profile: {p.name.upper()}")
            print(f"    Description:    {p.description}")
            print(f"    Target Type:    {p.target_type}")
            print(f"    Active Agents:  {', '.join(p.active_agents)}")
            print(f"    Default Limit:  {p.max_iterations} iterations, {p.timeout_seconds}s timeout")
            for cap in p.capabilities:
                print(f"      - {cap}")
        print("\n" + "=" * 64)
        sys.exit(0)

    # Case A2: Subcommand DOCTOR
    elif args.subcommand == "doctor":
        sys.exit(cmd_doctor())

    # Case A3: Subcommand QUICKSTART
    elif args.subcommand == "quickstart":
        sys.exit(cmd_quickstart(output_dir=args.output_dir))

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
        scope = ScopeManifest(
            allowed_hosts=args.allowed_hosts,
            allowed_domains=args.allowed_domains,
            allowed_cidrs=args.allowed_cidrs,
            allowed_repos=args.allowed_repos,
            allowed_cloud_accounts=args.allowed_cloud_accounts,
            allowed_container_images=args.allowed_container_images,
            allowed_identity_domains=args.allowed_identity_domains,
        )
        sys.exit(run_mission(
            target=target,
            scope=scope,
            profile_name=args.profile,
            output_dir=args.output_dir,
            max_iterations=args.max_iterations,
        ))

    # Case F: Legacy positional target (backward compatibility)
    elif args.legacy_target:
        scope = ScopeManifest(
            allowed_hosts=["localhost", "127.0.0.1", args.legacy_target],
        )
        sys.exit(run_mission(
            target=args.legacy_target,
            scope=scope,
            profile_name=getattr(args, "profile", "full-spectrum"),
            output_dir=getattr(args, "output_dir", "evidence"),
            max_iterations=getattr(args, "max_iterations", 25),
        ))

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
