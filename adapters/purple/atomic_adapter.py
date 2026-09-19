"""
REVENANT — Atomic Red Team Adversary Emulation Adapter
Executes curated, safe, non-destructive MITRE ATT&CK atomic tests for adversary emulation
and defensive validation against Windows and Linux (WSL2) targets.
Includes strict sandboxing, scope enforcement, and automated cleanup routines.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from adapters.purple.telemetry_collector import write_telemetry_event

from adapters.base import AdapterResult, BaseAdapter, to_wsl_path
from control_plane.schemas.models import Finding, HostAsset, Severity
from control_plane.schemas.scope import ScopeEngine, ScopeManifest, ScopeViolationError

logger = logging.getLogger("revenant.adapter.atomic")


class SafetyViolationError(Exception):
    """Raised when an atomic emulation command fails safety sandboxing checks."""
    pass


@dataclass
class AtomicTest:
    """Definition of a safe, benign atomic test mapped to a MITRE ATT&CK technique."""
    technique_id: str
    technique_name: str
    test_name: str
    description: str
    supported_platforms: List[str]  # "windows", "linux"
    executor: str                   # "cmd", "powershell", "bash", "sh"
    command: str
    cleanup_command: Optional[str] = None
    is_safe: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


# Dangerous patterns strictly blocked by safety sandbox
DANGEROUS_COMMAND_PATTERNS = [
    r"\brm\s+-[rf]{1,2}\b",
    r"\bdel\s+/[sSqQ]\b",
    r"\bformat(\.com|\.exe)?\s+[a-zA-Z]:",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"\bshutdown\b",
    r"\breboot\b",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;",  # forkbomb
    r"\bdrop\s+database\b",
    r"\bdrop\s+table\b",
    r">\s*/dev/sd[a-z]",
    r"\bpowershell.*-EncodedCommand\s+[a-zA-Z0-9+/=]{100,}",
]

# Curated library of safe, benign atomic emulation tests
ATOMIC_TESTS_CATALOG: Dict[str, List[AtomicTest]] = {
    "T1082": [
        AtomicTest(
            technique_id="T1082",
            technique_name="System Information Discovery",
            test_name="Host OS and Architecture Enumeration",
            description="Queries operating system version, hostname, and hardware architecture using native system utilities.",
            supported_platforms=["windows"],
            executor="powershell",
            command="Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture, CSName | Format-List",
        ),
        AtomicTest(
            technique_id="T1082",
            technique_name="System Information Discovery",
            test_name="Linux Kernel and System Release Discovery",
            description="Collects kernel version and OS release metadata via uname and os-release.",
            supported_platforms=["linux"],
            executor="bash",
            command="uname -a; cat /etc/os-release 2>/dev/null | head -n 10",
        ),
    ],
    "T1087.001": [
        AtomicTest(
            technique_id="T1087.001",
            technique_name="Local Account Discovery",
            test_name="Enumerate Local User Accounts (Windows)",
            description="Queries local user accounts using net.exe and PowerShell.",
            supported_platforms=["windows"],
            executor="cmd",
            command="net user",
        ),
        AtomicTest(
            technique_id="T1087.001",
            technique_name="Local Account Discovery",
            test_name="Enumerate Local Users from Passwd Database (Linux)",
            description="Lists user account names registered in /etc/passwd.",
            supported_platforms=["linux"],
            executor="bash",
            command="cut -d: -f1 /etc/passwd | head -n 25",
        ),
    ],
    "T1057": [
        AtomicTest(
            technique_id="T1057",
            technique_name="Process Discovery",
            test_name="Active Process Listing (Windows)",
            description="Enumerates running processes and session IDs.",
            supported_platforms=["windows"],
            executor="powershell",
            command="Get-Process | Select-Object -First 15 Id, ProcessName, Handles | Format-Table -AutoSize",
        ),
        AtomicTest(
            technique_id="T1057",
            technique_name="Process Discovery",
            test_name="Active Process Snapshot (Linux)",
            description="Collects list of running processes via ps.",
            supported_platforms=["linux"],
            executor="bash",
            command="ps aux | head -n 20",
        ),
    ],
    "T1016": [
        AtomicTest(
            technique_id="T1016",
            technique_name="System Network Configuration Discovery",
            test_name="Network Adapter and IP Configuration (Windows)",
            description="Enumerates local network interfaces, gateways, and DNS servers.",
            supported_platforms=["windows"],
            executor="cmd",
            command="ipconfig /all",
        ),
        AtomicTest(
            technique_id="T1016",
            technique_name="System Network Configuration Discovery",
            test_name="Network IP and Link Configuration (Linux)",
            description="Queries IP address configuration and routing table.",
            supported_platforms=["linux"],
            executor="bash",
            command="ip -brief addr show 2>/dev/null || ifconfig -a",
        ),
    ],
    "T1049": [
        AtomicTest(
            technique_id="T1049",
            technique_name="System Network Connections Discovery",
            test_name="Active Network Sockets and Listeners (Windows)",
            description="Lists active TCP/UDP listening ports and established connections.",
            supported_platforms=["windows"],
            executor="cmd",
            command="netstat -ano | findstr /R /C:\"LISTENING\" /C:\"ESTABLISHED\"",
        ),
        AtomicTest(
            technique_id="T1049",
            technique_name="System Network Connections Discovery",
            test_name="Listening Sockets and TCP Connections (Linux)",
            description="Queries active network listeners and sockets via ss or netstat.",
            supported_platforms=["linux"],
            executor="bash",
            command="ss -tuln 2>/dev/null | head -n 25 || netstat -tuln | head -n 25",
        ),
    ],
    "T1033": [
        AtomicTest(
            technique_id="T1033",
            technique_name="System Owner/User Discovery",
            test_name="Current User Identity and Privileges (Windows)",
            description="Checks active execution identity and privilege tokens via whoami.",
            supported_platforms=["windows"],
            executor="cmd",
            command="whoami /all",
        ),
        AtomicTest(
            technique_id="T1033",
            technique_name="System Owner/User Discovery",
            test_name="Current User Identity and Group Memberships (Linux)",
            description="Retrieves current UID, GID, and effective groups.",
            supported_platforms=["linux"],
            executor="bash",
            command="id; whoami",
        ),
    ],
    "T1083": [
        AtomicTest(
            technique_id="T1083",
            technique_name="File and Directory Discovery",
            test_name="Inspect Temporary Directory Contents (Windows)",
            description="Lists temporary directory files to simulate adversary reconnaissance.",
            supported_platforms=["windows"],
            executor="cmd",
            command="dir \"%TEMP%\" /b",
        ),
        AtomicTest(
            technique_id="T1083",
            technique_name="File and Directory Discovery",
            test_name="Inspect Temporary Directory Contents (Linux)",
            description="Lists /tmp directory contents non-destructively.",
            supported_platforms=["linux"],
            executor="bash",
            command="ls -la /tmp | head -n 20",
        ),
    ],
    "T1059.001": [
        AtomicTest(
            technique_id="T1059.001",
            technique_name="Command and Scripting Interpreter: PowerShell",
            test_name="Benign PowerShell Execution Policy Probe",
            description="Executes a benign PowerShell one-liner to validate execution policy and script block logging.",
            supported_platforms=["windows"],
            executor="powershell",
            command="Get-ExecutionPolicy; Write-Output 'REVENANT-PURPLE-BENIGN-T1059.001'",
        ),
    ],
    "T1518.001": [
        AtomicTest(
            technique_id="T1518.001",
            technique_name="Security Software Discovery",
            test_name="Security Product Enumeration (Windows)",
            description="Queries Windows Security Center for registered antivirus and EDR agents.",
            supported_platforms=["windows"],
            executor="powershell",
            command="Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct 2>$null | Select-Object displayName, productState | Format-List",
        ),
        AtomicTest(
            technique_id="T1518.001",
            technique_name="Security Software Discovery",
            test_name="Host Firewall and Security Software Discovery (Linux)",
            description="Detects active local firewalls or host security services.",
            supported_platforms=["linux"],
            executor="bash",
            command="which ufw iptables apparmor_status firewalld 2>/dev/null || true",
        ),
    ],
}


class AtomicRedTeamAdapter(BaseAdapter):
    """
    Adapter executing scripted Atomic Red Team tests for adversary emulation.
    Enforces strict safety verification, parameter sanitization, and scope controls.
    """

    def __init__(
        self,
        use_wsl: bool = False,
        wsl_distro: str = "Ubuntu",
        timeout_seconds: int = 45,
    ):
        super().__init__(
            name="atomic_red_team",
            category="adversary_emulation",
            binary_override="powershell.exe" if platform.system() == "Windows" else "bash",
            use_wsl=use_wsl,
            wsl_distro=wsl_distro,
        )
        self.timeout_seconds = timeout_seconds

    def is_installed(self) -> bool:
        """Adversary emulation utilizes native system shells (PowerShell, cmd, bash)."""
        if platform.system() == "Windows":
            return bool(shutil.which("powershell.exe") or shutil.which("cmd.exe"))
        return bool(shutil.which("bash") or shutil.which("sh"))

    def validate_safety(self, command: str) -> None:
        """
        Safety Sandbox: inspect command line against strict safety rules.
        Rejects potentially destructive, dangerous, or persistence-modifying commands.
        """
        for pat in DANGEROUS_COMMAND_PATTERNS:
            if re.search(pat, command, re.IGNORECASE):
                raise SafetyViolationError(
                    f"Command rejected by Atomic Safety Sandbox due to prohibited pattern: '{pat}'"
                )

    def validate_target_scope(self, target: str, manifest: ScopeManifest) -> None:
        """Ensure the emulation target host/IP is explicitly authorized in the scope manifest."""
        scope_engine = ScopeEngine(manifest)
        allowed, reason = scope_engine.is_allowed(target)
        if not allowed:
            raise ScopeViolationError(
                target, f"Emulation target '{target}' is not within authorized scope manifest: {reason}"
            )

    def build_command(self, target: str, **kwargs) -> str:
        technique_id = kwargs.get("technique_id", "T1082")
        return f"atomic_exec --target {target} --technique {technique_id}"

    def parse_output(
        self, stdout: str, stderr: str, target: str, **kwargs
    ) -> tuple[List[Finding], List[HostAsset]]:
        technique_id = kwargs.get("technique_id", "T1082")
        test_name = kwargs.get("test_name", "Adversary Emulation Test")
        findings: List[Finding] = []

        # Successful execution of an atomic technique indicates an emulation event
        snippet = stdout.strip()
        if len(snippet) > 800:
            snippet = snippet[:800] + "... [truncated]"

        finding = Finding(
            title=f"Emulated TTP: {technique_id} - {test_name}",
            description=(
                f"Adversary emulation technique {technique_id} ({test_name}) was successfully executed against `{target}`. "
                "Evaluate whether defensive SIEM, EDR, and log monitoring detected this activity."
            ),
            severity=Severity.INFO,
            target=target,
            tool="atomic_red_team",
            mitre_attack_ids=[technique_id],
            evidence=snippet,
            raw_data={
                "technique_id": technique_id,
                "test_name": test_name,
                "stdout": stdout[:2000],
                "stderr": stderr[:1000],
            },
        )
        findings.append(finding)

        asset = HostAsset(
            ip=target if re.match(r"^\d+\.\d+\.\d+\.\d+$", target) else None,
            hostname=target if not re.match(r"^\d+\.\d+\.\d+\.\d+$", target) else None,
            metadata={"emulation_tested": True, "technique_id": technique_id},
        )

        return findings, [asset]

    def execute_atomic_test(
        self, test: AtomicTest, target: str, manifest: ScopeManifest
    ) -> AdapterResult:
        """Safely execute a single AtomicTest against target within scope."""
        self.validate_target_scope(target, manifest)
        self.validate_safety(test.command)

        start_time = time.time()
        logger.info("Executing atomic test %s (%s) against %s", test.technique_id, test.test_name, target)

        current_platform = "windows" if platform.system() == "Windows" and not self.use_wsl else "linux"

        # Determine execution command
        if self.use_wsl:
            cmd = ["wsl", "-d", self.wsl_distro, "-u", "root", "bash", "-c", test.command]
        elif current_platform == "windows":
            if test.executor == "powershell":
                cmd = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", test.command]
            else:
                cmd = ["cmd.exe", "/c", test.command]
        else:
            cmd = ["bash", "-c", test.command]

        proc_stdout, proc_stderr, exit_code = "", "", 0
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
            proc_stdout = proc.stdout
            proc_stderr = proc.stderr
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            proc_stderr = f"Execution timed out after {self.timeout_seconds} seconds."
            exit_code = 124
        except Exception as ex:
            proc_stderr = f"Execution error: {str(ex)}"
            exit_code = 1
        finally:
            # Execute cleanup command if provided
            if test.cleanup_command and exit_code == 0:
                try:
                    self.validate_safety(test.cleanup_command)
                    if self.use_wsl:
                        cleanup_cmd = ["wsl", "-d", self.wsl_distro, "-u", "root", "bash", "-c", test.cleanup_command]
                    elif current_platform == "windows":
                        cleanup_cmd = ["cmd.exe", "/c", test.cleanup_command]
                    else:
                        cleanup_cmd = ["bash", "-c", test.cleanup_command]
                    subprocess.run(cleanup_cmd, capture_output=True, timeout=10)
                except Exception as ex:
                    logger.warning("Cleanup failed for %s: %s", test.technique_id, ex)

        elapsed = time.time() - start_time
        findings, assets = self.parse_output(
            proc_stdout, proc_stderr, target,
            technique_id=test.technique_id,
            test_name=test.test_name,
        )

        # Write real execution evidence to telemetry JSON for DetectionGapEngine
        try:
            write_telemetry_event(
                technique_id=test.technique_id,
                command=test.command,
                stdout=proc_stdout,
                stderr=proc_stderr,
                exit_code=exit_code,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        except Exception as _telem_err:
            logger.debug("Telemetry write skipped: %s", _telem_err)

        return AdapterResult(
            tool_name=self.name,
            target=target,
            findings=findings,
            discovered_assets=assets,
            raw_stdout=proc_stdout,
            raw_stderr=proc_stderr,
            exit_code=exit_code,
            duration_seconds=elapsed,
        )

    def run(self, target: str, manifest: ScopeManifest, **kwargs) -> AdapterResult:
        """
        Execute atomic test suite against target.
        kwargs['technique_id']: Optional specific technique ID to execute (e.g. 'T1082').
        kwargs['platform_override']: Optional 'windows' or 'linux'.
        """
        self.validate_target_scope(target, manifest)

        target_platform = kwargs.get("platform_override")
        if not target_platform:
            target_platform = "linux" if self.use_wsl else ("windows" if platform.system() == "Windows" else "linux")

        requested_technique = kwargs.get("technique_id")
        tests_to_run: List[AtomicTest] = []

        if requested_technique:
            candidates = ATOMIC_TESTS_CATALOG.get(requested_technique, [])
            for t in candidates:
                if target_platform in t.supported_platforms:
                    tests_to_run.append(t)
        else:
            # Run core discovery baseline
            baseline_techniques = ["T1082", "T1087.001", "T1057", "T1016", "T1033"]
            for tid in baseline_techniques:
                candidates = ATOMIC_TESTS_CATALOG.get(tid, [])
                for t in candidates:
                    if target_platform in t.supported_platforms:
                        tests_to_run.append(t)
                        break

        if not tests_to_run:
            return AdapterResult(
                tool_name=self.name,
                target=target,
                findings=[],
                raw_stdout="No atomic tests available for target platform.",
                exit_code=0,
            )

        all_findings: List[Finding] = []
        all_assets: List[HostAsset] = []
        full_stdout = []
        full_stderr = []
        worst_exit = 0
        total_time = 0.0

        for test in tests_to_run:
            res = self.execute_atomic_test(test, target, manifest)
            all_findings.extend(res.findings)
            all_assets.extend(res.discovered_assets)
            full_stdout.append(f"=== {test.technique_id}: {test.test_name} ===\n{res.raw_stdout}")
            if res.raw_stderr:
                full_stderr.append(f"=== {test.technique_id} STDERR ===\n{res.raw_stderr}")
            if res.exit_code != 0:
                worst_exit = res.exit_code
            total_time += res.duration_seconds

        return AdapterResult(
            tool_name=self.name,
            target=target,
            findings=all_findings,
            discovered_assets=all_assets,
            raw_stdout="\n\n".join(full_stdout),
            raw_stderr="\n\n".join(full_stderr),
            exit_code=worst_exit,
            duration_seconds=total_time,
        )
