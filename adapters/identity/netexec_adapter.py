"""
REVENANT — NetExec (nxc) Active Directory & Network Protocol Security Adapter
Conducts active network protocol assessments across SMB, LDAP, and WinRM:
- SMB signing requirement verification & Relay vulnerability assessment (T1557.001)
- Null-session & Guest account share access permissions (CWE-287 / CWE-732)
- Active Directory AS-REP roasting & Kerberoasting extraction (T1558.003 / T1558.004)
- Password spraying with strict lockout threshold protection (T1110.003)
Executes natively in WSL2 or Windows using the verified standalone nxc binary.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from adapters.base import AdapterResult, BaseAdapter
from control_plane.schemas.models import Finding, HostAsset, Severity
from control_plane.schemas.scope import ScopeManifest

logger = logging.getLogger("revenant.adapters.netexec")


class NetExecAdapter(BaseAdapter):
    """Adapter for NetExec (nxc) active network protocol auditing and credential verification."""

    def __init__(
        self,
        binary_override: Optional[str] = None,
        use_wsl: bool = True,
    ):
        super().__init__(
            name="netexec",
            category="identity",
            version="1.5.0+",
            binary_override=binary_override,
            use_wsl=use_wsl,
        )

    def is_installed(self) -> bool:
        return True

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        protocol = params.get("protocol", "smb").lower()
        cmd = [self.binary_path or "nxc", protocol, target]

        # Credentials (or anonymous/null session probe by default)
        username = params.get("username", "")
        password = params.get("password", "")
        if username or password or params.get("probe_null_session", True):
            cmd.extend(["-u", username if username else "''"])
            cmd.extend(["-p", password if password else "''"])

        # Safety & Lockout Controls
        ufail_limit = params.get("ufail_limit", 2)
        cmd.extend(["--ufail-limit", str(ufail_limit)])

        if "jitter" in params:
            cmd.extend(["--jitter", str(params["jitter"])])

        timeout = params.get("timeout", 10)
        cmd.extend(["--timeout", str(timeout)])
        cmd.append("--no-progress")

        # Protocol-specific options
        if protocol == "smb":
            if params.get("shares", True):
                cmd.append("--shares")
            if params.get("pass_pol", False):
                cmd.append("--pass-pol")
        elif protocol == "ldap":
            if params.get("asreproast", False):
                cmd.append("--asreproast")
            if params.get("kerberoasting", False):
                cmd.append("--kerberoasting")

        return cmd

    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        findings: List[Finding] = []
        assets: List[HostAsset] = []

        combined = stdout + "\n" + stderr
        lines = [line.strip() for line in combined.splitlines() if line.strip()]

        discovered_host = target
        discovered_domain = ""
        discovered_os = ""

        for line in lines:
            # 1. Host information line parsing
            # e.g.: SMB  10.0.0.5  445  DC01  [*] Windows 10 / Server 2019 (name:DC01) (domain:REVENANT.LOCAL) (signing:False) (SMBv1:False)
            name_match = re.search(r"\(name:([^\)]+)\)", line, re.IGNORECASE)
            dom_match = re.search(r"\(domain:([^\)]+)\)", line, re.IGNORECASE)
            if dom_match:
                discovered_domain = dom_match.group(1).strip()
            if name_match:
                discovered_host = name_match.group(1).strip()

            # 2. SMB Signing Check (CWE-306 / T1557.001 - NTLM Relay risk)
            if re.search(r"\(signing:\s*False\)", line, re.IGNORECASE) or "signing:False" in line:
                findings.append(
                    Finding(
                        title=f"SMB Signing Not Required on {discovered_host}",
                        description=(
                            f"Host {discovered_host} ({target}) has SMB message signing disabled or not required. "
                            "Unauthenticated attackers on the local network segment can intercept and relay NTLM authentication "
                            "sessions to gain unauthorized access or domain privileges."
                        ),
                        severity=Severity.HIGH,
                        target=target,
                        cwe="CWE-306",
                        cvss_score=7.5,
                        mitre_attack_ids=["T1557.001"],
                        tool="netexec",
                        evidence=f"protocol=smb; signing=False; raw={line}",
                        remediation="Configure Group Policy to require SMB packet signing (Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> Microsoft network server: Digitally sign communications (always)).",
                    )
                )

            # 3. Guest Account or Null-Session Access (CWE-287 / T1078)
            if re.search(r"\[\+\].*(?:Guest|anonymous).*(?:READ|WRITE|STATUS_SUCCESS)", line, re.IGNORECASE):
                findings.append(
                    Finding(
                        title=f"Anonymous / Guest Access Permitted on {discovered_host}",
                        description=(
                            f"Target {target} allows unauthenticated or Guest session access to SMB shares. "
                            "Attackers can enumerate network shares, harvest sensitive files, or identify writable folders."
                        ),
                        severity=Severity.HIGH,
                        target=target,
                        cwe="CWE-287",
                        cvss_score=7.3,
                        mitre_attack_ids=["T1078.001"],
                        tool="netexec",
                        evidence=line,
                        remediation="Disable anonymous/guest SMB access and enforce authenticated SMB access control lists.",
                    )
                )

            # 4. Kerberoasting Hash / User Extraction (CWE-522 / T1558.003)
            if "$krb5tgs$" in line or re.search(r"(?:Found Kerberoastable user|Kerberoasting):?\s*(\S+)", line, re.IGNORECASE):
                user_match = re.search(r"(?:Found Kerberoastable user|Kerberoasting):?\s*(\S+)", line, re.IGNORECASE)
                user = user_match.group(1) if user_match else "Service Account"
                findings.append(
                    Finding(
                        title=f"Kerberoastable Service Principal Identified: {user}",
                        description=(
                            f"Active Directory user account '{user}' has a registered Service Principal Name (SPN). "
                            "Any authenticated domain user can request a Kerberos TGS ticket for this account and crack "
                            "the password hash offline."
                        ),
                        severity=Severity.CRITICAL,
                        target=f"{user}@{discovered_domain or target}",
                        cwe="CWE-522",
                        cvss_score=8.2,
                        mitre_attack_ids=["T1558.003"],
                        tool="netexec",
                        evidence=f"user={user}; raw={line}",
                        remediation="Ensure service accounts utilize AES-256 Kerberos encryption with complex 25+ character passwords or transition to Group Managed Service Accounts (gMSA).",
                    )
                )

            # 5. AS-REP Roasting Extraction (CWE-522 / T1558.004)
            if "$krb5asrep$" in line or re.search(r"(?:AS-REP roastable user|AS-REP Roasting):?\s*(\S+)", line, re.IGNORECASE):
                user_match = re.search(r"(?:AS-REP roastable user|AS-REP Roasting):?\s*(\S+)", line, re.IGNORECASE)
                user = user_match.group(1) if user_match else "User Account"
                findings.append(
                    Finding(
                        title=f"AS-REP Roastable Account Identified: {user}",
                        description=(
                            f"Active Directory user '{user}' does not require Kerberos pre-authentication (DONT_REQ_PREAUTH). "
                            "An attacker can request an AS-REP ticket without knowing the user's password and crack the hash offline."
                        ),
                        severity=Severity.HIGH,
                        target=f"{user}@{discovered_domain or target}",
                        cwe="CWE-522",
                        cvss_score=7.8,
                        mitre_attack_ids=["T1558.004"],
                        tool="netexec",
                        evidence=f"user={user}; raw={line}",
                        remediation="Enable 'Do not require Kerberos preauthentication' restriction (uncheck the attribute) for all Active Directory user accounts.",
                    )
                )

            # 6. Valid Credentials Verified / Pwn3d
            if "Pwn3d!" in line or re.search(r"\[\+\].*\(Pwn3d!\)", line):
                findings.append(
                    Finding(
                        title=f"High-Privilege Administrative Access Confirmed on {discovered_host}",
                        description=(
                            f"Administrative session confirmed on host {discovered_host} ({target}). "
                            "Supplied credentials possess local Administrator or Domain Administrator privileges."
                        ),
                        severity=Severity.CRITICAL,
                        target=target,
                        cwe="CWE-284",
                        cvss_score=9.8,
                        mitre_attack_ids=["T1078.002"],
                        tool="netexec",
                        evidence=line,
                        remediation="Restrict administrative access, implement Local Administrator Password Solution (LAPS), and enforce multi-factor authentication.",
                    )
                )

        # Discovered host asset
        assets.append(
            HostAsset(
                ip=target if re.match(r"^\d+\.\d+\.\d+\.\d+$", target) else None,
                hostname=discovered_host if discovered_host != target else (discovered_domain or target),
                metadata={
                    "source": "netexec",
                    "tags": ["identity", "active-directory", discovered_domain] if discovered_domain else ["identity"],
                    "domain": discovered_domain,
                },
            )
        )

        return findings, assets

    def run(
        self,
        target: str,
        scope: ScopeManifest,
        params: Optional[Dict[str, Any]] = None,
        timeout_seconds: int = 60,
    ) -> AdapterResult:
        params = params or {}
        self.validate_target_scope(target, scope)

        # Check if target is a file containing NetExec output for offline / fixture parsing
        if os.path.isfile(target):
            try:
                with open(target, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                findings, assets = self.parse_output(content, "", target)
                return AdapterResult(
                    tool_name=self.name,
                    target=target,
                    exit_code=0,
                    findings=findings,
                    discovered_assets=assets,
                    raw_stdout=content,
                    duration_seconds=0.01,
                )
            except Exception as e:
                logger.warning(f"NetExec fixture parse failed: {e}")

        # Live invocation via WSL2 or native
        return super().run(target, scope, params=params, timeout_seconds=timeout_seconds)
