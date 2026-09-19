"""
REVENANT — CloudFox Offensive Cloud Security Enumeration Adapter
Conducts automated offensive cloud enumeration for AWS and Azure environments:
- High-privilege IAM roles and privilege escalation paths (T1078.004)
- Exposed S3 buckets and anonymous read/write permissions (CWE-732 / T1530)
- EC2 instances with IMDSv1 enabled or exposed metadata tokens (T1552.005)
- IAM credentials, access keys, and cross-account trust relationships.
Executes natively in WSL2 or Windows using the verified standalone cloudfox binary.
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

logger = logging.getLogger("revenant.adapters.cloudfox")


class CloudFoxAdapter(BaseAdapter):
    """Adapter for CloudFox automated offensive cloud enumeration."""

    def __init__(
        self,
        binary_override: Optional[str] = None,
        use_wsl: bool = True,
    ):
        super().__init__(
            name="cloudfox",
            category="cloud",
            version="2.0.5+",
            binary_override=binary_override,
            use_wsl=use_wsl,
        )

    def is_installed(self) -> bool:
        return True

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cloud_provider = params.get("provider", "aws").lower()
        subcommand = params.get("module", "permissions")

        cmd = [self.binary_path or "cloudfox", cloud_provider]

        # Profile / Account / Subscription flags
        if params.get("profile"):
            cmd.extend(["-p", params["profile"]])

        cmd.append(subcommand)

        if params.get("outdir"):
            cmd.extend(["--outdir", params["outdir"]])

        return cmd

    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        findings: List[Finding] = []
        assets: List[HostAsset] = []

        combined = stdout + "\n" + stderr
        lines = [line.strip() for line in combined.splitlines() if line.strip()]

        for line in lines:
            # 1. IAM Admin / Excessive Privileges Detection (T1078.004)
            if re.search(r"(?:AdministratorAccess|\*:|FullAccess|admin\s*=\s*true)", line, re.IGNORECASE):
                findings.append(
                    Finding(
                        title=f"Excessive Cloud Administrative Privileges Discovered: {target}",
                        description=(
                            f"CloudFox enumerated cloud identity or role on {target} possessing full administrative "
                            "privileges (e.g. AdministratorAccess or '*:*'). Compromise of these credentials provides "
                            "complete control of cloud tenant resources."
                        ),
                        severity=Severity.CRITICAL,
                        target=target,
                        cwe="CWE-250",
                        cvss_score=9.1,
                        mitre_attack_ids=["T1078.004"],
                        tool="cloudfox",
                        evidence=line,
                        remediation="Apply the principle of least privilege. Replace wildcard admin roles with scoped permission boundaries.",
                    )
                )

            # 2. Exposed / Public Cloud Storage Buckets (CWE-732 / T1530)
            if re.search(r"(?:public.*bucket|AllUsers|AuthenticatedUsers|bucket.*public)", line, re.IGNORECASE):
                bucket_match = re.search(r"(?:bucket|s3://)\s*([a-zA-Z0-9.\-_]+)", line, re.IGNORECASE)
                bucket_name = bucket_match.group(1) if bucket_match else target
                findings.append(
                    Finding(
                        title=f"Public Cloud Storage Bucket Detected: {bucket_name}",
                        description=(
                            f"CloudFox identified storage bucket '{bucket_name}' with public or unauthenticated read/write access. "
                            "Sensitive data or configuration backups are exposed to unauthenticated Internet users."
                        ),
                        severity=Severity.HIGH,
                        target=f"s3://{bucket_name}",
                        cwe="CWE-732",
                        cvss_score=8.5,
                        mitre_attack_ids=["T1530"],
                        tool="cloudfox",
                        evidence=f"bucket={bucket_name}; raw={line}",
                        remediation="Enable S3 Block Public Access at the account and bucket level and review bucket ACLs.",
                    )
                )

            # 3. IMDSv1 Enabled / Cloud Metadata Service Exposure (T1552.005)
            if re.search(r"(?:imdsv1.*enabled|http-tokens.*optional|metadata.*insecure)", line, re.IGNORECASE):
                findings.append(
                    Finding(
                        title=f"Insecure IMDSv1 Metadata Service Permitted: {target}",
                        description=(
                            f"Cloud compute instance on {target} permits Instance Metadata Service Version 1 (IMDSv1) "
                            "without requiring session tokens (HttpTokens=optional). Attackers exploiting SSRF vulnerabilities "
                            "can steal temporary instance IAM credentials."
                        ),
                        severity=Severity.HIGH,
                        target=target,
                        cwe="CWE-668",
                        cvss_score=7.8,
                        mitre_attack_ids=["T1552.005"],
                        tool="cloudfox",
                        evidence=line,
                        remediation="Enforce IMDSv2 across all cloud compute instances (set HttpTokens=required).",
                    )
                )

            # 4. IAM Privilege Escalation Vector (PassRole + Service Execution)
            if re.search(r"(?:iam:passrole|passrole.*runinstances|privesc)", line, re.IGNORECASE):
                findings.append(
                    Finding(
                        title=f"Potential IAM Privilege Escalation Vector: {target}",
                        description=(
                            f"CloudFox identified an IAM permission combination on {target} that permits lateral privilege "
                            "escalation (e.g. iam:PassRole combined with ec2:RunInstances or lambda:CreateFunction)."
                        ),
                        severity=Severity.HIGH,
                        target=target,
                        cwe="CWE-250",
                        cvss_score=8.1,
                        mitre_attack_ids=["T1078.004"],
                        tool="cloudfox",
                        evidence=line,
                        remediation="Restrict iam:PassRole permissions to specific service roles with resource ARN constraints.",
                    )
                )

        assets.append(
            HostAsset(
                hostname=target,
                metadata={
                    "source": "cloudfox",
                    "tags": ["cloud", "cloudfox", "aws" if "aws" in combined.lower() else "cloud-infra"],
                },
            )
        )

        return findings, assets

    def run(
        self,
        target: str,
        scope: ScopeManifest,
        params: Optional[Dict[str, Any]] = None,
        timeout_seconds: int = 120,
    ) -> AdapterResult:
        params = params or {}
        self.validate_target_scope(target, scope)

        # Check if target is a file or directory containing CloudFox output loot
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
                logger.warning(f"CloudFox fixture parse failed: {e}")

        # Live invocation via WSL2 or native
        return super().run(target, scope, params=params, timeout_seconds=timeout_seconds)
