"""
REVENANT — Checkov Infrastructure as Code (IaC) Static Security Adapter
Analyzes Terraform, CloudFormation, Kubernetes, ARM, and Dockerfile configurations:
- Detects cloud misconfigurations, overly permissive security groups, and exposed resources
- Discovers hardcoded credentials and IAM privilege escalation risks (CWE-798 / CWE-250)
- Enforces CIS Benchmarks and cloud security compliance policies.
Executes natively in WSL2 or Windows using the verified checkov engine.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from adapters.base import AdapterResult, BaseAdapter, to_wsl_path
from control_plane.schemas.models import Finding, HostAsset, Severity
from control_plane.schemas.scope import ScopeManifest

logger = logging.getLogger("revenant.adapters.checkov")


class CheckovAdapter(BaseAdapter):
    """Adapter for Checkov Infrastructure as Code (IaC) and cloud posture analysis."""

    def __init__(
        self,
        binary_override: Optional[str] = None,
        use_wsl: bool = True,
    ):
        super().__init__(
            name="checkov",
            category="cloud",
            version="3.3.19+",
            binary_override=binary_override,
            use_wsl=use_wsl,
        )

    def is_installed(self) -> bool:
        return True

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        target_path = to_wsl_path(target) if self.use_wsl else target
        is_dir = os.path.isdir(target) if os.path.exists(target) else True

        cmd = [
            self.binary_path or "checkov",
            "-d" if is_dir else "-f",
            target_path,
            "--output", "json",
            "--soft-fail",
            "--quiet",
            "--skip-download",
        ]

        framework = params.get("framework")
        if framework:
            cmd.extend(["--framework", framework])

        return cmd

    def _map_severity(self, raw_severity: Optional[str], check_name: str, check_id: str) -> Severity:
        if raw_severity:
            norm = str(raw_severity).upper()
            if "CRIT" in norm:
                return Severity.CRITICAL
            if "HIGH" in norm:
                return Severity.HIGH
            if "MED" in norm:
                return Severity.MEDIUM
            if "LOW" in norm:
                return Severity.LOW
            if "INFO" in norm:
                return Severity.INFO

        # Heuristic inference from check_id and check_name
        name_lower = check_name.lower()
        if "secret" in check_id.lower() or "secret" in name_lower or "password" in name_lower or "key" in name_lower:
            return Severity.HIGH
        if "root" in name_lower or "privileged" in name_lower or "admin" in name_lower:
            return Severity.HIGH
        if "public" in name_lower or "unrestricted" in name_lower or "0.0.0.0" in name_lower:
            return Severity.HIGH
        if "encryption" in name_lower or "tls" in name_lower or "https" in name_lower:
            return Severity.MEDIUM

        return Severity.MEDIUM

    def _map_cwe(self, check_id: str, check_name: str) -> str:
        name_lower = check_name.lower()
        id_lower = check_id.lower()

        if "secret" in id_lower or "secret" in name_lower or "key" in name_lower or "password" in name_lower:
            return "CWE-798"  # Hard-coded Credentials
        if "root" in name_lower or "privilege" in name_lower:
            return "CWE-250"  # Execution with Unnecessary Privileges
        if "public" in name_lower or "acl" in name_lower or "permission" in name_lower:
            return "CWE-732"  # Incorrect Permission Assignment
        if "encrypt" in name_lower or "plain" in name_lower:
            return "CWE-311"  # Missing Encryption
        if "security_group" in name_lower or "firewall" in name_lower or "port" in name_lower:
            return "CWE-284"  # Improper Access Control

        return "CWE-16"  # Configuration Flaw

    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        findings: List[Finding] = []
        assets: List[HostAsset] = []

        cleaned = stdout.strip()
        if not cleaned:
            return [], []

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            # Fallback: scan for JSON blocks
            logger.debug("Checkov output was not direct JSON; attempting substring search.")
            start = cleaned.find("[")
            if start == -1:
                start = cleaned.find("{")
            if start != -1:
                try:
                    data = json.loads(cleaned[start:])
                except json.JSONDecodeError:
                    return [], []
            else:
                return [], []

        # Checkov output can be a single dict or a list of dicts (per framework)
        blocks = data if isinstance(data, list) else [data]

        for block in blocks:
            if not isinstance(block, dict):
                continue
            results = block.get("results", {})
            failed_checks = results.get("failed_checks", [])
            for check in failed_checks:
                check_id = check.get("check_id", "CKV_UNKNOWN")
                check_name = check.get("check_name", "IaC Security Policy Violation")
                file_path = check.get("file_path", target)
                guideline = check.get("guideline", "")
                line_range = check.get("file_line_range", [1, 1])
                code_block = check.get("code_block", [])
                resource = check.get("resource", target)

                severity = self._map_severity(check.get("severity"), check_name, check_id)
                cwe = self._map_cwe(check_id, check_name)

                # Format finding
                evidence_data = {
                    "check_id": check_id,
                    "resource": resource,
                    "line_range": line_range,
                    "guideline": guideline,
                    "snippet": "\n".join([str(c[1]) for c in code_block]) if code_block else "",
                }
                findings.append(
                    Finding(
                        title=f"{check_id}: {check_name}",
                        description=(
                            f"Checkov flagged policy failure in resource '{resource}' ({file_path}): {check_name}. "
                            f"Policy reference: {guideline or 'CIS / Cloud Security Benchmark'}"
                        ),
                        severity=severity,
                        target=f"{file_path}:{line_range[0]}" if line_range else file_path,
                        cwe=cwe,
                        cvss_score=8.0 if severity == Severity.HIGH else (9.0 if severity == Severity.CRITICAL else 5.5),
                        mitre_attack_ids=["T1078.004"] if cwe == "CWE-250" else (["T1552.001"] if cwe == "CWE-798" else ["T1082"]),
                        tool="checkov",
                        evidence=json.dumps(evidence_data),
                        remediation=f"Remediate according to official policy guideline: {guideline}" if guideline else "Review resource configuration and enforce least-privilege principles.",
                    )
                )

        assets.append(
            HostAsset(
                hostname=target,
                metadata={
                    "source": "checkov",
                    "tags": ["iac", "cloud", "checkov"],
                },
            )
        )

        return findings, assets

    def run(
        self,
        target: str,
        scope: ScopeManifest,
        params: Optional[Dict[str, Any]] = None,
        timeout_seconds: int = 180,
    ) -> AdapterResult:
        params = params or {}
        self.validate_target_scope(target, scope)

        # Direct JSON fixture file ingestion support
        if os.path.isfile(target) and target.endswith(".json"):
            try:
                with open(target, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                data = json.loads(content)
                if isinstance(data, (dict, list)) and ("results" in data or (isinstance(data, list) and len(data) > 0 and "results" in data[0])):
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
                logger.warning(f"Checkov fixture parse check: {e}")

        # Live invocation via WSL2 or native
        return super().run(target, scope, params=params, timeout_seconds=timeout_seconds)
