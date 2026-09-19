"""
REVENANT — Gitleaks Tool Adapter
Fast secret detection and credential harvesting across git history and filesystems.
Parses Gitleaks JSON reports into normalized Finding records with CodeLocation metadata.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from adapters.base import BaseAdapter
from control_plane.schemas.models import CodeLocation, Finding, HostAsset, Severity


class GitleaksAdapter(BaseAdapter):
    """Adapter for Gitleaks secret scanner."""

    def __init__(self, binary_override: Optional[str] = None):
        super().__init__(
            name="gitleaks",
            category="sast",
            version="8.21.0+",
            binary_override=binary_override,
        )
        self._temp_report_path: Optional[str] = None

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        target_path = Path(target).resolve()
        is_git_repo = (target_path / ".git").is_dir()

        # Generate a temporary file path for gitleaks JSON output
        temp_dir = Path(tempfile.gettempdir())
        self._temp_report_path = str(temp_dir / f"gitleaks_{os.getpid()}_{id(self)}.json")

        cmd = [
            self.binary_path or "gitleaks",
            "detect",
            f"--source={str(target_path)}",
            f"--report-path={self._temp_report_path}",
            "--report-format=json",
            "--exit-code=0",  # Don't fail process on finding secrets
        ]

        if not is_git_repo or params.get("no_git", False):
            cmd.append("--no-git")

        if params.get("verbose", False):
            cmd.append("--verbose")

        return cmd

    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        findings: List[Finding] = []
        raw_items: List[Dict[str, Any]] = []

        # Read from report file if generated
        if self._temp_report_path and os.path.exists(self._temp_report_path):
            try:
                with open(self._temp_report_path, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content:
                        raw_items = json.loads(content)
            except Exception:
                pass
            finally:
                try:
                    os.remove(self._temp_report_path)
                except OSError:
                    pass

        # Fallback to stdout if report file was empty
        if not raw_items and stdout.strip():
            try:
                parsed = json.loads(stdout.strip())
                if isinstance(parsed, list):
                    raw_items = parsed
            except json.JSONDecodeError:
                pass

        for item in raw_items:
            rule_id = item.get("RuleID") or "generic-secret"
            description = item.get("Description") or f"Exposed {rule_id}"
            file_name = item.get("File") or item.get("SymlinkFile") or "unknown"
            start_line = item.get("StartLine") or 1
            end_line = item.get("EndLine") or start_line
            secret = item.get("Secret") or item.get("Match") or ""
            commit = item.get("Commit")
            author = item.get("Author")

            # Mask secret for safe reporting (keep first 3 and last 3 chars)
            if len(secret) > 8:
                masked_secret = f"{secret[:3]}...{secret[-3:]}"
            else:
                masked_secret = "***"

            # Determine severity based on secret type
            rule_lower = rule_id.lower()
            if any(k in rule_lower for k in ["aws", "private-key", "rsa", "jwt", "database", "postgres", "mysql", "token"]):
                severity = Severity.CRITICAL
            elif any(k in rule_lower for k in ["api-key", "generic-api-key", "slack", "github", "discord"]):
                severity = Severity.HIGH
            else:
                severity = Severity.MEDIUM

            code_loc = CodeLocation(
                file_path=file_name,
                start_line=start_line,
                end_line=end_line,
                snippet=f"Rule: {rule_id} | Secret: {masked_secret}",
                commit_hash=commit,
                author=author,
            )

            finding = Finding(
                title=f"Hardcoded Secret Discovered: {description}",
                description=f"Gitleaks identified hardcoded secret pattern '{rule_id}' in file '{file_name}' at line {start_line}.",
                severity=severity,
                target=target,
                tool=self.name,
                cwe="CWE-798",
                secret_type=rule_id,
                code_location=code_loc,
                endpoint=f"{target}/{file_name}:{start_line}",
                reproduction_steps=f"gitleaks detect --source={target} --no-git",
                evidence=f"File: {file_name}:{start_line}\nRule: {rule_id}\nSecret Masked: {masked_secret}\nEntropy: {item.get('Entropy', 'N/A')}",
                raw_data=item,
            )
            findings.append(finding)

        # Represent the codebase as an asset
        asset = HostAsset(
            hostname=Path(target).name or target,
            metadata={"source": "gitleaks", "path": str(Path(target).resolve()), "secrets_count": len(findings)},
        )

        return findings, [asset] if findings else []
