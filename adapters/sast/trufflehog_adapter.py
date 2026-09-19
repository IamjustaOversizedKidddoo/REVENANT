"""
REVENANT — TruffleHog Tool Adapter
Deep secret scanning, entropy analysis, and credential verification engine.
Parses TruffleHog JSON-lines into normalized Finding records with verified validity indicators.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from adapters.base import BaseAdapter
from control_plane.schemas.models import CodeLocation, Finding, HostAsset, Severity


class TruffleHogAdapter(BaseAdapter):
    """Adapter for TruffleHog secret and credential verification engine."""

    def __init__(self, binary_override: Optional[str] = None):
        super().__init__(
            name="trufflehog",
            category="sast",
            version="3.97.0+",
            binary_override=binary_override,
        )

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        target_path = Path(target).resolve()
        is_git_repo = (target_path / ".git").is_dir()

        if is_git_repo and not params.get("filesystem_only", False):
            cmd = [
                self.binary_path or "trufflehog",
                "git",
                f"file://{str(target_path)}",
                "--json",
                "--no-update",
            ]
        else:
            cmd = [
                self.binary_path or "trufflehog",
                "filesystem",
                str(target_path),
                "--json",
                "--no-update",
            ]

        if params.get("only_verified", False):
            cmd.append("--only-verified")

        return cmd

    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        findings: List[Finding] = []

        cleaned_stdout = stdout.strip()
        if not cleaned_stdout:
            return [], []

        for line in cleaned_stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            detector = data.get("DetectorName") or "Generic"
            verified = bool(data.get("Verified", False))
            raw_secret = data.get("Raw", "")
            redacted = data.get("Redacted") or (f"{raw_secret[:3]}...{raw_secret[-3:]}" if len(raw_secret) > 6 else "***")

            # Extract source file metadata
            source_meta = data.get("SourceMetadata", {}).get("Data", {})
            file_path = "unknown"
            line_number = 1
            commit_hash = None
            author = None

            if "Filesystem" in source_meta:
                fs_data = source_meta["Filesystem"]
                file_path = fs_data.get("file", "unknown")
                line_number = fs_data.get("line", 1)
            elif "Git" in source_meta:
                git_data = source_meta["Git"]
                file_path = git_data.get("file", "unknown")
                line_number = git_data.get("line", 1)
                commit_hash = git_data.get("commit")
                author = git_data.get("email")

            # Determine severity
            det_lower = detector.lower()
            if verified or any(k in det_lower for k in ["aws", "gcp", "azure", "privatekey", "ssh", "jwt", "slack", "stripe"]):
                severity = Severity.CRITICAL
            else:
                severity = Severity.HIGH

            status_label = "VERIFIED" if verified else "Candidate"
            code_loc = CodeLocation(
                file_path=file_path,
                start_line=line_number,
                snippet=f"Detector: {detector} | Redacted: {redacted}",
                commit_hash=commit_hash,
                author=author,
            )

            finding = Finding(
                title=f"{status_label} Secret Detected: {detector}",
                description=f"TruffleHog detected {status_label.lower()} secret of type '{detector}' in '{file_path}' at line {line_number}.",
                severity=severity,
                target=target,
                tool=self.name,
                cwe="CWE-798",
                secret_type=detector,
                verified=verified,
                verified_valid=verified,
                code_location=code_loc,
                endpoint=f"{target}/{file_path}:{line_number}",
                reproduction_steps=f"trufflehog filesystem {target} --no-update",
                evidence=f"Detector: {detector}\nVerified: {verified}\nFile: {file_path}:{line_number}\nRedacted: {redacted}",
                raw_data=data,
            )
            findings.append(finding)

        asset = HostAsset(
            hostname=Path(target).name or target,
            metadata={"source": "trufflehog", "path": str(Path(target).resolve()), "secrets_count": len(findings)},
        )

        return findings, [asset] if findings else []
