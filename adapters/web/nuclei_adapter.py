"""
REVENANT — ProjectDiscovery Nuclei Tool Adapter
Template-based vulnerability detection, CVE mapping, and evidence capture.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple
from control_plane.schemas.models import Finding, HostAsset, Severity
from adapters.base import BaseAdapter

SEVERITY_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class NucleiAdapter(BaseAdapter):
    """Adapter for ProjectDiscovery Nuclei vulnerability scanner."""

    def __init__(self, binary_override: str | None = None):
        super().__init__(
            name="nuclei",
            category="web",
            version="3.3.0+",
            binary_override=binary_override,
        )

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [
            self.binary_path or "nuclei",
            "-u", target,
            "-jsonl",
            "-silent",
            "-duc",
            "-ni",
        ]
        if params.get("templates"):
            for t in params["templates"]:
                cmd.extend(["-t", t])
        if params.get("tags"):
            cmd.extend(["-tags", ",".join(params["tags"])])
        if params.get("severity"):
            cmd.extend(["-severity", ",".join(params["severity"])])
        if params.get("rate_limit"):
            cmd.extend(["-rate-limit", str(params["rate_limit"])])
        return cmd

    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        findings: List[Finding] = []

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = data.get("info") or {}
            raw_sev = (info.get("severity") or "info").lower()
            severity = SEVERITY_MAP.get(raw_sev, Severity.MEDIUM)

            classification = info.get("classification") or {}
            cve_list = classification.get("cve-id")
            cve = cve_list[0] if isinstance(cve_list, list) and cve_list else None
            cwe_list = classification.get("cwe-id")
            cwe = cwe_list[0] if isinstance(cwe_list, list) and cwe_list else None
            cvss_score = classification.get("cvss-score")
            try:
                cvss_float = float(cvss_score) if cvss_score is not None else None
            except (ValueError, TypeError):
                cvss_float = None

            matched_at = data.get("matched-at") or target
            curl_cmd = data.get("curl-command")
            extracted = data.get("extracted-results")

            evidence_parts = []
            if curl_cmd:
                evidence_parts.append(f"Reproduction:\n{curl_cmd}")
            if extracted:
                evidence_parts.append(f"Extracted: {extracted}")
            evidence_text = "\n\n".join(evidence_parts) or f"Matched at: {matched_at}"

            finding = Finding(
                title=info.get("name") or data.get("template-id") or "Vulnerability Detected",
                description=info.get("description") or f"Detected by template {data.get('template-id')}",
                severity=severity,
                target=target,
                tool=self.name,
                cve=cve,
                cwe=cwe,
                cvss_score=cvss_float,
                endpoint=matched_at,
                reproduction_steps=curl_cmd,
                evidence=evidence_text,
                raw_data=data,
            )
            findings.append(finding)

        return findings, []
