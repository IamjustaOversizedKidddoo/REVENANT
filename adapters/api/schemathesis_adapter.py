"""
REVENANT — Schemathesis API Security Tool Adapter
Property-based API testing against OpenAPI and GraphQL schemas.
Detects server crashes (500s), schema non-conformance, and boundary violations.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple
from adapters.base import BaseAdapter
from control_plane.schemas.models import Finding, HostAsset, Severity


class SchemathesisAdapter(BaseAdapter):
    """Adapter for Schemathesis property-based API fuzzer."""

    def __init__(self, binary_override: str | None = None):
        super().__init__(
            name="schemathesis",
            category="api",
            version="3.30+",
            binary_override=binary_override,
        )

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [
            self.binary_path or "schemathesis",
            "run",
            target,
            "--no-color",
            "--checks=all",
            "-n", str(params.get("max_examples", 2)),
        ]
        if params.get("rate_limit"):
            cmd.extend(["--rate-limit", str(params["rate_limit"])])
        if params.get("header"):
            cmd.extend(["-H", params["header"]])
        return cmd

    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        findings: List[Finding] = []

        cleaned_stdout = stdout.strip()
        if not cleaned_stdout:
            return [], []

        # Schemathesis JSON output may be a single JSON object or line-by-line JSON events
        records = []
        try:
            parsed = json.loads(cleaned_stdout)
            if isinstance(parsed, list):
                records = parsed
            elif isinstance(parsed, dict):
                if "events" in parsed:
                    records = parsed["events"]
                elif "failures" in parsed or "errors" in parsed:
                    records = [parsed]
                else:
                    records = [parsed]
        except json.JSONDecodeError:
            for line in cleaned_stdout.splitlines():
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        for rec in records:
            event_type = rec.get("event") or rec.get("type") or ""
            failures = rec.get("failures") or rec.get("errors") or []

            checks = rec.get("checks") or []
            for check in checks:
                if check.get("status") in ["failure", "error"]:
                    failures.append(check)

            for failure in failures:
                endpoint = rec.get("path") or failure.get("path") or target
                method = rec.get("method") or failure.get("method") or "GET"
                message = failure.get("message") or failure.get("title") or "API Check Failed"
                status_code = failure.get("status_code")

                severity = Severity.HIGH if status_code and status_code >= 500 else Severity.MEDIUM

                findings.append(
                    Finding(
                        title=f"API Vulnerability on {method} {endpoint}: {message[:60]}",
                        description=f"Schemathesis property test identified an API defect on {method} {endpoint}. {message}",
                        severity=severity,
                        target=target,
                        tool=self.name,
                        cwe="CWE-754" if status_code and status_code >= 500 else "CWE-398",
                        endpoint=endpoint,
                        reproduction_steps=failure.get("curl") or f"schemathesis run {target} --endpoint={endpoint}",
                        evidence=f"Method: {method}, Endpoint: {endpoint}, Status: {status_code}\nDetails: {message}",
                        raw_data=failure,
                    )
                )

        # Fallback: Parse human-readable failure blocks if no JSON records found
        if not findings and "FAILURES" in cleaned_stdout:
            current_op = None
            current_desc: List[str] = []
            curl_cmd = None
            for line in cleaned_stdout.splitlines():
                if line.startswith("_____") and line.endswith("_____"):
                    if current_op:
                        findings.append(
                            Finding(
                                title=f"API Vulnerability on {current_op}",
                                description="; ".join(current_desc) or f"Schemathesis identified failure on {current_op}",
                                severity=Severity.HIGH if any("50" in d for d in current_desc) else Severity.MEDIUM,
                                target=target,
                                tool=self.name,
                                cwe="CWE-754",
                                reproduction_steps=curl_cmd or f"schemathesis run {target}",
                                evidence="\n".join(current_desc),
                            )
                        )
                    current_op = line.strip("_ ").strip()
                    current_desc = []
                    curl_cmd = None
                elif "curl " in line:
                    curl_cmd = line.strip()
                elif line.strip().startswith("- ") or "returned " in line:
                    current_desc.append(line.strip())

            if current_op:
                findings.append(
                    Finding(
                        title=f"API Vulnerability on {current_op}",
                        description="; ".join(current_desc) or f"Schemathesis identified failure on {current_op}",
                        severity=Severity.HIGH if any("50" in d for d in current_desc) else Severity.MEDIUM,
                        target=target,
                        tool=self.name,
                        cwe="CWE-754",
                        reproduction_steps=curl_cmd or f"schemathesis run {target}",
                        evidence="\n".join(current_desc),
                    )
                )

        return findings, []
