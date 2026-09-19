"""
REVENANT — Ffuf (Fast Web Fuzzer) Tool Adapter
Discovers hidden endpoints, directories, files, and administrative panels.
Parses Ffuf JSON output into structured EndpointInfo and Finding records.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple
from adapters.base import BaseAdapter
from control_plane.schemas.models import EndpointInfo, Finding, HostAsset, Severity

SENSITIVE_PATHS = [
    "admin", "api", "config", "backup", "db", "swagger", "openapi",
    "actuator", ".env", ".git", "v1", "v2", "graphql", "console", "dashboard"
]


class FfufAdapter(BaseAdapter):
    """Adapter for Ffuf web directory & endpoint fuzzer."""

    def __init__(self, binary_override: str | None = None):
        super().__init__(
            name="ffuf",
            category="web",
            version="2.1.0+",
            binary_override=binary_override,
        )

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        from pathlib import Path
        base_url = target.rstrip("/")
        fuzz_url = f"{base_url}/FUZZ"
        default_wl = Path(__file__).resolve().parent.parent.parent / "wordlists" / "common.txt"
        wordlist = params.get("wordlist") or (str(default_wl) if default_wl.is_file() else "/opt/revenant/wordlists/common.txt")

        cmd = [
            self.binary_path or "ffuf",
            "-u", fuzz_url,
            "-w", wordlist,
            "-json",
            "-s",  # silent
            "-mc", "200,204,301,302,307,401,403",
        ]
        if params.get("threads"):
            cmd.extend(["-t", str(params["threads"])])
        if params.get("rate"):
            cmd.extend(["-rate", str(params["rate"])])
        return cmd

    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        findings: List[Finding] = []
        endpoints: List[EndpointInfo] = []

        cleaned_stdout = stdout.strip()
        if not cleaned_stdout:
            return [], []

        results: List[Dict[str, Any]] = []
        # Attempt 1: Wrapped JSON object
        try:
            data = json.loads(cleaned_stdout)
            if isinstance(data, dict):
                results = data.get("results", [])
            elif isinstance(data, list):
                results = data
        except json.JSONDecodeError:
            # Attempt 2: JSON lines
            for line in cleaned_stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        import base64
        for res in results:
            url = res.get("url") or f"{target.rstrip('/')}/{res.get('input', {}).get('FUZZ', '')}"
            status = res.get("status")
            raw_fuzz = (res.get("input") or {}).get("FUZZ", "")
            try:
                # ffuf encodes FUZZ values in base64 in json output mode
                fuzz_word = base64.b64decode(raw_fuzz).decode("utf-8", errors="ignore").lower()
            except Exception:
                fuzz_word = str(raw_fuzz).lower()
            if not fuzz_word or fuzz_word.startswith("http"):
                fuzz_word = url.split("?")[0].rstrip("/").split("/")[-1].lower()

            endpoints.append(
                EndpointInfo(
                    url=url,
                    method="GET",
                    status_code=status,
                )
            )

            # Check if exposed endpoint is sensitive
            is_sensitive = any(s in fuzz_word for s in SENSITIVE_PATHS)
            if is_sensitive and status in [200, 204, 301, 302]:
                severity = Severity.MEDIUM if any(c in fuzz_word for c in [".env", ".git", "backup", "config"]) else Severity.LOW
                findings.append(
                    Finding(
                        title=f"Sensitive Endpoint Discovered: /{fuzz_word}",
                        description=f"Web fuzzing identified exposed path '{url}' returning HTTP {status}.",
                        severity=severity,
                        target=target,
                        tool=self.name,
                        endpoint=url,
                        evidence=f"URL: {url}, HTTP Status: {status}, Response Size: {res.get('length')} bytes",
                        raw_data=res,
                    )
                )

        discovered_assets: List[HostAsset] = []
        if endpoints:
            discovered_assets.append(
                HostAsset(
                    hostname=target,
                    endpoints=endpoints,
                )
            )

        return findings, discovered_assets
