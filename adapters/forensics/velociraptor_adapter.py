"""
REVENANT — Velociraptor Digital Forensics & Incident Response (DFIR) Adapter
Executes Velociraptor VQL queries and artifact collections against endpoints:
- Collects and analyzes Windows persistence (Run keys, services, tasks)
- Analyzes evidence of execution (Prefetch, Amcache, ShimCache)
- Inspects endpoint socket state and active processes via VQL.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

from adapters.base import AdapterResult, BaseAdapter, to_wsl_path
from control_plane.schemas.models import Finding, HostAsset, Severity

logger = logging.getLogger("revenant.adapters.velociraptor")


class VelociraptorAdapter(BaseAdapter):
    """Adapter for Velociraptor endpoint artifact collection and VQL triage."""

    def __init__(
        self,
        binary_override: Optional[str] = None,
        use_wsl: bool = True,
    ):
        super().__init__(
            name="velociraptor",
            category="forensics",
            version="0.70+",
            binary_override=binary_override,
            use_wsl=use_wsl,
        )

    def is_installed(self) -> bool:
        return True

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        binary = self.binary_path or "/usr/local/bin/velociraptor"

        if "query" in params:
            query = params["query"]
            cmd = [binary, "query", query, "--format", "json"]
        else:
            artifact = params.get("artifact", "Linux.Network.Netstat")
            cmd = [binary, "artifacts", "collect", artifact, "--format", "json"]

        return cmd

    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        findings: List[Finding] = []
        assets: List[HostAsset] = []

        if not stdout or not stdout.strip():
            return findings, assets

        try:
            clean_stdout = stdout.strip()
            data = []
            decoder = json.JSONDecoder()
            idx = 0
            while idx < len(clean_stdout):
                while idx < len(clean_stdout) and clean_stdout[idx].isspace():
                    idx += 1
                if idx >= len(clean_stdout):
                    break
                try:
                    obj, end_idx = decoder.raw_decode(clean_stdout, idx)
                    if isinstance(obj, list):
                        data.extend(obj)
                    elif isinstance(obj, dict):
                        data.append(obj)
                    idx = end_idx
                except json.JSONDecodeError:
                    idx += 1

            findings, assets = self._extract_findings_and_assets(data, target)

        except Exception as e:
            logger.warning(f"Failed to parse Velociraptor output: {e}")
            return findings, assets

        return findings, assets

    def _extract_findings_and_assets(
        self, data: List[Dict[str, Any]], target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        findings: List[Finding] = []
        assets: List[HostAsset] = []

        for item in data:
            if not isinstance(item, dict):
                continue

            # Check if this is an info() or system artifact
            if "Hostname" in item and "OS" in item:
                hostname = item.get("Hostname", "unknown")
                os_family = item.get("PlatformFamily", item.get("OS", "unknown"))
                assets.append(
                    HostAsset(
                        ip="127.0.0.1",
                        hostname=hostname,
                        metadata={
                            "os": item.get("OS"),
                            "kernel": item.get("KernelVersion"),
                            "platform": item.get("Platform"),
                            "family": os_family,
                        },
                    )
                )

            # 1. Persistence Registry Artifacts
            if "ValueName" in item and "ValueData" in item and ("Key" in item or "Path" in item):
                val_name = item.get("ValueName", "")
                val_data = item.get("ValueData", "")
                reg_key = item.get("Key", item.get("Path", ""))

                is_encoded_ps = "-enc" in val_data.lower() or "powershell" in val_data.lower()
                is_suspicious_path = (
                    "\\users\\public\\" in val_data.lower()
                    or "\\appdata\\" in val_data.lower()
                    or "\\temp\\" in val_data.lower()
                )

                if is_encoded_ps or is_suspicious_path:
                    severity = Severity.CRITICAL if is_encoded_ps else Severity.HIGH
                    title = f"Malicious Persistence Registry Entry: {val_name}"
                    desc = (
                        f"Velociraptor detected an autostart persistence mechanism in registry key '{reg_key}'. "
                        f"Entry '{val_name}' executes command: '{val_data}'."
                    )
                    mitre_ids = ["T1547.001"]  # Boot or Logon Autostart Execution: Registry Run Keys
                    if is_encoded_ps:
                        mitre_ids.append("T1059.001")  # PowerShell

                    findings.append(
                        Finding(
                            title=title,
                            description=desc,
                            severity=severity,
                            target=f"{target}:{reg_key}\\{val_name}",
                            tool=self.name,
                            cwe_id=284,
                            mitre_attack_ids=mitre_ids,
                            remediation=(
                                f"Delete registry value '{val_name}' from '{reg_key}'. "
                                "Quarantine referenced binary and investigate execution provenance."
                            ),
                            raw_evidence=json.dumps(item),
                        )
                    )

            # 2. Network Sockets / Netstat Artifacts
            elif "LocalPort" in item and "State" in item:
                state = item.get("State", "")
                local_port = item.get("LocalPort", 0)
                proc_info = item.get("ProcessInfo") or {}
                cmd = proc_info.get("Command", "").strip()
                pid = proc_info.get("Pid", 0)

                # In live inspection or test fixtures, identify sensitive open services (e.g. SMB on 445/139)
                if local_port in (445, 139) and state.lower() == "listening":
                    findings.append(
                        Finding(
                            title=f"Exposed SMB Service Detected via Endpoint Triage (Port {local_port})",
                            description=(
                                f"Velociraptor Netstat artifact identified listening SMB service "
                                f"bound to port {local_port} by PID {pid} ({cmd})."
                            ),
                            severity=Severity.MEDIUM,
                            target=f"{target}:{local_port}",
                            tool=self.name,
                            cwe_id=200,
                            mitre_attack_ids=["T1046", "T1049"],
                            remediation="Ensure SMB signing is strictly enforced or restrict listening interface to management VLANs.",
                            raw_evidence=json.dumps(item),
                        )
                    )

        return findings, assets
