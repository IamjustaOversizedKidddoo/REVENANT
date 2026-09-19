"""
REVENANT — MobSF (Mobile Security Framework) REST Client Adapter
Interacts with MobSF REST API for automated binary analysis of Android (.apk, .aab)
and iOS (.ipa) applications. Gracefully delegates to MobsfscanAdapter if MobSF is offline.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx

from adapters.base import AdapterResult, BaseAdapter
from adapters.mobile.mobsfscan_adapter import MobsfscanAdapter
from control_plane.schemas.models import Finding, HostAsset, Severity
from control_plane.schemas.scope import ScopeEngine, ScopeManifest, ScopeViolationError

logger = logging.getLogger("revenant.adapter.mobsf")


class MobSFAdapter(BaseAdapter):
    """
    Adapter for Mobile Security Framework (MobSF) REST API.
    Handles upload, scanning, scorecard generation, and report ingestion.
    """

    def __init__(
        self,
        server_url: str = "http://127.0.0.1:8000",
        api_key: Optional[str] = None,
        timeout_seconds: int = 180,
    ):
        super().__init__(
            name="mobsf",
            category="mobile_dast",
            binary_override=None,
        )
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key or os.environ.get("MOBSF_API_KEY", "")
        self.timeout_seconds = timeout_seconds
        self.scan_fallback = MobsfscanAdapter()

    def is_installed(self) -> bool:
        """Check if MobSF server is reachable via REST API."""
        try:
            with httpx.Client(timeout=3.0) as client:
                r = client.get(f"{self.server_url}/api/v1/docs")
                return r.status_code in [200, 401, 403]
        except Exception:
            return False

    def validate_target_scope(self, target: str, manifest: ScopeManifest) -> None:
        self.scan_fallback.validate_target_scope(target, manifest)

    def build_command(self, target: str, params: Optional[Dict[str, Any]] = None) -> List[str]:
        return ["mobsf_api", "--target", target, "--server", self.server_url]

    def parse_output(
        self, raw_stdout: str, raw_stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        """Parse MobSF report_json output into standard Finding models."""
        findings: List[Finding] = []
        target_name = Path(target).name or target
        asset = HostAsset(
            hostname=target_name,
            metadata={"service": "mobile_app", "tool": "mobsf", "target": target},
        )

        if not raw_stdout:
            return findings, [asset]

        try:
            data = json.loads(raw_stdout)

            # 1. Manifest Analysis
            manifest_analysis = data.get("manifest_analysis", [])
            for item in manifest_analysis:
                if isinstance(item, dict):
                    stat = item.get("stat", "info")
                    if stat in ["high", "warning"]:
                        sev = Severity.HIGH if stat == "high" else Severity.MEDIUM
                        title = item.get("title", "Manifest Security Flaw")
                        desc = item.get("desc", "")
                        findings.append(
                            Finding(
                                title=f"MobSF: {title}",
                                description=desc,
                                severity=sev,
                                target=target,
                                tool="mobsf",
                                cwe="CWE-926",
                                mitre_attack_ids=["T1190"],
                                owasp_category="MASVS-PLATFORM-1",
                                endpoint=target,
                                remediation="Review AndroidManifest.xml permissions and exported status.",
                                verified=True,
                                verified_valid=True,
                            )
                        )

            # 2. Code Analysis
            code_analysis = data.get("code_analysis", {})
            for rule, rule_data in code_analysis.items():
                if isinstance(rule_data, dict):
                    metadata = rule_data.get("metadata", {})
                    sev_str = metadata.get("severity", "warning").lower()
                    sev = Severity.HIGH if "high" in sev_str or "error" in sev_str else Severity.MEDIUM
                    desc = metadata.get("description", f"Code flaw: {rule}")
                    cwe = metadata.get("cwe", "CWE-200")

                    findings.append(
                        Finding(
                            title=f"MobSF: {rule}",
                            description=desc,
                            severity=sev,
                            target=target,
                            tool="mobsf",
                            cwe=cwe,
                            mitre_attack_ids=["T1552.001"],
                            owasp_category="MASVS-CODE-1",
                            endpoint=target,
                            evidence=json.dumps({"files": rule_data.get("files", {})}),
                            remediation="Follow OWASP MASVS secure coding guidelines.",
                            verified=True,
                            verified_valid=True,
                        )
                    )
        except Exception as e:
            logger.error("Failed to parse MobSF JSON report: %s", e)

        return findings, [asset]

    def run(
        self, target: str, manifest: ScopeManifest, params: Optional[Dict[str, Any]] = None
    ) -> AdapterResult:
        """Run MobSF scan or delegate to MobsfscanAdapter if server is not reachable."""
        self.validate_target_scope(target, manifest)

        if not self.is_installed() or not self.api_key:
            logger.info("MobSF server not reachable or API key absent, delegating to MobsfscanAdapter")
            return self.scan_fallback.run(target, manifest, params)

        start_time = time.time()
        headers = {"Authorization": self.api_key}

        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                # 1. Upload File
                with open(target, "rb") as f:
                    files = {"file": (os.path.basename(target), f, "application/octet-stream")}
                    up_resp = client.post(f"{self.server_url}/api/v1/upload", files=files, headers=headers)

                if up_resp.status_code != 200:
                    raise RuntimeError(f"Upload failed: {up_resp.text}")

                up_data = up_resp.json()
                scan_hash = up_data.get("hash")
                scan_type = up_data.get("scan_type")

                # 2. Trigger Scan
                scan_resp = client.post(
                    f"{self.server_url}/api/v1/scan",
                    data={"hash": scan_hash, "scan_type": scan_type},
                    headers=headers,
                )
                if scan_resp.status_code != 200:
                    raise RuntimeError(f"Scan failed: {scan_resp.text}")

                # 3. Retrieve JSON Report
                rep_resp = client.post(
                    f"{self.server_url}/api/v1/report_json",
                    data={"hash": scan_hash},
                    headers=headers,
                )
                raw_json = rep_resp.text
                duration = time.time() - start_time

                findings, assets = self.parse_output(raw_json, "", target)
                return AdapterResult(
                    tool_name="mobsf",
                    target=target,
                    exit_code=0,
                    duration_seconds=duration,
                    findings=findings,
                    discovered_assets=assets,
                    raw_stdout=raw_json,
                    raw_stderr="",
                )
        except Exception as e:
            logger.warning("MobSF execution failed (%s), falling back to MobsfscanAdapter", e)
            return self.scan_fallback.run(target, manifest, params)
