"""
REVENANT — Garak LLM Vulnerability Scanner Adapter
Integrates NVIDIA Garak (Generative AI Red-teaming & Assessment Kit) for automated LLM probing.
Includes JSONL report parsing and graceful fallback to NativeAiProbeAdapter.
"""

from __future__ import annotations

import glob
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from adapters.ai.native_probe_adapter import NativeAiProbeAdapter, OWASP_LLM01, OWASP_LLM02, OWASP_LLM05, OWASP_LLM06
from adapters.base import AdapterResult, BaseAdapter
from control_plane.schemas.models import Finding, HostAsset, Severity
from control_plane.schemas.scope import ScopeEngine, ScopeManifest, ScopeViolationError

logger = logging.getLogger("revenant.adapter.garak")


class GarakAdapter(BaseAdapter):
    """
    Adapter for Garak LLM vulnerability scanner.
    Runs automated probe batteries against REST endpoints or model interfaces
    and ingests .report.jsonl outputs into normalized findings.
    """

    def __init__(
        self,
        binary_override: Optional[str] = None,
        use_wsl: bool = True,
        timeout_seconds: int = 180,
    ):
        binary = binary_override or shutil.which("garak")
        super().__init__(
            name="garak",
            category="ai_redteam",
            binary_override=binary or "garak",
            use_wsl=use_wsl,
        )
        self.timeout_seconds = timeout_seconds
        self.native_fallback = NativeAiProbeAdapter(timeout_seconds=float(timeout_seconds))

    def is_installed(self) -> bool:
        if shutil.which(self.binary_path):
            return True
        if self.use_wsl:
            try:
                proc = subprocess.run(
                    ["wsl", "-d", "Ubuntu", "-u", "root", "which", "garak"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                return proc.returncode == 0 and len(proc.stdout.strip()) > 0
            except Exception:
                pass
        return False

    def validate_target_scope(self, target: str, manifest: ScopeManifest) -> None:
        engine = ScopeEngine(manifest)
        engine.validate_or_raise(target)

    def build_command(self, target: str, params: Optional[Dict[str, Any]] = None) -> List[str]:
        params = params or {}
        probes = params.get("probes", "promptinject,leakreplay")
        report_prefix = params.get("report_prefix", "garak_report")
        return [
            self.binary_path,
            "--model_type",
            "rest",
            "--target",
            target,
            "--probes",
            probes,
            "--report_prefix",
            report_prefix,
            "--narrow_output",
        ]

    def parse_output(
        self, raw_stdout: str, raw_stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        """Parse Garak JSONL stream or JSON report records into findings."""
        findings: List[Finding] = []
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        asset = HostAsset(
            hostname=hostname,
            metadata={"service": "llm", "tool": "garak", "endpoint": target},
        )

        if not raw_stdout:
            return findings, [asset]

        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue

            try:
                record = json.loads(line)
                entry_type = record.get("entry_type")

                # Process evaluation/result records
                if entry_type == "eval" or "passed" in record or "score" in record:
                    passed = record.get("passed", True)
                    score = float(record.get("score", 1.0))
                    probe_name = record.get("probe", "garak.probe")

                    if not passed or score < 0.5:
                        category = OWASP_LLM01
                        cwe = "CWE-77"
                        severity = Severity.HIGH
                        mitre = ["AML.T0051"]

                        if "leak" in probe_name.lower() or "sys" in probe_name.lower():
                            category = OWASP_LLM02
                            cwe = "CWE-200"
                            mitre = ["AML.T0057"]
                        elif "xss" in probe_name.lower() or "output" in probe_name.lower():
                            category = OWASP_LLM05
                            cwe = "CWE-79"
                            mitre = ["AML.T0043"]
                        elif "agency" in probe_name.lower() or "tool" in probe_name.lower():
                            category = OWASP_LLM06
                            cwe = "CWE-284"
                            severity = Severity.CRITICAL
                            mitre = ["AML.T0051"]

                        evidence_data = {
                            "probe": probe_name,
                            "detector": record.get("detector"),
                            "score": score,
                            "prompt": record.get("prompt"),
                            "response": record.get("output", "")[:500],
                        }

                        findings.append(
                            Finding(
                                title=f"Garak: {probe_name} Vulnerability Detected",
                                description=f"Garak probe {probe_name} failed safety evaluation with score {score:.2f}.",
                                severity=severity,
                                target=target,
                                tool="garak",
                                cwe=cwe,
                                mitre_attack_ids=mitre,
                                owasp_category=category,
                                endpoint=target,
                                evidence=json.dumps(evidence_data),
                                remediation="Review model system prompts and implement strict safety guardrails.",
                                verified=True,
                                verified_valid=True,
                            )
                        )
            except Exception as e:
                logger.debug("Skipping unparseable Garak line: %s", e)

        return findings, [asset]

    def run(
        self, target: str, manifest: ScopeManifest, params: Optional[Dict[str, Any]] = None
    ) -> AdapterResult:
        """Run Garak probe battery; fallback to NativeAiProbeAdapter if unavailable."""
        self.validate_target_scope(target, manifest)

        if not self.is_installed():
            logger.info("Garak binary not installed on host or WSL2, falling back to NativeAiProbeAdapter")
            return self.native_fallback.run(target, manifest, params)

        params = params or {}
        with tempfile.TemporaryDirectory() as temp_dir:
            prefix = os.path.join(temp_dir, "garak_scan")
            params["report_prefix"] = prefix

            cmd = self.build_command(target, params)
            start_time = time.time()

            try:
                if self.use_wsl:
                    full_cmd = ["wsl", "-d", "Ubuntu", "-u", "root"] + cmd
                else:
                    full_cmd = cmd

                proc = subprocess.run(
                    full_cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                )
                duration = time.time() - start_time

                # Aggregate generated report jsonl files
                raw_reports = ""
                for report_path in glob.glob(f"{prefix}*.report.jsonl"):
                    with open(report_path, "r", encoding="utf-8") as rf:
                        raw_reports += rf.read() + "\n"

                combined_stdout = proc.stdout + "\n" + raw_reports
                findings, assets = self.parse_output(combined_stdout, proc.stderr, target)

                return AdapterResult(
                    tool_name="garak",
                    target=target,
                    exit_code=proc.returncode,
                    duration_seconds=duration,
                    findings=findings,
                    discovered_assets=assets,
                    raw_stdout=combined_stdout,
                    raw_stderr=proc.stderr,
                )
            except Exception as e:
                logger.warning("Garak execution failed (%s), falling back to NativeAiProbeAdapter", e)
                return self.native_fallback.run(target, manifest, params)
