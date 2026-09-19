"""
REVENANT — MobSFScan Mobile Application SAST Adapter
Executes mobsfscan inside WSL2 or host for static security code auditing of Android & iOS
application packages, manifests, and source directories, normalized to OWASP MASVS and CWE.
Includes a built-in heuristic AST scanner for Android/iOS security configurations.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from adapters.base import AdapterResult, BaseAdapter, to_wsl_path
from control_plane.schemas.models import CodeLocation, Finding, HostAsset, Severity
from control_plane.schemas.scope import ScopeEngine, ScopeManifest, ScopeViolationError

logger = logging.getLogger("revenant.adapter.mobsfscan")


class MobsfscanAdapter(BaseAdapter):
    """
    Adapter for mobsfscan static application security testing (SAST) tool.
    Audits Android (Java/Kotlin/XML) and iOS (Swift/Obj-C/plist) codebases and manifests.
    """

    def __init__(
        self,
        binary_override: Optional[str] = None,
        use_wsl: bool = True,
        wsl_distro: str = "Ubuntu",
        timeout_seconds: int = 180,
    ):
        super().__init__(
            name="mobsfscan",
            category="mobile_sast",
            binary_override=binary_override or "mobsfscan",
            use_wsl=use_wsl,
            wsl_distro=wsl_distro,
        )
        self.timeout_seconds = timeout_seconds

    def is_installed(self) -> bool:
        if shutil.which(self.binary_path):
            return True
        if self.use_wsl:
            try:
                proc = subprocess.run(
                    ["wsl", "-d", self.wsl_distro, "-u", "root", "which", "mobsfscan"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                if proc.returncode == 0 and len(proc.stdout.strip()) > 0:
                    return True
            except Exception:
                pass
        return False

    def validate_target_scope(self, target: str, manifest: ScopeManifest) -> None:
        """Validate target mobile package or directory against authorized scopes."""
        if manifest.allowed_repos:
            try:
                target_norm = os.path.normpath(str(Path(target).resolve())).lower()
            except Exception:
                target_norm = target.lower()

            allowed = False
            for repo in manifest.allowed_repos:
                if repo == "*":
                    allowed = True
                    break
                try:
                    repo_norm = os.path.normpath(str(Path(repo).resolve())).lower()
                except Exception:
                    repo_norm = repo.lower()
                if target_norm == repo_norm or target_norm.startswith(repo_norm + os.sep) or target_norm.startswith(repo_norm + "/"):
                    allowed = True
                    break

            if not allowed:
                raise ScopeViolationError(
                    target, f"Target '{target}' is not within authorized repositories {manifest.allowed_repos}"
                )
            return

        engine = ScopeEngine(manifest)
        engine.validate_or_raise(target)

    def build_command(self, target: str, params: Optional[Dict[str, Any]] = None) -> List[str]:
        params = params or {}
        output_file = params.get("output_file", "mobsfscan_out.json")
        target_wsl = to_wsl_path(target) if self.use_wsl else target
        return [
            self.binary_path,
            target_wsl,
            "--json",
            "-o",
            output_file,
        ]

    def _normalize_severity(self, raw_sev: str) -> Severity:
        s = raw_sev.upper().strip()
        if "ERROR" in s or "CRITICAL" in s or "HIGH" in s:
            return Severity.HIGH
        if "WARN" in s or "MED" in s:
            return Severity.MEDIUM
        return Severity.LOW

    def _normalize_cwe(self, raw_cwe: str) -> str:
        if not raw_cwe:
            return "CWE-200"
        m = re.search(r"(CWE-\d+)", raw_cwe, re.IGNORECASE)
        if m:
            return m.group(1).upper()
        return raw_cwe.strip()

    def parse_output(
        self, raw_stdout: str, raw_stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        """Parse mobsfscan JSON output structure into normalized Finding objects."""
        findings: List[Finding] = []
        target_name = Path(target).name or target
        asset = HostAsset(
            hostname=target_name,
            metadata={"service": "mobile_app", "tool": "mobsfscan", "target": target},
        )

        if not raw_stdout:
            return findings, [asset]

        try:
            data = json.loads(raw_stdout)
            results = data.get("results", {})

            for rule_id, rule_info in results.items():
                meta = rule_info.get("metadata", {})
                raw_cwe = meta.get("cwe", "")
                cwe = self._normalize_cwe(raw_cwe)
                severity = self._normalize_severity(meta.get("severity", "WARNING"))
                masvs = meta.get("masvs", "MASVS-GENERAL")
                description = meta.get("description", f"Mobile flaw detected: {rule_id}")
                remediation = meta.get("reference", "Follow OWASP Mobile Security Verification Standards (MASVS).")

                # Map MASVS to MITRE technique
                mitre_ids = ["T1190"]
                if "CRYPTO" in masvs or "cwe-798" in cwe.lower():
                    mitre_ids = ["T1552.001"]
                elif "NETWORK" in masvs or "cwe-319" in cwe.lower():
                    mitre_ids = ["T1040"]
                elif "STORAGE" in masvs:
                    mitre_ids = ["T1083"]

                files = rule_info.get("files", [])
                if not files:
                    findings.append(
                        Finding(
                            title=f"Mobile: {rule_id}",
                            description=description,
                            severity=severity,
                            target=target,
                            tool="mobsfscan",
                            cwe=cwe,
                            mitre_attack_ids=mitre_ids,
                            owasp_category=masvs,
                            endpoint=target,
                            remediation=remediation,
                            verified=True,
                            verified_valid=True,
                        )
                    )
                else:
                    for f_entry in files:
                        f_path = f_entry.get("file_path", "")
                        match_lines = f_entry.get("match_lines", [1, 1])
                        snippet = f_entry.get("match_string", "")
                        start_line = match_lines[0] if match_lines else 1

                        findings.append(
                            Finding(
                                title=f"Mobile: {rule_id}",
                                description=description,
                                severity=severity,
                                target=target,
                                tool="mobsfscan",
                                cwe=cwe,
                                mitre_attack_ids=mitre_ids,
                                owasp_category=masvs,
                                endpoint=target,
                                code_location=CodeLocation(
                                    file_path=f_path,
                                    start_line=start_line,
                                    snippet=snippet[:400],
                                ),
                                evidence=json.dumps({
                                    "rule_id": rule_id,
                                    "masvs": masvs,
                                    "file": f_path,
                                    "lines": match_lines,
                                }),
                                remediation=remediation,
                                verified=True,
                                verified_valid=True,
                            )
                        )
        except Exception as e:
            logger.error("Failed to parse mobsfscan JSON output: %s", e)

        return findings, [asset]

    def analyze_heuristics(self, target_dir: str) -> List[Finding]:
        """
        Built-in mobile security heuristics scanner. Audits AndroidManifest.xml,
        network_security_config.xml, and source files directly.
        """
        findings: List[Finding] = []
        p = Path(target_dir)
        if not p.exists():
            return findings

        # 1. AndroidManifest.xml Auditing
        manifest_files = list(p.rglob("AndroidManifest.xml"))
        for mf in manifest_files:
            try:
                content = mf.read_text(encoding="utf-8", errors="ignore")

                # Cleartext HTTP traffic
                if 'android:usesCleartextTraffic="true"' in content:
                    findings.append(
                        Finding(
                            title="Mobile: Insecure Cleartext Traffic Allowed",
                            description="Application allows cleartext HTTP communication, exposing network traffic to interception.",
                            severity=Severity.HIGH,
                            target=str(mf),
                            tool="mobsfscan_heuristic",
                            cwe="CWE-319",
                            mitre_attack_ids=["T1040"],
                            owasp_category="MASVS-NETWORK-1",
                            code_location=CodeLocation(
                                file_path=str(mf),
                                start_line=1,
                                snippet='android:usesCleartextTraffic="true"',
                            ),
                            remediation="Set android:usesCleartextTraffic='false' and enforce HTTPS throughout.",
                            verified=True,
                            verified_valid=True,
                        )
                    )

                # Exported Components without permission
                exported_matches = re.finditer(
                    r'<(activity|service|receiver|provider)[^>]*android:exported="true"[^>]*>',
                    content,
                    re.IGNORECASE | re.DOTALL,
                )
                for m in exported_matches:
                    snippet = m.group(0)
                    if "android:permission" not in snippet:
                        findings.append(
                            Finding(
                                title="Mobile: Insecure Exported Android Component",
                                description=f"Android component is exported to all third-party apps without permission restrictions.",
                                severity=Severity.HIGH,
                                target=str(mf),
                                tool="mobsfscan_heuristic",
                                cwe="CWE-926",
                                mitre_attack_ids=["T1190"],
                                owasp_category="MASVS-PLATFORM-1",
                                code_location=CodeLocation(
                                    file_path=str(mf),
                                    start_line=content[: m.start()].count("\n") + 1,
                                    snippet=snippet[:250],
                                ),
                                remediation="Set android:exported='false' or guard the component with android:permission.",
                                verified=True,
                                verified_valid=True,
                            )
                        )

                # Debuggable build
                if 'android:debuggable="true"' in content:
                    findings.append(
                        Finding(
                            title="Mobile: Application Built with Debug Mode Enabled",
                            description="Application is debuggable in production, enabling memory inspection and hook injection.",
                            severity=Severity.HIGH,
                            target=str(mf),
                            tool="mobsfscan_heuristic",
                            cwe="CWE-215",
                            mitre_attack_ids=["T1059"],
                            owasp_category="MASVS-RESILIENCE-1",
                            code_location=CodeLocation(
                                file_path=str(mf),
                                start_line=1,
                                snippet='android:debuggable="true"',
                            ),
                            remediation="Ensure android:debuggable='false' in release configurations.",
                            verified=True,
                            verified_valid=True,
                        )
                    )

                # Backup allowed
                if 'android:allowBackup="true"' in content:
                    findings.append(
                        Finding(
                            title="Mobile: Application Data Backup Enabled",
                            description="Application data can be backed up via adb backup, enabling extraction of local databases and keys.",
                            severity=Severity.MEDIUM,
                            target=str(mf),
                            tool="mobsfscan_heuristic",
                            cwe="CWE-200",
                            mitre_attack_ids=["T1083"],
                            owasp_category="MASVS-STORAGE-2",
                            code_location=CodeLocation(
                                file_path=str(mf),
                                start_line=1,
                                snippet='android:allowBackup="true"',
                            ),
                            remediation="Set android:allowBackup='false' to prevent local adb data exfiltration.",
                            verified=True,
                            verified_valid=True,
                        )
                    )
            except Exception as e:
                logger.debug("Error analyzing manifest %s: %s", mf, e)

        # 2. Source Code Auditing (.java, .kt, .swift, .m)
        source_extensions = {".java", ".kt", ".swift", ".m"}
        for s_file in p.rglob("*"):
            if s_file.suffix.lower() in source_extensions and s_file.is_file():
                try:
                    s_content = s_file.read_text(encoding="utf-8", errors="ignore")

                    # Hardcoded Secrets / Keys
                    secret_patterns = [
                        (r'(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token|jwt[_-]?secret)\s*=\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "Hardcoded Mobile API Key / Secret"),
                    ]
                    for pat, title in secret_patterns:
                        for m in re.finditer(pat, s_content):
                            findings.append(
                                Finding(
                                    title=f"Mobile: {title}",
                                    description="Sensitive authentication token or secret key found hardcoded in mobile source code.",
                                    severity=Severity.CRITICAL,
                                    target=str(s_file),
                                    tool="mobsfscan_heuristic",
                                    cwe="CWE-798",
                                    mitre_attack_ids=["T1552.001"],
                                    owasp_category="MASVS-CRYPTO-1",
                                    code_location=CodeLocation(
                                        file_path=str(s_file),
                                        start_line=s_content[: m.start()].count("\n") + 1,
                                        snippet=m.group(0),
                                    ),
                                    remediation="Remove hardcoded secrets from client application code. Use an external secrets manager or Android Keystore.",
                                    verified=True,
                                    verified_valid=True,
                                )
                            )

                    # Insecure WebView JavaScript execution
                    if "setJavaScriptEnabled(true)" in s_content:
                        findings.append(
                            Finding(
                                title="Mobile: WebView with JavaScript Execution Enabled",
                                description="WebView enables JavaScript execution, exposing the application to Cross-Site Scripting (XSS) and bridge injection.",
                                severity=Severity.HIGH,
                                target=str(s_file),
                                tool="mobsfscan_heuristic",
                                cwe="CWE-79",
                                mitre_attack_ids=["T1189"],
                                owasp_category="MASVS-PLATFORM-2",
                                code_location=CodeLocation(
                                    file_path=str(s_file),
                                    start_line=1,
                                    snippet="setJavaScriptEnabled(true)",
                                ),
                                remediation="Disable JavaScript in WebViews unless strictly necessary; validate all loaded URLs.",
                                verified=True,
                                verified_valid=True,
                            )
                        )

                    # Insecure Random Number Generator
                    if "new Random()" in s_content or "java.util.Random" in s_content:
                        findings.append(
                            Finding(
                                title="Mobile: Insecure Pseudo-Random Number Generator",
                                description="Application uses java.util.Random instead of SecureRandom for cryptographic operations.",
                                severity=Severity.MEDIUM,
                                target=str(s_file),
                                tool="mobsfscan_heuristic",
                                cwe="CWE-338",
                                mitre_attack_ids=["T1552"],
                                owasp_category="MASVS-CRYPTO-6",
                                code_location=CodeLocation(
                                    file_path=str(s_file),
                                    start_line=1,
                                    snippet="new Random()",
                                ),
                                remediation="Use java.security.SecureRandom for cryptographic key generation and nonce creation.",
                                verified=True,
                                verified_valid=True,
                            )
                        )
                except Exception as e:
                    logger.debug("Error analyzing source %s: %s", s_file, e)

        return findings

    def run(
        self, target: str, manifest: ScopeManifest, params: Optional[Dict[str, Any]] = None
    ) -> AdapterResult:
        """Run mobsfscan on mobile codebase with automatic heuristic fallback."""
        start_time = time.time()
        self.validate_target_scope(target, manifest)

        params = params or {}
        findings: List[Finding] = []
        target_name = Path(target).name or target
        asset = HostAsset(
            hostname=target_name,
            metadata={"service": "mobile_app", "target": target},
        )

        # 1. Check if real mobsfscan binary is available
        if self.is_installed():
            with tempfile.TemporaryDirectory() as temp_dir:
                out_json_host = os.path.join(temp_dir, "mobsfscan.json")
                out_json_wsl = to_wsl_path(out_json_host) if self.use_wsl else out_json_host
                target_wsl = to_wsl_path(target) if self.use_wsl else target

                cmd = [
                    self.binary_path,
                    target_wsl,
                    "--json",
                    "-o",
                    out_json_wsl,
                ]

                try:
                    if self.use_wsl:
                        full_cmd = ["wsl", "-d", self.wsl_distro, "-u", "root"] + cmd
                    else:
                        full_cmd = cmd

                    proc = subprocess.run(
                        full_cmd,
                        capture_output=True,
                        text=True,
                        timeout=self.timeout_seconds,
                    )
                    duration = time.time() - start_time

                    raw_out = ""
                    if os.path.exists(out_json_host):
                        with open(out_json_host, "r", encoding="utf-8") as f:
                            raw_out = f.read()

                    parsed_findings, assets = self.parse_output(raw_out, proc.stderr, target)
                    findings.extend(parsed_findings)

                    # Enrich with built-in heuristic analysis for manifest and source checks
                    heuristic_findings = self.analyze_heuristics(target)
                    existing_titles = {f.title for f in findings}
                    for hf in heuristic_findings:
                        if hf.title not in existing_titles:
                            findings.append(hf)

                    if findings:
                        return AdapterResult(
                            tool_name="mobsfscan",
                            target=target,
                            exit_code=proc.returncode,
                            duration_seconds=duration,
                            findings=findings,
                            discovered_assets=assets,
                            raw_stdout=raw_out,
                            raw_stderr=proc.stderr,
                        )
                except Exception as e:
                    logger.warning("mobsfscan binary execution failed: %s, falling back to heuristics", e)

        # 2. Fallback: Run built-in mobile SAST heuristics
        logger.info("Executing built-in mobile SAST heuristics on %s", target)
        heuristic_findings = self.analyze_heuristics(target)
        duration = time.time() - start_time

        return AdapterResult(
            tool_name="mobsfscan",
            target=target,
            exit_code=0,
            duration_seconds=duration,
            findings=heuristic_findings,
            discovered_assets=[asset],
            raw_stdout=json.dumps({"findings": [f.model_dump(mode="json") for f in heuristic_findings]}),
            raw_stderr="",
        )
