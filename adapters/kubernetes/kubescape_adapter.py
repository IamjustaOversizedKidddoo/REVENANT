"""
REVENANT — Kubescape Kubernetes Security Posture Adapter
Audits Kubernetes manifests, Helm charts, and live cluster configurations:
- Detects container escape risks (privileged=true, hostPID, hostPath mounts)
- Enforces NSA/CISA, MITRE ATT&CK, and CIS Kubernetes hardening frameworks
- Analyzes dangerous RBAC permissions and service account token exposures.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from adapters.base import AdapterResult, BaseAdapter, to_wsl_path
from control_plane.schemas.models import Finding, HostAsset, Severity
from control_plane.schemas.scope import ScopeManifest

logger = logging.getLogger("revenant.adapters.kubescape")


class KubescapeAdapter(BaseAdapter):
    """Adapter for Kubescape Kubernetes posture and manifest scanning."""

    def __init__(
        self,
        binary_override: Optional[str] = None,
        use_wsl: bool = True,
    ):
        super().__init__(
            name="kubescape",
            category="cloud",
            version="3.0+",
            binary_override=binary_override,
            use_wsl=use_wsl,
        )

    def is_installed(self) -> bool:
        return True

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        target_path = to_wsl_path(target) if self.use_wsl else target
        binary = self.binary_path or "kubescape"

        framework = params.get("framework", "nsa")
        cmd = [
            binary,
            "scan",
            "framework",
            framework,
            target_path,
            "--format", "json",
            "--keep-local",
            "--logger", "error",
        ]

        if params.get("verbose"):
            cmd.append("--verbose")

        return cmd

    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        findings: List[Finding] = []
        assets: List[HostAsset] = []

        # Always register the scanned K8s target asset
        asset = HostAsset(
            ip="127.0.0.1",
            hostname=f"k8s-workload:{os.path.basename(target)}",
            metadata={"type": "kubernetes", "target": target},
        )
        assets.append(asset)

        if not stdout.strip():
            return findings, assets

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            json_start = stdout.find("{")
            json_end = stdout.rfind("}")
            if json_start != -1 and json_end != -1:
                try:
                    data = json.loads(stdout[json_start : json_end + 1])
                except json.JSONDecodeError:
                    logger.warning("Failed to decode Kubescape JSON output")
                    return findings, assets
            else:
                return findings, assets

        # Schema 1: Summary / ControlReports structure (Kubescape v2)
        control_reports = data.get("controlReports", [])
        for ctrl in control_reports:
            ctrl_name = ctrl.get("name", "Unknown Control")
            ctrl_id = ctrl.get("controlID", "")
            base_score = ctrl.get("baseScore", 5.0)
            description = ctrl.get("description", "")
            remediation = ctrl.get("remediation", "")

            rule_reports = ctrl.get("ruleReports", [])
            for rule in rule_reports:
                rule_responses = rule.get("ruleResponses", [])
                for resp in rule_responses:
                    status = resp.get("alertStatus", "").lower()
                    if status in ["failed", "alert", "error"]:
                        alert_obj = resp.get("alertObject", {}).get("k8sApiObjects", [{}])[0]
                        res_kind = alert_obj.get("kind", "Workload")
                        res_name = alert_obj.get("metadata", {}).get("name", "workload")
                        res_ns = alert_obj.get("metadata", {}).get("namespace", "default")

                        sev = Severity.HIGH if base_score >= 7.0 else (
                            Severity.CRITICAL if base_score >= 9.0 else Severity.MEDIUM
                        )
                        mitre_id = "T1611" if "privileged" in ctrl_name.lower() or "host" in ctrl_name.lower() else "T1610"

                        finding = Finding(
                            title=f"Kubernetes Security Failure [{ctrl_id}]: {ctrl_name} on {res_kind}/{res_name}",
                            description=f"Namespace: {res_ns}\nControl: {ctrl_name}\nDetails: {description}",
                            severity=sev,
                            target=target,
                            tool=self.name,
                            cvss_score=min(9.8, max(4.0, float(base_score))),
                            cwe="CWE-250",
                            mitre_attack_ids=[mitre_id],
                            remediation=remediation or f"Remediate {ctrl_name} following NSA/CISA Kubernetes guidance.",
                            evidence=json.dumps(resp, indent=2)[:1500],
                        )
                        findings.append(finding)

        # Schema 2: Results & Resources structure (Kubescape v3+)
        resources_dict = {r.get("resourceID"): r for r in data.get("resources", [])}
        results = data.get("results", [])
        for res in results:
            res_id = res.get("resourceID", "")
            res_info = resources_dict.get(res_id, {}).get("object", {})
            res_kind = res_info.get("kind", "Workload")
            res_name = res_info.get("metadata", {}).get("name", "workload")
            res_ns = res_info.get("metadata", {}).get("namespace", "default")

            controls = res.get("controls", [])
            for ctrl in controls:
                status = ctrl.get("status", {}).get("status", "").lower()
                if status in ["failed", "alert", "error"]:
                    ctrl_name = ctrl.get("name", ctrl.get("controlID", "K8s Control"))
                    ctrl_id = ctrl.get("controlID", "K8S-CTRL")
                    base_score = ctrl.get("baseScore", 7.0)

                    sev = Severity.CRITICAL if base_score >= 8.5 else (
                        Severity.HIGH if base_score >= 6.5 else Severity.MEDIUM
                    )

                    is_escape = any(k in ctrl_name.lower() for k in ["privileged", "hostpath", "hostpid", "hostnetwork", "socket"])
                    mitre_id = "T1611" if is_escape else "T1613"

                    finding = Finding(
                        title=f"Kubernetes Security Misconfiguration [{ctrl_id}]: {ctrl_name} ({res_kind}/{res_name})",
                        description=f"Workload {res_kind}/{res_name} in namespace '{res_ns}' violated control {ctrl_id}: {ctrl_name}.",
                        severity=sev,
                        target=target,
                        tool=self.name,
                        cvss_score=min(9.8, max(4.0, float(base_score))),
                        cwe="CWE-250" if is_escape else "CWE-732",
                        mitre_attack_ids=[mitre_id],
                        remediation=f"Update manifest to enforce Pod Security Standards (restricted). Avoid {ctrl_name}.",
                        evidence=json.dumps({"resource": res_name, "namespace": res_ns, "control": ctrl_id}, indent=2),
                    )
                    findings.append(finding)

        return findings, assets
