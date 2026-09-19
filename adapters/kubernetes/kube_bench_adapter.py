"""
REVENANT — kube-bench CIS Kubernetes Benchmark Adapter
Audits Kubernetes master nodes, worker nodes, and control planes against
the official Center for Internet Security (CIS) Kubernetes Benchmark:
- Master Node Configuration (API server flags, etcd permissions, controller manager)
- Worker Node & Kubelet Configuration (read-only port, anonymous auth, webhook auth)
- Control Plane Security Policies & Pod Security Standards.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from adapters.base import AdapterResult, BaseAdapter, to_wsl_path
from control_plane.schemas.models import Finding, HostAsset, Severity
from control_plane.schemas.scope import ScopeManifest

logger = logging.getLogger("revenant.adapters.kube_bench")


class KubeBenchAdapter(BaseAdapter):
    """Adapter for kube-bench CIS Kubernetes Benchmark auditing."""

    def __init__(
        self,
        binary_override: Optional[str] = None,
        use_wsl: bool = True,
    ):
        super().__init__(
            name="kube-bench",
            category="cloud",
            version="0.7+",
            binary_override=binary_override,
            use_wsl=use_wsl,
        )

    def is_installed(self) -> bool:
        return True

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        binary = self.binary_path or "kube-bench"
        targets = params.get("targets", ["master", "node"])
        if isinstance(targets, str):
            targets = [targets]

        cmd = [binary, "run", "--json"]
        if targets:
            cmd.extend(["--targets", ",".join(targets)])

        benchmark = params.get("benchmark")
        if benchmark:
            cmd.extend(["--benchmark", benchmark])

        return cmd

    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        findings: List[Finding] = []
        assets: List[HostAsset] = []

        asset = HostAsset(
            ip="127.0.0.1",
            hostname=f"k8s-node:{target or 'cluster-node'}",
            metadata={"type": "kubernetes-node", "target": target},
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
                    return findings, assets
            else:
                return findings, assets

        controls_list = data.get("Controls", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])

        for ctrl_group in controls_list:
            group_text = ctrl_group.get("text", "CIS Section")
            tests_list = ctrl_group.get("tests", [])

            for test_section in tests_list:
                section_name = test_section.get("desc", group_text)
                results = test_section.get("results", [])

                for item in results:
                    status = item.get("status", "").upper()
                    if status in ["FAIL", "WARN"]:
                        test_num = item.get("test_number", "CIS")
                        test_desc = item.get("test_desc", "CIS Test Failure")
                        audit_cmd = item.get("audit", "")
                        remediation = item.get("remediation", "")

                        is_fail = (status == "FAIL")
                        severity = Severity.HIGH if is_fail else Severity.MEDIUM
                        cvss = 7.5 if is_fail else 5.0

                        finding = Finding(
                            title=f"CIS Kubernetes Benchmark Failure [{test_num}]: {test_desc}",
                            description=(
                                f"Section: {section_name}\n"
                                f"CIS Benchmark Test: {test_num}\n"
                                f"Status: {status}\n"
                                f"Audit Command: {audit_cmd}"
                            ),
                            severity=severity,
                            target=target,
                            tool=self.name,
                            cvss_score=cvss,
                            cwe="CWE-16",
                            mitre_attack_ids=["T1613"],
                            remediation=remediation or f"Apply CIS Benchmark recommendation for test {test_num}.",
                            evidence=json.dumps(item, indent=2),
                        )
                        findings.append(finding)

        return findings, assets
