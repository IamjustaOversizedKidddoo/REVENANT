"""
REVENANT — Milestone 4.1: Kubernetes & Cloud-Native Security Engine Test Suite
Tests Kubescape, kube-bench, Falco adapters, KubernetesAgent swarm specialist,
and AttackGraph container breakout and cluster-admin correlation chains.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
import pytest

from adapters.kubernetes.falco_adapter import FalcoAdapter
from adapters.kubernetes.kube_bench_adapter import KubeBenchAdapter
from adapters.kubernetes.kubescape_adapter import KubescapeAdapter
from control_plane.schemas.models import Finding, HostAsset, Severity
from control_plane.schemas.scope import ScopeManifest
from orchestrator.agents.kubernetes_agent import KubernetesAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType
from orchestrator.correlation.attack_graph_engine import AttackGraphEngine


# ============================================================================
# 1. Kubescape Adapter Tests
# ============================================================================

class TestKubescapeAdapter:
    """Unit tests for KubescapeAdapter command generation and output parsing."""

    def test_build_command_default_framework(self):
        adapter = KubescapeAdapter(use_wsl=False)
        cmd = adapter.build_command("deployment.yaml", {})
        assert "kubescape" in cmd[0]
        assert "scan" in cmd
        assert "framework" in cmd
        assert "nsa" in cmd
        assert "--format" in cmd
        assert "json" in cmd

    def test_build_command_custom_framework(self):
        adapter = KubescapeAdapter(use_wsl=False)
        cmd = adapter.build_command("manifests/", {"framework": "mitre", "verbose": True})
        assert "mitre" in cmd
        assert "--verbose" in cmd

    def test_parse_kubescape_v3_results(self):
        adapter = KubescapeAdapter()
        sample_json = {
            "resources": [
                {
                    "resourceID": "apps/v1/Deployment/default/privileged-webapp",
                    "object": {
                        "kind": "Deployment",
                        "metadata": {"name": "privileged-webapp", "namespace": "default"},
                    },
                }
            ],
            "results": [
                {
                    "resourceID": "apps/v1/Deployment/default/privileged-webapp",
                    "controls": [
                        {
                            "controlID": "C-0017",
                            "name": "Privileged container",
                            "baseScore": 9.0,
                            "status": {"status": "failed"},
                        },
                        {
                            "controlID": "C-0046",
                            "name": "Insecure hostPath volume",
                            "baseScore": 8.0,
                            "status": {"status": "failed"},
                        },
                        {
                            "controlID": "C-0001",
                            "name": "Configured resource limits",
                            "baseScore": 5.0,
                            "status": {"status": "passed"},
                        },
                    ],
                }
            ],
        }
        findings, assets = adapter.parse_output(json.dumps(sample_json), "", "vulnerable.yaml")

        assert len(assets) == 1
        assert assets[0].metadata.get("type") == "kubernetes"
        assert len(findings) == 2

        priv_finding = next((f for f in findings if "Privileged container" in f.title), None)
        assert priv_finding is not None
        assert priv_finding.severity == Severity.CRITICAL
        assert "T1611" in priv_finding.mitre_attack_ids
        assert priv_finding.tool == "kubescape"

        host_finding = next((f for f in findings if "hostPath" in f.title), None)
        assert host_finding is not None
        assert host_finding.severity == Severity.HIGH
        assert "T1611" in host_finding.mitre_attack_ids

    def test_parse_kubescape_v2_control_reports(self):
        adapter = KubescapeAdapter()
        sample_json = {
            "controlReports": [
                {
                    "controlID": "C-0057",
                    "name": "Host PID / IPC sharing",
                    "baseScore": 8.5,
                    "description": "Sharing host PID allows container processes to view host processes.",
                    "remediation": "Set hostPID: false in the pod spec.",
                    "ruleReports": [
                        {
                            "ruleResponses": [
                                {
                                    "alertStatus": "failed",
                                    "alertObject": {
                                        "k8sApiObjects": [
                                            {
                                                "kind": "Pod",
                                                "metadata": {"name": "vuln-pod", "namespace": "prod"},
                                            }
                                        ]
                                    },
                                }
                            ]
                        }
                    ],
                }
            ]
        }
        findings, assets = adapter.parse_output(json.dumps(sample_json), "", "pod.yaml")
        assert len(findings) == 1
        f = findings[0]
        assert "Host PID" in f.title
        assert f.severity == Severity.HIGH
        assert "T1611" in f.mitre_attack_ids
        assert f.tool == "kubescape"
        assert "Set hostPID: false" in f.remediation


# ============================================================================
# 2. kube-bench Adapter Tests
# ============================================================================

class TestKubeBenchAdapter:
    """Unit tests for KubeBenchAdapter CIS Benchmark parsing."""

    def test_build_command(self):
        adapter = KubeBenchAdapter(use_wsl=False)
        cmd = adapter.build_command("master", {"targets": ["master", "node"], "benchmark": "cis-1.6"})
        assert "kube-bench" in cmd[0]
        assert "run" in cmd
        assert "--json" in cmd
        assert "master,node" in cmd[cmd.index("--targets") + 1]
        assert "cis-1.6" in cmd[cmd.index("--benchmark") + 1]

    def test_parse_output_fail_and_warn(self):
        adapter = KubeBenchAdapter()
        sample_json = {
            "Controls": [
                {
                    "id": "1",
                    "text": "Control Plane Components",
                    "tests": [
                        {
                            "section": "1.1",
                            "desc": "Master Node Configuration",
                            "results": [
                                {
                                    "test_number": "1.1.1",
                                    "test_desc": "Ensure API server pod specification file permissions are 600",
                                    "status": "FAIL",
                                    "audit": "stat -c %a /etc/kubernetes/manifests/kube-apiserver.yaml",
                                    "remediation": "chmod 600 /etc/kubernetes/manifests/kube-apiserver.yaml",
                                },
                                {
                                    "test_number": "1.2.1",
                                    "test_desc": "Ensure anonymous requests are not enabled on kubelet",
                                    "status": "WARN",
                                    "audit": "grep anonymous /var/lib/kubelet/config.yaml",
                                    "remediation": "Set authentication.anonymous.enabled to false",
                                },
                                {
                                    "test_number": "1.3.1",
                                    "test_desc": "Ensure client CA file is configured",
                                    "status": "PASS",
                                    "audit": "",
                                    "remediation": "",
                                },
                            ],
                        }
                    ],
                }
            ]
        }
        findings, assets = adapter.parse_output(json.dumps(sample_json), "", "k8s-cluster")
        assert len(assets) == 1
        assert len(findings) == 2

        fail_f = next((f for f in findings if "1.1.1" in f.title), None)
        assert fail_f is not None
        assert fail_f.severity == Severity.HIGH
        assert fail_f.cvss_score == 7.5
        assert fail_f.tool == "kube-bench"

        warn_f = next((f for f in findings if "1.2.1" in f.title), None)
        assert warn_f is not None
        assert warn_f.severity == Severity.MEDIUM
        assert warn_f.cvss_score == 5.0


# ============================================================================
# 3. Falco Adapter Tests
# ============================================================================

class TestFalcoAdapter:
    """Unit tests for FalcoAdapter runtime behavioral alert ingestion."""

    def test_build_command(self):
        adapter = FalcoAdapter(use_wsl=False)
        cmd = adapter.build_command("audit.log", {"rules_file": "/etc/falco/rules.yaml"})
        assert "falco" in cmd[0]
        assert "-r" in cmd
        assert "/etc/falco/rules.yaml" in cmd

    def test_parse_streaming_json_alerts(self):
        adapter = FalcoAdapter()
        raw_stream = (
            '{"rule": "Terminal shell in container", "priority": "Warning", "output": "Terminal shell spawned in container", "output_fields": {"container.name": "webapp", "proc.name": "bash", "user.name": "root"}}\n'
            '{"rule": "Privileged container breakout attempt", "priority": "Critical", "output": "Privileged breakout detected via /proc mount", "output_fields": {"container.name": "webapp"}}\n'
            '{"rule": "Read sensitive file untrusted", "priority": "Notice", "output": "Read /etc/shadow", "output_fields": {"container.name": "backend"}}\n'
        )
        findings, assets = adapter.parse_output(raw_stream, "", "cluster")
        assert len(findings) == 3

        shell_f = next((f for f in findings if "Terminal shell" in f.title), None)
        assert shell_f is not None
        assert shell_f.severity == Severity.HIGH
        assert "T1059.004" in shell_f.mitre_attack_ids
        assert shell_f.tool == "falco"

        breakout_f = next((f for f in findings if "breakout" in f.title), None)
        assert breakout_f is not None
        assert breakout_f.severity == Severity.CRITICAL
        assert "T1611" in breakout_f.mitre_attack_ids

        notice_f = next((f for f in findings if "sensitive file" in f.title), None)
        assert notice_f is not None
        assert notice_f.severity == Severity.MEDIUM


# ============================================================================
# 4. Kubernetes Agent Swarm Specialist Tests
# ============================================================================

class TestKubernetesAgent:
    """Unit tests for KubernetesAgent swarm integration."""

    def test_can_handle_manifest_target(self):
        agent = KubernetesAgent()
        ev_yaml = BlackboardEvent(
            event_type=EventType.TARGET_REGISTERED,
            source_agent="orchestrator",
            target="tests/fixtures/k8s/vulnerable_deployment.yaml",
        )
        assert agent.can_handle(ev_yaml) is True

        ev_container = BlackboardEvent(
            event_type=EventType.CONTAINER_DISCOVERED,
            source_agent="recon",
            target="k8s-pod:nginx-proxy",
        )
        assert agent.can_handle(ev_container) is True

        ev_repo = BlackboardEvent(
            event_type=EventType.REPO_DISCOVERED,
            source_agent="recon",
            target="https://github.com/org/repo.git",
        )
        assert agent.can_handle(ev_repo) is False

    def test_handle_emits_container_escape_event(self):
        # Create a mock kubescape adapter returning a privileged finding
        class MockKubescape(KubescapeAdapter):
            def run(self, target, scope, params=None):
                f = Finding(
                    title="Kubernetes Security Failure [C-0017]: Privileged container on Deployment/webapp",
                    description="Privileged container detected",
                    severity=Severity.CRITICAL,
                    target=target,
                    tool="kubescape",
                    cvss_score=9.5,
                    cwe="CWE-250",
                    mitre_attack_ids=["T1611"],
                    remediation="Remove privileged: true",
                )
                from adapters.base import AdapterResult
                return AdapterResult(
                    tool_name="kubescape",
                    target=target,
                    findings=[f],
                    discovered_assets=[HostAsset(ip="127.0.0.1", hostname="k8s-webapp")],
                )

        agent = KubernetesAgent(kubescape_adapter=MockKubescape())
        bb = Blackboard()
        scope = ScopeManifest(allowed_hosts=["127.0.0.1"], allowed_cidrs=["0.0.0.0/0"])

        ev = BlackboardEvent(
            event_type=EventType.TARGET_REGISTERED,
            source_agent="orchestrator",
            target="vulnerable_deployment.yaml",
        )
        emitted = agent.handle(ev, bb, scope)

        assert len(emitted) == 1
        assert emitted[0].event_type == EventType.PRIVILEGE_ESCALATION_PATH_DETECTED
        assert emitted[0].payload.get("is_container_escape") is True
        assert len(bb.get_findings()) == 1
        assert len(bb.get_assets()) == 1


# ============================================================================
# 5. Kubernetes Attack Graph & Breakout Correlation Tests
# ============================================================================

class TestKubernetesAttackGraph:
    """Tests cross-domain correlation for Container Breakout and K8s Cluster Admin Takeover."""

    def test_k8s_attack_graph_chains(self):
        engine = AttackGraphEngine()

        finding_escape = Finding(
            title="Kubernetes Security Failure [C-0017]: Privileged container and docker.sock escape",
            description="Container runs as root with host docker socket mounted",
            severity=Severity.CRITICAL,
            target="k8s-pod:privileged-webapp",
            tool="kubescape",
            cvss_score=9.5,
            cwe="CWE-250",
            mitre_attack_ids=["T1611"],
        )

        finding_rbac = Finding(
            title="Dangerous RBAC: ClusterRoleBinding grants cluster-admin to ServiceAccount",
            description="Default namespace service account holds cluster-admin permissions",
            severity=Severity.CRITICAL,
            target="k8s-sa:cluster-admin-sa",
            tool="kubescape",
            cvss_score=9.8,
            cwe="CWE-250",
            mitre_attack_ids=["T1078"],
        )

        graph = engine.build_graph(
            findings=[finding_escape, finding_rbac],
            assets=[
                HostAsset(ip="127.0.0.1", hostname="k8s-pod:privileged-webapp"),
                HostAsset(ip="127.0.0.1", hostname="k8s-sa:cluster-admin-sa"),
            ],
        )

        # 1. Host Node Root Execution objective must be synthesized
        assert "obj_host_kernel" in graph.nodes
        assert graph.nodes["obj_host_kernel"].label == "Host Node Root Execution"

        # 2. Kubernetes Cluster-Admin Takeover objective must be synthesized
        assert "obj_k8s_cluster_admin" in graph.nodes
        assert graph.nodes["obj_k8s_cluster_admin"].label == "Kubernetes Cluster-Admin Takeover"

        # 3. Check for directed breakout edge
        breakout_edge = next((e for e in graph.edges if e.target == "obj_host_kernel"), None)
        assert breakout_edge is not None
        assert breakout_edge.label == "Container Breakout"

        # 4. Check for directed RBAC takeover edge
        rbac_edge = next((e for e in graph.edges if e.target == "obj_k8s_cluster_admin"), None)
        assert rbac_edge is not None
        assert rbac_edge.label == "Privileged ServiceAccount"

        # 5. Verify attack paths
        paths = graph.find_attack_paths(max_depth=5)
        assert len(paths) >= 2


# ============================================================================
# 6. Live Manifest Audit (Real Tool / Test Manifest)
# ============================================================================

@pytest.mark.live
class TestKubescapeLiveManifest:
    """
    LABEL: REAL-TOOL-vs-TEST-MANIFEST
    Executes real kubescape binary in WSL2 against the vulnerable K8s manifest fixture.
    """

    def test_kubescape_live_manifest_scan(self):
        # Verify kubescape binary is present in WSL2
        check = subprocess.run(
            ["wsl", "-d", "Ubuntu", "-e", "bash", "-c", "which kubescape 2>&1"],
            capture_output=True, text=True, timeout=15,
        )
        if not check.stdout.strip() or check.returncode != 0:
            pytest.skip("kubescape binary is not installed in WSL2 — skipping live manifest execution")

        fixture_wsl = "/mnt/d/REVENANT/tests/fixtures/k8s/vulnerable_deployment.yaml"
        result = subprocess.run(
            ["wsl", "-d", "Ubuntu", "-e", "bash", "-c",
             f"kubescape scan {fixture_wsl} --format json --logger error"],
            capture_output=True, text=True, timeout=60,
        )

        raw_stdout = result.stdout
        print("\n[LIVE kubescape output length]:", len(raw_stdout))
        assert len(raw_stdout.strip()) > 50, f"Expected Kubescape JSON output, got: {raw_stdout[:300]}"

        # Feed real output through adapter parser
        adapter = KubescapeAdapter(use_wsl=True)
        findings, assets = adapter.parse_output(raw_stdout, result.stderr, "tests/fixtures/k8s/vulnerable_deployment.yaml")

        print(f"[LIVE K8s findings count]: {len(findings)}")
        print(f"[LIVE K8s findings sample]: {[f.title for f in findings[:5]]}")

        assert len(findings) >= 1
        assert len(assets) >= 1
