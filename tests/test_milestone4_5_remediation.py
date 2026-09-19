"""
REVENANT — Milestone 4.5 Test Suite: Autonomous Remediation, SOAR & Platform GA
Tests:
- RemediationEngine: Terraform AWS fixes (S3, SG, IAM)
- RemediationEngine: Kubernetes NetworkPolicies & PodSecurityStandards patches
- RemediationEngine: Ansible OS / service hardening playbooks (SMB, Telnet/SSH)
- RemediationEngine: Detection Engineering (YARA and Sigma rule generation)
- SOARWebhookAdapter: Real live local HTTP webhook dispatch with HMAC-SHA256 signature verification
- ASMDaemon: Continuous attack surface monitoring, baseline establishment, drift detection, and automated dispatch
- End-to-End Autonomous Defensive Pipeline
"""

import http.server
import json
import os
import socketserver
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from adapters.soar.webhook_adapter import (
    SOARNotificationPayload,
    SOARPlatform,
    SOARWebhookAdapter,
)
from control_plane.schemas.models import Finding, Severity
from orchestrator.asm_daemon import ASMDaemon, DriftReport
from orchestrator.blackboard import BlackboardEvent, EventType, StigmergicBlackboard
from orchestrator.remediation.remediation_engine import (
    RemediationArtifact,
    RemediationEngine,
    RemediationType,
)


@pytest.fixture
def sample_s3_finding() -> Finding:
    return Finding(
        id="find-s3-public-01",
        title="Publicly Readable AWS S3 Storage Bucket",
        description="Bucket 'corp-internal-backups' allows unauthenticated public read/write access via S3 API.",
        severity=Severity.CRITICAL,
        target="s3://corp-internal-backups",
        tool="cloud_enum",
        cwe="CWE-284",
        mitre_attack_ids=["T1530", "T1087.004"],
        remediation="Enable S3 Block Public Access at the bucket and account level.",
        evidence="ACL: AllUsers READ/WRITE",
    )


@pytest.fixture
def sample_k8s_finding() -> Finding:
    return Finding(
        id="find-k8s-priv-01",
        title="Privileged Container with Lateral Movement Risk",
        description="Pod 'payment-worker' in namespace 'prod' runs with privileged: true and NET_RAW capability without network isolation.",
        severity=Severity.HIGH,
        target="prod/payment-worker",
        tool="kubescape",
        cwe="CWE-269",
        mitre_attack_ids=["T1611", "T1055"],
        remediation="Drop ALL capabilities and enforce default-deny NetworkPolicy.",
        evidence="privileged=true, NET_RAW=true",
    )


@pytest.fixture
def sample_smb_finding() -> Finding:
    return Finding(
        id="find-smb-01",
        title="Deprecated SMBv1 Protocol Enabled & Unsigned Sessions",
        description="Host 192.168.1.50 supports SMBv1 without mandatory SMB packet signing, vulnerable to NTLM relay and EternalBlue.",
        severity=Severity.HIGH,
        target="192.168.1.50",
        tool="nxc",
        cwe="CWE-319",
        mitre_attack_ids=["T1557.001", "T1210"],
        remediation="Disable SMBv1 and enforce SMB signing.",
        evidence="SMBv1=True, signing=False",
    )


@pytest.fixture
def sample_webshell_finding() -> Finding:
    return Finding(
        id="find-webshell-01",
        title="Obfuscated PHP Webshell Stager Detected",
        description="File /var/www/html/shell.php contains base64 eval execution stager connected to remote C2.",
        severity=Severity.CRITICAL,
        target="/var/www/html/shell.php",
        tool="yara",
        cwe="CWE-94",
        mitre_attack_ids=["T1505.003", "T1071"],
        remediation="Quarantine infected file and rotate web server credentials.",
        evidence="0xb4:$eval_b64: eval(base64_decode",
    )


# ==============================================================================
# 1. TERRAFORM REMEDIATION TESTS
# ==============================================================================
class TestTerraformRemediation:
    def test_s3_public_access_block(self, sample_s3_finding):
        engine = RemediationEngine()
        artifact = engine.generate_terraform_remediation(sample_s3_finding)

        assert artifact is not None
        assert artifact.artifact_type == RemediationType.TERRAFORM
        assert "s3_lockdown" in artifact.filename
        assert "aws_s3_bucket_public_access_block" in artifact.content
        assert "block_public_acls       = true" in artifact.content
        assert "restrict_public_buckets = true" in artifact.content
        assert "aws_s3_bucket_server_side_encryption_configuration" in artifact.content
        assert "terraform apply" in artifact.apply_command

    def test_security_group_lockdown(self):
        finding = Finding(
            title="Exposed Security Group Port 22 Open to 0.0.0.0/0",
            description="AWS security group sg-0123 allows unrestricted SSH from 0.0.0.0/0",
            severity=Severity.HIGH,
            target="sg-0123456789abcdef0",
            tool="prowler",
            cwe="CWE-284",
            mitre_attack_ids=["T1021.004"],
        )
        engine = RemediationEngine()
        artifact = engine.generate_terraform_remediation(finding)

        assert artifact is not None
        assert "aws_security_group_rule" in artifact.content
        assert "10.0.0.0/8" in artifact.content
        assert "from_port         = 22" in artifact.content


# ==============================================================================
# 2. KUBERNETES REMEDIATION TESTS
# ==============================================================================
class TestKubernetesRemediation:
    def test_network_policy_isolation(self, sample_k8s_finding):
        engine = RemediationEngine()
        artifact = engine.generate_kubernetes_remediation(sample_k8s_finding)

        assert artifact is not None
        assert artifact.artifact_type == RemediationType.KUBERNETES
        assert "kind: NetworkPolicy" in artifact.content
        assert "networking.k8s.io/v1" in artifact.content
        assert "revenant-default-deny-ingress" in artifact.content
        assert "kubectl apply" in artifact.apply_command

    def test_pod_security_hardening(self):
        finding = Finding(
            title="Kubernetes Pod Running As Root with Insecure Privileges",
            description="Kubescape audit flagged deployment api-gateway for root execution and writeable root filesystem",
            severity=Severity.MEDIUM,
            target="kube-system/api-gateway",
            tool="kubescape",
            cwe="CWE-250",
        )
        engine = RemediationEngine()
        artifact = engine.generate_kubernetes_remediation(finding)

        assert artifact is not None
        assert "runAsNonRoot: true" in artifact.content
        assert "readOnlyRootFilesystem: true" in artifact.content
        assert "drop:\n            - ALL" in artifact.content


# ==============================================================================
# 3. ANSIBLE REMEDIATION TESTS
# ==============================================================================
class TestAnsibleRemediation:
    def test_smb_hardening_playbook(self, sample_smb_finding):
        engine = RemediationEngine()
        artifact = engine.generate_ansible_remediation(sample_smb_finding)

        assert artifact is not None
        assert artifact.artifact_type == RemediationType.ANSIBLE
        assert "ansible.windows.win_regedit" in artifact.content
        assert "name: SMB1" in artifact.content
        assert "data: 0" in artifact.content
        assert "RequireSecuritySignature" in artifact.content
        assert "server min protocol = SMB2_02" in artifact.content
        assert "ansible-playbook" in artifact.apply_command

    def test_ssh_telnet_lockdown_playbook(self):
        finding = Finding(
            title="Unencrypted Telnet Service & Insecure SSH Configuration",
            description="Host is listening on telnet port 23 and sshd permits root login",
            severity=Severity.HIGH,
            target="10.0.0.5",
            tool="nmap",
            cwe="CWE-319",
        )
        engine = RemediationEngine()
        artifact = engine.generate_ansible_remediation(finding)

        assert artifact is not None
        assert "telnet.socket" in artifact.content
        assert "PermitRootLogin no" in artifact.content
        assert "PasswordAuthentication no" in artifact.content


# ==============================================================================
# 4. DETECTION ENGINEERING (YARA & SIGMA) TESTS
# ==============================================================================
class TestDetectionEngineering:
    def test_yara_rule_generation(self, sample_webshell_finding):
        engine = RemediationEngine()
        artifacts = engine.generate_detection_rules(sample_webshell_finding)

        yara_art = next((a for a in artifacts if a.artifact_type == RemediationType.YARA), None)
        assert yara_art is not None
        assert "rule REVENANT_AutoDetect_" in yara_art.content
        assert 'author = "REVENANT Autonomous Remediation Engine"' in yara_art.content
        assert "T1505.003" in yara_art.content
        assert "eval(base64_decode" in yara_art.content
        assert "any of ($s*) or $h1" in yara_art.content

    def test_sigma_rule_generation(self):
        finding = Finding(
            title="Process Injection & Remote Thread Creation Detected",
            description="Agent observed CreateRemoteThread and VirtualAllocEx memory tampering",
            severity=Severity.CRITICAL,
            target="WIN-SRV01:1337",
            tool="volatility",
            cwe="CWE-119",
            mitre_attack_ids=["T1055"],
        )
        engine = RemediationEngine()
        artifacts = engine.generate_detection_rules(finding)

        sigma_art = next((a for a in artifacts if a.artifact_type == RemediationType.SIGMA), None)
        assert sigma_art is not None
        parsed = yaml.safe_load(sigma_art.content)
        assert parsed["status"] == "experimental"
        assert parsed["logsource"]["product"] == "windows"
        assert "VirtualAllocEx" in parsed["detection"]["selection"]["CommandLine|contains"]
        assert parsed["level"] == "high"


# ==============================================================================
# 5. LIVE SOAR WEBHOOK DISPATCH TESTS
# ==============================================================================
class WebhookCaptureHandler(http.server.BaseHTTPRequestHandler):
    """Local HTTP handler capturing dispatched SOAR webhooks."""
    captured_requests: List[Dict[str, Any]] = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.__class__.captured_requests.append({
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
            "json": json.loads(body.decode("utf-8")),
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"received","ingested":true}')

    def log_message(self, format, *args):
        # Suppress standard logging to keep test runner output clean
        pass


@pytest.fixture(scope="module")
def live_soar_server():
    """Spin up local ephemeral HTTP webhook server for real live testing."""
    WebhookCaptureHandler.captured_requests = []
    server = socketserver.TCPServer(("127.0.0.1", 0), WebhookCaptureHandler)
    host, port = server.server_address
    server_url = f"http://127.0.0.1:{port}/webhook"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield server_url

    server.shutdown()
    server.server_close()


class TestSOARWebhookAdapterLive:
    def test_live_webhook_dispatch_with_hmac_signature(self, live_soar_server, sample_s3_finding, sample_webshell_finding):
        adapter = SOARWebhookAdapter()
        secret = "secret-revenant-hmac-key-2026"
        findings = [sample_s3_finding, sample_webshell_finding]

        res = adapter.dispatch(
            endpoint_url=live_soar_server,
            platform=SOARPlatform.GENERIC,
            event_title="Critical Compromise Detected in Cloud + Web Assets",
            findings=findings,
            secret=secret,
            metadata={"engagement": "Production Audit", "cluster": "us-east-1"},
        )

        assert res["success"] is True
        assert res["status_code"] == 200
        assert res["dispatched_count"] == 2

        # Verify captured request at live HTTP endpoint
        captured = WebhookCaptureHandler.captured_requests[-1]
        sig_header = next(
            (v for k, v in captured["headers"].items() if k.lower() == "x-revenant-signature"),
            None,
        )
        assert sig_header is not None
        expected_sig = f"sha256={SOARWebhookAdapter.sign_payload(secret, captured['body'])}"
        assert sig_header == expected_sig

        payload = captured["json"]
        assert payload["source"] == "REVENANT Autonomous Cyber Warfare Platform"
        assert payload["summary"]["critical"] == 2
        assert len(payload["findings"]) == 2

    def test_slack_payload_formatting(self, sample_s3_finding):
        adapter = SOARWebhookAdapter()
        payload = adapter.format_payload(
            platform=SOARPlatform.SLACK,
            event_title="S3 Bucket Compromise",
            findings=[sample_s3_finding],
        )

        assert "attachments" in payload
        attachment = payload["attachments"][0]
        assert attachment["color"] == "#E01E5A"  # Critical red
        blocks = attachment["blocks"]
        assert any("corp-internal-backups" in json.dumps(b) for b in blocks)

    def test_splunk_hec_formatting(self, sample_smb_finding):
        adapter = SOARWebhookAdapter()
        payload = adapter.format_payload(
            platform=SOARPlatform.SPLUNK_HEC,
            event_title="SMB Compromise Alert",
            findings=[sample_smb_finding],
            metadata={"index": "sec_ops"},
        )

        assert payload["sourcetype"] == "revenant:finding"
        assert payload["index"] == "sec_ops"
        assert payload["event"]["metrics"]["high"] == 1


# ==============================================================================
# 6. CONTINUOUS ATTACK SURFACE MANAGEMENT (ASM) DAEMON TESTS
# ==============================================================================
class TestASMDaemon:
    def test_drift_detection_lifecycle(self, sample_s3_finding, sample_smb_finding, sample_webshell_finding):
        daemon = ASMDaemon()

        # Cycle 1: Establish baseline with 2 findings
        cycle1_res = daemon.execute_cycle(simulated_cycle_findings=[sample_s3_finding, sample_smb_finding])
        assert cycle1_res["drift"]["new_count"] == 2
        assert cycle1_res["drift"]["resolved_count"] == 0
        assert cycle1_res["drift"]["persistent_count"] == 0
        assert cycle1_res["has_critical_drift"] is True

        # Cycle 2: S3 finding resolved, webshell finding introduced, SMB finding persistent
        cycle2_res = daemon.execute_cycle(simulated_cycle_findings=[sample_smb_finding, sample_webshell_finding])
        assert cycle2_res["drift"]["new_count"] == 1       # webshell is new
        assert cycle2_res["drift"]["resolved_count"] == 1  # s3 is resolved
        assert cycle2_res["drift"]["persistent_count"] == 1 # smb is persistent
        assert cycle2_res["remediation_artifacts_count"] >= 1  # generated YARA/Remediation for webshell

    def test_asm_with_live_soar_dispatch(self, live_soar_server, sample_webshell_finding):
        daemon = ASMDaemon(
            soar_url=live_soar_server,
            soar_platform=SOARPlatform.GENERIC,
            soar_secret="asm-daemon-secret",
        )
        daemon.register_target("https://target.corp.local")

        res = daemon.execute_cycle(simulated_cycle_findings=[sample_webshell_finding])
        assert res["soar_result"] is not None
        assert res["soar_result"]["success"] is True
        assert res["soar_result"]["status_code"] == 200
        assert res["attack_graph_nodes"] > 0


# ==============================================================================
# 7. FULL END-TO-END AUTONOMOUS REMEDIATION CAMPAIGN
# ==============================================================================
class TestEndToEndRemediationCampaign:
    def test_full_campaign_remediation_export(self, tmp_path, sample_s3_finding, sample_k8s_finding, sample_smb_finding, sample_webshell_finding):
        engine = RemediationEngine(output_dir=str(tmp_path))
        findings = [sample_s3_finding, sample_k8s_finding, sample_smb_finding, sample_webshell_finding]

        artifacts = engine.remediate_campaign(findings)
        assert len(artifacts) >= 5

        exported_paths = engine.export_artifacts(artifacts)
        assert len(exported_paths) == len(artifacts)

        # Verify artifacts exist on filesystem in subdirectories
        for p in exported_paths:
            assert os.path.exists(p)
            assert os.path.getsize(p) > 0

        # Verify directory structure
        assert (tmp_path / "terraform").exists()
        assert (tmp_path / "kubernetes").exists()
        assert (tmp_path / "ansible").exists()
        assert (tmp_path / "yara").exists()
