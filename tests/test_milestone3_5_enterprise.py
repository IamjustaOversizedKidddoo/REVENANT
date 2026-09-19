"""
REVENANT — Milestone 3.5 Enterprise Intelligence & Release v1.2 Test Suite
Validates ComplianceMapper (NIST AI RMF, OWASP LLM, CIS Controls v8, OWASP MASVS),
FaradayExporter, DradisExporter, ReportGenerator multi-format exports,
API report endpoints, and master multi-domain synthesis.
"""

from __future__ import annotations

import json
import pytest
from fastapi.testclient import TestClient

from control_plane.api.main import app, campaigns_db
from control_plane.schemas.models import CodeLocation, Finding, HostAsset, PortInfo, Severity
from control_plane.schemas.scope import ScopeManifest
from orchestrator.blackboard import Blackboard
from reporting.compliance_mapper import ComplianceMapper
from reporting.enterprise_exporters import DradisExporter, FaradayExporter
from reporting.generator import ReportGenerator

client = TestClient(app)


@pytest.fixture
def multi_domain_findings() -> list[Finding]:
    """Sample cross-domain findings across Web, SAST, Cloud, Identity, Mobile, AI, and Purple Teaming."""
    return [
        # 1. SAST Secrets
        Finding(
            title="Hardcoded AWS Production Access Key",
            description="AWS root key exposed in codebase.",
            severity=Severity.CRITICAL,
            target="repo:revenant-core",
            tool="gitleaks",
            cwe="CWE-798",
            secret_type="AWS",
            mitre_attack_ids=["T1552.001"],
            remediation="Rotate AWS key and store in AWS Secrets Manager.",
        ),
        # 2. Web DAST
        Finding(
            title="SQL Injection on Login Parameter",
            description="Classic boolean SQLi on username parameter.",
            severity=Severity.HIGH,
            target="http://127.0.0.1:3000/api/login",
            tool="dast",
            cwe="CWE-89",
            mitre_attack_ids=["T1190"],
            remediation="Use parameterized prepared statements.",
        ),
        # 3. Cloud Posture
        Finding(
            title="Public AWS S3 Bucket with Customer Data",
            description="S3 bucket allows anonymous read access.",
            severity=Severity.HIGH,
            target="s3://customer-data-bucket",
            tool="prowler",
            cwe="CWE-732",
            mitre_attack_ids=["T1530"],
            remediation="Enable S3 Block Public Access.",
        ),
        # 4. Identity / Active Directory
        Finding(
            title="Kerberoasting Vulnerability: SPN on High Privilege Account",
            description="ServicePrincipalName registered on Domain Admin account.",
            severity=Severity.HIGH,
            target="svc_backup@CORP.LOCAL",
            tool="netexec",
            cwe="CWE-521",
            mitre_attack_ids=["T1558.003"],
            remediation="Use Group Managed Service Accounts (gMSA).",
        ),
        # 5. Mobile Security
        Finding(
            title="Mobile: Insecure Exported Broadcast Receiver",
            description="Broadcast receiver exported without intent permissions.",
            severity=Severity.HIGH,
            target="com.revenant.app",
            tool="mobsfscan",
            cwe="CWE-926",
            owasp_category="MASVS-PLATFORM",
            mitre_attack_ids=["T1624"],
            remediation="Set android:exported='false' or apply permissions.",
        ),
        # 6. GenAI / LLM
        Finding(
            title="AI/LLM: Direct Prompt Injection via Role Impersonation",
            description="Model bypassed safety guardrails and leaked system prompt.",
            severity=Severity.HIGH,
            target="http://127.0.0.1:8001/v1/chat/completions",
            tool="ai_redteam",
            cwe="CWE-77",
            owasp_category="LLM01",
            mitre_attack_ids=["AML.T0051"],
            remediation="Apply dual-LLM verification guardrail and XML delimiters.",
        ),
        # 7. Purple Teaming
        Finding(
            title="Defensive Blind Spot: Undetected TTP T1087.001 (Local Account Enumeration)",
            description="Local user discovery executed without detection or logging.",
            severity=Severity.MEDIUM,
            target="127.0.0.1",
            tool="detection_engine",
            mitre_attack_ids=["T1087.001"],
            remediation="Deploy Sigma rule for net.exe and Get-LocalUser.",
        ),
    ]


@pytest.fixture
def sample_assets() -> list[HostAsset]:
    return [
        HostAsset(
            ip="127.0.0.1",
            hostname="revenant-host",
            os="Ubuntu Linux / Windows",
            cloud_provider="AWS",
            ports=[
                PortInfo(port=80, protocol="tcp", state="open", service="http"),
                PortInfo(port=443, protocol="tcp", state="open", service="https"),
                PortInfo(port=8001, protocol="tcp", state="open", service="ai-api"),
            ],
        )
    ]


class TestComplianceMapper:
    """Verifies compliance mappings across NIST AI RMF, OWASP LLM, CIS Controls, and OWASP MASVS."""

    def test_frameworks_registered(self):
        mapper = ComplianceMapper()
        assert "NIST_AI_RMF" in mapper.frameworks
        assert "OWASP_LLM" in mapper.frameworks
        assert "CIS_V8" in mapper.frameworks
        assert "OWASP_MASVS" in mapper.frameworks

    def test_ai_finding_maps_to_nist_and_owasp_llm(self, multi_domain_findings: list[Finding]):
        mapper = ComplianceMapper()
        ai_finding = next(f for f in multi_domain_findings if f.tool == "ai_redteam")
        controls = mapper.map_finding_to_controls(ai_finding)

        control_ids = {c.control_id for c in controls}
        assert "LLM01" in control_ids
        assert "MEASURE-2.6" in control_ids
        assert "MANAGE-1.3" in control_ids

    def test_mobile_finding_maps_to_masvs(self, multi_domain_findings: list[Finding]):
        mapper = ComplianceMapper()
        mobile_finding = next(f for f in multi_domain_findings if f.tool == "mobsfscan")
        controls = mapper.map_finding_to_controls(mobile_finding)

        control_ids = {c.control_id for c in controls}
        assert "MASVS-PLATFORM" in control_ids
        assert "CIS-16" in control_ids

    def test_secret_finding_maps_to_cis_controls(self, multi_domain_findings: list[Finding]):
        mapper = ComplianceMapper()
        secret_finding = next(f for f in multi_domain_findings if f.cwe == "CWE-798")
        controls = mapper.map_finding_to_controls(secret_finding)

        control_ids = {c.control_id for c in controls}
        assert "CIS-3" in control_ids  # Data Protection

    def test_compliance_evaluation_summary(self, multi_domain_findings: list[Finding]):
        mapper = ComplianceMapper()
        summary = mapper.evaluate_compliance(multi_domain_findings)

        assert "NIST_AI_RMF" in summary
        assert "OWASP_LLM" in summary
        assert "CIS_V8" in summary
        assert "OWASP_MASVS" in summary

        # Verify posture percentages are calculated
        for fw_name, data in summary.items():
            assert 0.0 <= data["posture_percentage"] <= 100.0
            assert data["findings_count"] >= 1

    def test_markdown_compliance_scorecard(self, multi_domain_findings: list[Finding]):
        mapper = ComplianceMapper()
        md = mapper.generate_markdown_summary(multi_domain_findings)

        assert "Enterprise Regulatory & Compliance Posture" in md
        assert "NIST AI RMF 1.0" in md
        assert "OWASP Top 10 for LLM Applications" in md
        assert "CIS Critical Security Controls v8" in md
        assert "OWASP Mobile Security Verification" in md


class TestFaradayExporter:
    """Verifies Faraday JSON export formatting and schema compliance."""

    def test_faraday_export_structure(
        self, multi_domain_findings: list[Finding], sample_assets: list[HostAsset]
    ):
        exporter = FaradayExporter()
        payload = exporter.export(
            campaign_id="camp-test-1234",
            target="127.0.0.1",
            assets=sample_assets,
            findings=multi_domain_findings,
        )

        assert payload["faraday_schema_version"] == "3.0"
        assert payload["workspace"] == "revenant_camp-tes"
        assert len(payload["hosts"]) == 1
        assert len(payload["vulnerabilities"]) == len(multi_domain_findings)

        # Verify host services
        host = payload["hosts"][0]
        assert host["ip"] == "127.0.0.1"
        assert len(host["services"]) == 3

        # Verify vulnerability severity mapping
        vulns = payload["vulnerabilities"]
        crit_vuln = next(v for v in vulns if v["cwe"] == "CWE-798")
        assert crit_vuln["severity"] == "critical"
        assert crit_vuln["cvss"] >= 9.0

        high_vuln = next(v for v in vulns if v["cwe"] == "CWE-89")
        assert high_vuln["severity"] == "high"


class TestDradisExporter:
    """Verifies Dradis project export formatting and issue templates."""

    def test_dradis_export_structure(
        self, multi_domain_findings: list[Finding], sample_assets: list[HostAsset]
    ):
        exporter = DradisExporter()
        payload = exporter.export(
            campaign_id="camp-test-1234",
            target="127.0.0.1",
            assets=sample_assets,
            findings=multi_domain_findings,
        )

        assert payload["dradis_template_version"] == "4.0"
        assert payload["project"]["campaign_id"] == "camp-test-1234"
        assert len(payload["nodes"]) >= 1
        assert len(payload["issues"]) == len(multi_domain_findings)

        # Check raw template fields
        first_issue = payload["issues"][0]
        assert "#[Title]#" in first_issue["raw_template"]
        assert "#[Severity]#" in first_issue["raw_template"]
        assert "#[Remediation]#" in first_issue["raw_template"]
        assert "#[Evidence]#" in first_issue["raw_template"]


class TestReportGeneratorEnterpriseIntegration:
    """Verifies ReportGenerator exports Faraday, Dradis, and Compliance reports."""

    def test_generator_faraday_export(
        self, multi_domain_findings: list[Finding], sample_assets: list[HostAsset]
    ):
        gen = ReportGenerator(
            campaign_id="camp-ent-001",
            target="127.0.0.1",
            assets=sample_assets,
            findings=multi_domain_findings,
        )
        data = gen.generate_faraday()
        assert data["faraday_schema_version"] == "3.0"
        assert data["summary"]["total_vulnerabilities"] == len(multi_domain_findings)

    def test_generator_dradis_export(
        self, multi_domain_findings: list[Finding], sample_assets: list[HostAsset]
    ):
        gen = ReportGenerator(
            campaign_id="camp-ent-001",
            target="127.0.0.1",
            assets=sample_assets,
            findings=multi_domain_findings,
        )
        data = gen.generate_dradis()
        assert data["dradis_template_version"] == "4.0"
        assert data["summary"]["total_issues"] == len(multi_domain_findings)

    def test_generator_compliance_report_in_json_and_markdown(
        self, multi_domain_findings: list[Finding], sample_assets: list[HostAsset]
    ):
        gen = ReportGenerator(
            campaign_id="camp-ent-001",
            target="127.0.0.1",
            assets=sample_assets,
            findings=multi_domain_findings,
        )
        # JSON includes compliance posture
        json_data = gen.generate_json()
        assert "compliance_posture" in json_data
        assert "NIST_AI_RMF" in json_data["compliance_posture"]

        # Markdown includes compliance scorecard
        md = gen.generate_markdown()
        assert "## Regulatory & Framework Compliance Posture" in md
        assert "NIST AI RMF 1.0" in md


class TestControlPlaneApiEnterpriseReporting:
    """Verifies FastAPI control plane endpoints support faraday and dradis export formats."""

    def test_api_report_faraday_and_dradis_formats(
        self, multi_domain_findings: list[Finding], sample_assets: list[HostAsset]
    ):
        campaign_id = "test-camp-api-999"
        bb = Blackboard(campaign_id=campaign_id)
        for a in sample_assets:
            bb.add_asset(a)
        for f in multi_domain_findings:
            bb.add_finding(f)

        campaigns_db[campaign_id] = {
            "campaign_id": campaign_id,
            "target": "127.0.0.1",
            "status": "COMPLETED",
            "created_at": "2026-09-18T10:00:00Z",
            "summary": bb.get_summary(),
            "blackboard": bb,
            "scope": ScopeManifest(allowed_hosts=["127.0.0.1"]),
        }

        # Query Faraday format
        res_faraday = client.get(f"/api/v1/campaigns/{campaign_id}/report?format=faraday")
        assert res_faraday.status_code == 200
        data_f = res_faraday.json()
        assert data_f["faraday_schema_version"] == "3.0"
        assert len(data_f["vulnerabilities"]) == len(multi_domain_findings)

        # Query Dradis format
        res_dradis = client.get(f"/api/v1/campaigns/{campaign_id}/report?format=dradis")
        assert res_dradis.status_code == 200
        data_d = res_dradis.json()
        assert data_d["dradis_template_version"] == "4.0"
        assert len(data_d["issues"]) == len(multi_domain_findings)


class TestMasterMultiDomainMissionSynthesis:
    """Validates complete multi-domain synthesis across all 7 domains in REVENANT."""

    def test_multi_domain_attack_graph_all_chains(
        self, multi_domain_findings: list[Finding], sample_assets: list[HostAsset]
    ):
        gen = ReportGenerator(
            campaign_id="camp-synthesis-master",
            target="127.0.0.1",
            assets=sample_assets,
            findings=multi_domain_findings,
        )
        graph = gen.attack_graph

        # Check that high-value objectives exist from multiple chains
        obj_nodes = [n for n in graph.nodes.values() if n.node_type.value == "OBJECTIVE"]
        obj_labels = {n.label for n in obj_nodes}

        # Chains present in synthesis:
        # Chain A/B: Database Compromise / Cloud IAM Compromise
        # Chain C: Domain Controller Admin
        # Chain F: Autonomous Agent Hijack
        # Chain G: Mobile Component Hijack
        # Chain H: Unmonitored Adversary Path
        assert any("Domain Admin" in l or "Active Directory" in l for l in obj_labels)
        assert any("Cloud Control Plane" in l or "IAM Admin" in l for l in obj_labels)
        assert any("Autonomous Agent Hijack" in l for l in obj_labels)
        assert any("Mobile Application Component" in l for l in obj_labels)
        assert any("Unmonitored Adversary Attack Path" in l for l in obj_labels)

        # Verify Mermaid diagram compiles cleanly without syntax errors
        mermaid_str = graph.to_mermaid()
        assert "flowchart" in mermaid_str
        assert "Unmonitored Adversary" in mermaid_str
        assert "obj_unmonitored_adversary_path" in graph.nodes
