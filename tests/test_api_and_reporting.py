"""
Integration tests for REVENANT Control Plane REST API and Multi-Format Reporting Engine.
Verifies Layer 1 Scope Enforcement, campaign lifecycle, and Markdown, HTML, SARIF generation.
"""

import pytest
from fastapi.testclient import TestClient

from control_plane.api.main import app, campaigns_db
from control_plane.schemas.models import EndpointInfo, Finding, HostAsset, PortInfo, Severity
from reporting.generator import ReportGenerator

client = TestClient(app)


class TestControlPlaneAPI:
    """Test suite for FastAPI control plane endpoints."""

    def test_health_check(self):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["platform"] == "REVENANT"

    def test_layer1_scope_intake_refuses_out_of_scope(self):
        """Layer 1 Gate must reject out-of-scope targets with HTTP 400."""
        payload = {
            "target": "https://unauthorized-victim.org",
            "scope": {
                "name": "lab-scope",
                "allowed_domains": ["sanctioned.local"],
            },
        }
        response = client.post("/api/v1/campaigns", json=payload)
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert data["detail"]["error"] == "SCOPE_VIOLATION"
        assert "unauthorized-victim.org" in data["detail"]["target"]

    def test_in_scope_campaign_and_query_endpoints(self):
        """In-scope target starts campaign, completes, and populates endpoints."""
        payload = {
            "target": "http://127.0.0.1:3000",
            "scope": {
                "allowed_hosts": ["localhost", "127.0.0.1"],
            },
            "max_iterations": 5,
        }
        response = client.post("/api/v1/campaigns", json=payload)
        assert response.status_code == 201
        data = response.json()
        campaign_id = data["campaign_id"]
        assert data["status"] == "COMPLETED"

        # Query Campaign
        get_res = client.get(f"/api/v1/campaigns/{campaign_id}")
        assert get_res.status_code == 200
        assert get_res.json()["campaign_id"] == campaign_id

        # Query Findings
        findings_res = client.get(f"/api/v1/campaigns/{campaign_id}/findings")
        assert findings_res.status_code == 200
        assert isinstance(findings_res.json(), list)

        # Query Assets
        assets_res = client.get(f"/api/v1/campaigns/{campaign_id}/assets")
        assert assets_res.status_code == 200
        assert isinstance(assets_res.json(), list)

        # 404 on missing campaign
        assert client.get("/api/v1/campaigns/non-existent-uuid").status_code == 404

    def test_report_endpoint_formats(self):
        """Verify report endpoint generates markdown, html, sarif, and json."""
        # Seed dummy campaign
        cid = "test-report-cid"
        campaigns_db[cid] = {
            "campaign_id": cid,
            "target": "http://localhost:3000",
            "status": "COMPLETED",
            "created_at": "2026-09-17T12:00:00Z",
            "summary": {},
            "blackboard": type("DummyBB", (), {
                "get_assets": lambda self: [
                    HostAsset(hostname="localhost", ip="127.0.0.1", ports=[PortInfo(port=3000)])
                ],
                "get_findings": lambda self: [
                    Finding(
                        title="SQL Injection in Login Form",
                        description="Vulnerable to time-based blind SQLi",
                        severity=Severity.HIGH,
                        target="http://localhost:3000/rest/user/login",
                        tool="nuclei",
                        cve="CVE-2024-SQLI",
                        reproduction_steps="curl -X POST http://localhost:3000/rest/user/login",
                    )
                ],
            })(),
        }

        # Test Markdown
        res_md = client.get(f"/api/v1/campaigns/{cid}/report?format=markdown")
        assert res_md.status_code == 200
        assert "text/plain" in res_md.headers["content-type"]
        assert "# REVENANT Security Assessment Report" in res_md.text
        assert "SQL Injection in Login Form" in res_md.text

        # Test HTML
        res_html = client.get(f"/api/v1/campaigns/{cid}/report?format=html")
        assert res_html.status_code == 200
        assert "text/html" in res_html.headers["content-type"]
        assert "<!DOCTYPE html>" in res_html.text
        assert "REVENANT Security Assessment" in res_html.text

        # Test SARIF
        res_sarif = client.get(f"/api/v1/campaigns/{cid}/report?format=sarif")
        assert res_sarif.status_code == 200
        assert "application/json" in res_sarif.headers["content-type"]
        sarif_json = res_sarif.json()
        assert sarif_json["version"] == "2.1.0"
        assert len(sarif_json["runs"][0]["results"]) == 1

        # Test JSON
        res_json = client.get(f"/api/v1/campaigns/{cid}/report?format=json")
        assert res_json.status_code == 200
        raw_json = res_json.json()
        assert raw_json["campaign_id"] == cid
        assert len(raw_json["findings"]) == 1


class TestReportGenerator:
    """Unit tests for the multi-format ReportGenerator."""

    def test_sarif_v210_structure(self):
        assets = [HostAsset(ip="127.0.0.1", hostname="lab.local")]
        findings = [
            Finding(
                title="Remote Code Execution",
                description="Unauthenticated RCE vulnerability",
                severity=Severity.CRITICAL,
                target="http://lab.local",
                tool="nuclei",
                cve="CVE-2023-12345",
                cvss_score=9.8,
                endpoint="http://lab.local/api/upload",
            ),
            Finding(
                title="Sensitive Config Exposed",
                description="Configuration file is publicly accessible",
                severity=Severity.MEDIUM,
                target="http://lab.local",
                tool="ffuf",
                cwe="CWE-200",
                endpoint="http://lab.local/.env",
            ),
        ]

        generator = ReportGenerator(
            campaign_id="camp-123",
            target="http://lab.local",
            assets=assets,
            findings=findings,
        )

        sarif = generator.generate_sarif()
        assert sarif["version"] == "2.1.0"
        assert "sarif-schema-2.1.0.json" in sarif["$schema"]

        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "REVENANT"
        assert len(run["results"]) == 2

        # Check CRITICAL maps to 'error' level in SARIF
        crit_result = next(r for r in run["results"] if r["ruleId"] == "CVE-2023-12345")
        assert crit_result["level"] == "error"

        # Check MEDIUM maps to 'warning' level in SARIF
        med_result = next(r for r in run["results"] if r["ruleId"] == "CWE-200")
        assert med_result["level"] == "warning"

        # Explicitly validate against the official OASIS SARIF v2.1.0 schema
        import json
        import jsonschema
        from pathlib import Path
        schema_path = Path(__file__).resolve().parent.parent / "reporting" / "sarif-schema-2.1.0.json"
        if schema_path.exists():
            with open(schema_path, "r", encoding="utf-8") as f:
                oasis_schema = json.load(f)
            jsonschema.validate(instance=sarif, schema=oasis_schema)

    def test_markdown_executive_summary_counts(self):
        findings = [
            Finding(
                title="F1", description="desc", severity=Severity.HIGH,
                target="http://t.local", tool="nmap"
            ),
            Finding(
                title="F2", description="desc", severity=Severity.LOW,
                target="http://t.local", tool="httpx"
            ),
        ]
        gen = ReportGenerator("cid", "http://t.local", [], findings)
        md = gen.generate_markdown()
        assert "| 🟠 HIGH | 1 |" in md
        assert "| 🔵 LOW | 1 |" in md
        assert "| 🔴 CRITICAL | 0 |" in md
