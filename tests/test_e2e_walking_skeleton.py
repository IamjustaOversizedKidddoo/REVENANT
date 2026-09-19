"""
End-to-End Walking Skeleton Benchmark & Verification Tests.
Proves the full 5-step autonomous red teaming lifecycle from intake through
discovery, scanning, triage, and multi-format report generation, with airtight 3-layer scope gates.
"""

import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from adapters.base import AdapterResult
from adapters.recon.httpx_adapter import HTTPXAdapter
from adapters.web.nuclei_adapter import NucleiAdapter
from control_plane.cli import run_mission
from control_plane.schemas.models import EndpointInfo, Finding, HostAsset, PortInfo, Severity
from control_plane.schemas.scope import ScopeManifest, ScopeViolationError
from orchestrator.agents.recon_agent import ReconAgent
from orchestrator.agents.triage_agent import TriageAgent
from orchestrator.agents.web_agent import WebAgent
from orchestrator.blackboard import Blackboard
from orchestrator.engine import Orchestrator
from reporting.generator import ReportGenerator


class TestE2EWalkingSkeleton:
    """Complete system integration tests validating the autonomous red teaming platform."""

    @pytest.fixture
    def temp_output_dir(self):
        temp_dir = tempfile.mkdtemp(prefix="revenant_test_e2e_")
        yield temp_dir
        shutil.rmtree(temp_dir, ignore_errors=True)

    def test_e2e_full_lifecycle_and_report_generation(self, temp_output_dir):
        """
        Simulates an entire autonomous mission against OWASP Juice Shop / crAPI benchmark:
        1. Intake & Scope Validation (Layer 1)
        2. Swarm Execution: Recon -> Web Scan -> Triage
        3. Report Generation: Markdown, HTML, SARIF, JSON
        """
        # 1. Setup mock adapters simulating Juice Shop / crAPI response
        mock_httpx = MagicMock(spec=HTTPXAdapter)
        mock_httpx.name = "httpx"
        mock_httpx.run.return_value = AdapterResult(
            tool_name="httpx",
            target="http://localhost:3000",
            exit_code=0,
            discovered_assets=[
                HostAsset(
                    ip="127.0.0.1",
                    hostname="localhost",
                    ports=[PortInfo(port=3000, service="http", state="open")],
                    endpoints=[
                        EndpointInfo(url="http://localhost:3000/rest/user/login", title="Juice Shop Login"),
                        EndpointInfo(url="http://localhost:3000/api/Feedbacks", title="Feedback API"),
                    ],
                )
            ],
            findings=[
                Finding(
                    title="Express Framework Fingerprinted",
                    description="HTTP probing detected Express web server",
                    severity=Severity.INFO,
                    target="http://localhost:3000",
                    tool="httpx",
                )
            ],
        )

        mock_nuclei = MagicMock(spec=NucleiAdapter)
        mock_nuclei.name = "nuclei"
        mock_nuclei.run.return_value = AdapterResult(
            tool_name="nuclei",
            target="http://localhost:3000/rest/user/login",
            exit_code=0,
            findings=[
                Finding(
                    title="SQL Injection in Login Authentication",
                    description="Authentication bypass possible via SQL injection in email parameter",
                    severity=Severity.CRITICAL,
                    target="http://localhost:3000/rest/user/login",
                    tool="nuclei",
                    cve="CVE-2024-JUICE-SQLI",
                    cwe="CWE-89",
                    cvss_score=9.8,
                    endpoint="http://localhost:3000/rest/user/login",
                    reproduction_steps="curl -X POST http://localhost:3000/rest/user/login -d 'email=' OR 1=1--'",
                    evidence="HTTP/1.1 200 OK - token returned",
                ),
                Finding(
                    title="Reflected Cross-Site Scripting (XSS)",
                    description="Search query parameter reflected without output encoding",
                    severity=Severity.HIGH,
                    target="http://localhost:3000/api/Feedbacks",
                    tool="nuclei",
                    cwe="CWE-79",
                    cvss_score=7.5,
                    endpoint="http://localhost:3000/api/Feedbacks",
                    reproduction_steps="curl 'http://localhost:3000/api/Feedbacks?q=<script>alert(1)</script>'",
                    evidence="<script>alert(1)</script> present in response body",
                ),
            ],
        )

        # 2. Build custom swarm for the benchmark test
        blackboard = Blackboard()
        recon_agent = ReconAgent(httpx_adapter=mock_httpx)
        web_agent = WebAgent(nuclei_adapter=mock_nuclei)
        triage_agent = TriageAgent()

        orchestrator = Orchestrator(
            blackboard=blackboard,
            agents=[recon_agent, web_agent, triage_agent],
        )

        scope = ScopeManifest(allowed_hosts=["localhost", "127.0.0.1"])

        # 3. Execute Autonomous Mission
        summary = orchestrator.start_campaign("http://localhost:3000", scope, max_iterations=10)

        # Assert campaign metrics
        assert summary["total_assets"] == 1
        assert summary["total_findings"] >= 2
        assert summary["findings_by_severity"]["CRITICAL"] == 1
        assert summary["findings_by_severity"]["HIGH"] == 1

        # 4. Generate all 4 report formats to output directory
        generator = ReportGenerator(
            campaign_id=blackboard.campaign_id,
            target="http://localhost:3000",
            assets=blackboard.get_assets(),
            findings=blackboard.get_findings(),
        )

        out_path = Path(temp_output_dir)
        md_file = out_path / "report.md"
        html_file = out_path / "report.html"
        sarif_file = out_path / "report.sarif"
        json_file = out_path / "report.json"

        md_file.write_text(generator.generate_markdown(), encoding="utf-8")
        html_file.write_text(generator.generate_html(), encoding="utf-8")
        sarif_file.write_text(json.dumps(generator.generate_sarif(), indent=2), encoding="utf-8")
        json_file.write_text(json.dumps(generator.generate_json(), indent=2), encoding="utf-8")

        # 5. Verify Artifacts
        assert md_file.exists()
        assert html_file.exists()
        assert sarif_file.exists()
        assert json_file.exists()

        # Check Markdown content
        md_text = md_file.read_text(encoding="utf-8")
        assert "REVENANT Security Assessment Report" in md_text
        assert "CRITICAL" in md_text
        assert "SQL Injection in Login Authentication" in md_text

        # Check HTML content
        html_text = html_file.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html_text
        assert "badge badge-CRITICAL" in html_text

        # Check SARIF schema compliance
        sarif_data = json.loads(sarif_file.read_text(encoding="utf-8"))
        assert sarif_data["version"] == "2.1.0"
        results = sarif_data["runs"][0]["results"]
        assert len(results) >= 2
        assert any(r["level"] == "error" for r in results)

        # Check JSON dump
        json_data = json.loads(json_file.read_text(encoding="utf-8"))
        assert json_data["target"] == "http://localhost:3000"
        assert len(json_data["findings"]) >= 2

    def test_e2e_cli_refuses_out_of_scope_target(self, temp_output_dir):
        """CLI runner must reject out-of-scope targets and produce no report files."""
        scope = ScopeManifest(allowed_domains=["authorized-only.com"])
        exit_code = run_mission(
            target="http://unauthorized-victim.org",
            scope=scope,
            output_dir=temp_output_dir,
            verbose=False,
        )

        assert exit_code == 1
        # No files should have been written to output_dir
        assert len(list(Path(temp_output_dir).iterdir())) == 0

    def test_e2e_empty_scope_refusal(self, temp_output_dir):
        """CLI runner must reject execution if scope is completely empty."""
        empty_scope = ScopeManifest(
            allowed_hosts=[],
            allowed_domains=[],
            allowed_cidrs=[],
            require_explicit_scope=True,
        )
        exit_code = run_mission(
            target="http://localhost:3000",
            scope=empty_scope,
            output_dir=temp_output_dir,
            verbose=False,
        )

        assert exit_code == 1
        assert len(list(Path(temp_output_dir).iterdir())) == 0
