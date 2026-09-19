"""
REVENANT — Milestone 2.2 Deep Web Crawling & DAST Test Suite.
Verifies KatanaAdapter, DastAdapter, CrawlAgent, DastAgent,
and end-to-end swarm crawling, form parsing, parameter fuzzing, and triage.
"""

import json
import pytest

from adapters.web.dast_adapter import DastAdapter
from adapters.web.katana_adapter import KatanaAdapter
from control_plane.schemas.models import EndpointInfo, Severity
from control_plane.schemas.scope import ScopeManifest, ScopeViolationError
from orchestrator.agents.crawl_agent import CrawlAgent
from orchestrator.agents.dast_agent import DastAgent
from orchestrator.agents.triage_agent import TriageAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType
from orchestrator.engine import Orchestrator
from reporting.generator import ReportGenerator

LAB_URL = "http://127.0.0.1:3000"


@pytest.fixture
def lab_scope() -> ScopeManifest:
    """Scope manifest permitting local lab server."""
    return ScopeManifest(
        allowed_hosts=["127.0.0.1", "localhost"],
        allowed_domains=["localhost"],
        allowed_cidrs=["127.0.0.1/32"],
    )


class TestKatanaAdapter:
    """Verifies Katana CLI command synthesis, JSON-lines parsing, and native recursive crawler."""

    def test_build_command(self):
        adapter = KatanaAdapter(binary_override="katana.exe")
        cmd = adapter.build_command("http://sanctioned.local", {"depth": 4, "timeout": 15})

        assert "katana.exe" in cmd[0]
        assert "-u" in cmd
        assert "http://sanctioned.local" in cmd
        assert "-jc" in cmd
        assert "-d" in cmd
        assert "4" in cmd
        assert "-aff" in cmd

    def test_parse_output_katana_json(self):
        adapter = KatanaAdapter()
        mock_output = "\n".join([
            json.dumps({
                "request": {"endpoint": "http://sanctioned.local/search?q=test", "method": "GET"},
                "response": {"status_code": 200, "headers": {"content_type": "text/html"}}
            }),
            json.dumps({
                "request": {"endpoint": "http://sanctioned.local/api/users", "method": "POST"},
                "response": {"status_code": 201, "headers": {"content_type": "application/json"}}
            })
        ])

        findings, assets = adapter.parse_output(mock_output, "", "http://sanctioned.local")
        assert len(assets) == 1
        asset = assets[0]
        assert len(asset.endpoints) == 2

        search_ep = next(ep for ep in asset.endpoints if "/search" in ep.url)
        assert search_ep.method == "GET"
        assert search_ep.parameters == ["q"]
        assert search_ep.status_code == 200

        api_ep = next(ep for ep in asset.endpoints if "/api/users" in ep.url)
        assert api_ep.method == "POST"

    def test_builtin_crawler_on_lab_server(self, lab_scope: ScopeManifest):
        adapter = KatanaAdapter()
        res = adapter.run(LAB_URL, lab_scope, params={"depth": 2, "max_pages": 15})

        assert res.exit_code == 0
        assert len(res.discovered_assets) == 1
        asset = res.discovered_assets[0]

        urls = [ep.url for ep in asset.endpoints]
        assert any("/search" in u for u in urls)
        assert any("/redirect" in u for u in urls)
        assert any("/view" in u for u in urls)

        # Confirm form parsing extracted inputs
        forms_found = [ep.forms for ep in asset.endpoints if ep.forms]
        assert len(forms_found) >= 1
        flat_forms = [f for sublist in forms_found for f in sublist]
        input_names = [inp["name"] for f in flat_forms for inp in f.get("inputs", [])]
        assert "query" in input_names or "username" in input_names

    def test_scope_enforcement_refuses_out_of_scope(self):
        adapter = KatanaAdapter()
        strict_scope = ScopeManifest(allowed_hosts=["192.168.1.50"])

        with pytest.raises(ScopeViolationError) as exc_info:
            adapter.run("http://unauthorized.target.com", strict_scope)

        assert "SCOPE VIOLATION" in str(exc_info.value)


class TestDastAdapter:
    """Verifies DAST active vulnerability injection fuzzer."""

    def test_dast_reflected_xss(self, lab_scope: ScopeManifest):
        adapter = DastAdapter()
        ep = EndpointInfo(url=f"{LAB_URL}/search", method="GET", parameters=["query"])

        res = adapter.run(LAB_URL, lab_scope, params={"endpoints": [ep]})
        assert res.exit_code == 0
        assert len(res.findings) >= 1

        xss_finding = next((f for f in res.findings if f.cwe == "CWE-79"), None)
        assert xss_finding is not None
        assert xss_finding.severity == Severity.HIGH
        assert "query" in xss_finding.title
        assert xss_finding.verified is True
        assert xss_finding.request_proof is not None
        assert "GET" in xss_finding.request_proof
        assert xss_finding.response_proof is not None

    def test_dast_open_redirect(self, lab_scope: ScopeManifest):
        adapter = DastAdapter()
        ep = EndpointInfo(url=f"{LAB_URL}/redirect", method="GET", parameters=["next"])

        res = adapter.run(LAB_URL, lab_scope, params={"endpoints": [ep]})
        assert res.exit_code == 0
        assert len(res.findings) >= 1

        redirect_finding = next((f for f in res.findings if f.cwe == "CWE-601"), None)
        assert redirect_finding is not None
        assert redirect_finding.severity == Severity.MEDIUM
        assert "Location:" in redirect_finding.evidence
        assert redirect_finding.verified is True

    def test_dast_path_traversal(self, lab_scope: ScopeManifest):
        adapter = DastAdapter()
        ep = EndpointInfo(url=f"{LAB_URL}/view", method="GET", parameters=["file"])

        res = adapter.run(LAB_URL, lab_scope, params={"endpoints": [ep]})
        assert res.exit_code == 0
        assert len(res.findings) >= 1

        traversal_finding = next((f for f in res.findings if f.cwe == "CWE-22"), None)
        assert traversal_finding is not None
        assert traversal_finding.severity == Severity.CRITICAL
        assert traversal_finding.verified is True

    def test_dast_scope_refusal(self):
        adapter = DastAdapter()
        strict_scope = ScopeManifest(allowed_hosts=["10.0.0.1"])

        with pytest.raises(ScopeViolationError) as exc_info:
            adapter.run("http://forbidden-host.corp", strict_scope)

        assert "SCOPE VIOLATION" in str(exc_info.value)


class TestCrawlAndDastAgents:
    """Verifies specialist agents event subscription and coordination."""

    def test_crawl_agent_predicates_and_dispatch(self, lab_scope: ScopeManifest):
        agent = CrawlAgent()
        bb = Blackboard()

        # Check predicate
        web_event = BlackboardEvent(
            event_type=EventType.TARGET_REGISTERED,
            source_agent="orchestrator",
            target=LAB_URL,
            payload={"target_type": "URL"},
        )
        assert agent.can_handle(web_event) is True

        # Non-web target should not be handled by crawl agent
        repo_event = BlackboardEvent(
            event_type=EventType.TARGET_REGISTERED,
            source_agent="orchestrator",
            target="D:/local_repo",
            payload={"target_type": "REPO"},
        )
        assert agent.can_handle(repo_event) is False

        # Execute handle
        events = agent.handle(web_event, bb, lab_scope)
        assert len(events) >= 1
        event_types = {e.event_type for e in events}
        assert EventType.CRAWL_COMPLETED in event_types or EventType.PARAMETER_DISCOVERED in event_types

    def test_dast_agent_predicates_and_dispatch(self, lab_scope: ScopeManifest):
        agent = DastAgent()
        bb = Blackboard()

        ep_payload = {
            "url": f"{LAB_URL}/search",
            "method": "GET",
            "parameters": ["query"],
        }
        param_event = BlackboardEvent(
            event_type=EventType.PARAMETER_DISCOVERED,
            source_agent="crawl-agent",
            target=f"{LAB_URL}/search",
            payload={"endpoint": ep_payload},
        )
        assert agent.can_handle(param_event) is True

        new_events = agent.handle(param_event, bb, lab_scope)
        assert len(new_events) >= 1
        assert any(e.event_type == EventType.DAST_CANDIDATE for e in new_events)


class TestEndToEndDastCascade:
    """Verifies complete Stigmergic cascade: CrawlAgent -> DastAgent -> TriageAgent."""

    def test_full_crawl_and_dast_campaign(self, lab_scope: ScopeManifest):
        bb = Blackboard()
        crawl_agent = CrawlAgent()
        dast_agent = DastAgent()
        triage_agent = TriageAgent()

        swarm = Orchestrator(
            blackboard=bb,
            agents=[crawl_agent, dast_agent, triage_agent],
        )

        summary = swarm.start_campaign(LAB_URL, lab_scope, max_iterations=6)
        findings = bb.get_findings()

        assert len(findings) >= 2
        cwes = {f.cwe for f in findings}
        # Reflected XSS and/or Open Redirect and/or Path Traversal must be triaged
        assert "CWE-79" in cwes or "CWE-601" in cwes or "CWE-22" in cwes

        # Generate report and confirm proofs are included
        generator = ReportGenerator(
            campaign_id="test-dast-campaign",
            target=LAB_URL,
            assets=bb.get_assets(),
            findings=findings,
        )
        md_report = generator.generate_markdown()
        assert "Executive Summary" in md_report

        sarif_data = generator.generate_sarif()
        assert isinstance(sarif_data, dict)
        assert len(sarif_data["runs"][0]["results"]) >= 2
