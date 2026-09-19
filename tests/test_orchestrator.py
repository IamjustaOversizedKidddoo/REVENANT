"""
Integration and unit tests for REVENANT Multi-Agent Orchestrator & Blackboard.
Verifies stigmergic agent cascade (Target -> Recon -> Web -> Triage) and Layer 2 scope enforcement.
"""

from unittest.mock import MagicMock
import pytest

from adapters.base import AdapterResult
from adapters.recon.httpx_adapter import HTTPXAdapter
from adapters.web.nuclei_adapter import NucleiAdapter
from control_plane.schemas.models import EndpointInfo, Finding, HostAsset, PortInfo, Severity
from control_plane.schemas.scope import ScopeManifest, ScopeViolationError
from orchestrator.agents.recon_agent import ReconAgent
from orchestrator.agents.triage_agent import TriageAgent
from orchestrator.agents.web_agent import WebAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType
from orchestrator.engine import Orchestrator


class TestBlackboard:
    """Test suite for Blackboard state management."""

    def test_event_lifecycle_and_agent_cursors(self):
        bb = Blackboard()
        event = BlackboardEvent(
            event_type=EventType.TARGET_REGISTERED,
            source_agent="user",
            target="http://localhost:3000",
        )
        bb.post_event(event)

        assert len(bb.get_events()) == 1
        assert len(bb.get_unhandled_events("recon-agent")) == 1

        bb.mark_handled(event.id, "recon-agent")
        assert len(bb.get_unhandled_events("recon-agent")) == 0
        # Another agent still sees it as unhandled
        assert len(bb.get_unhandled_events("web-agent")) == 1

    def test_asset_merging(self):
        bb = Blackboard()
        asset1 = HostAsset(
            ip="127.0.0.1",
            hostname="localhost",
            ports=[PortInfo(port=80, protocol="tcp", state="open")],
            endpoints=[EndpointInfo(url="http://localhost:80/")]
        )
        asset2 = HostAsset(
            ip="127.0.0.1",
            hostname="localhost",
            ports=[PortInfo(port=443, protocol="tcp", state="open")],
            endpoints=[EndpointInfo(url="https://localhost:443/api")]
        )

        bb.add_asset(asset1)
        bb.add_asset(asset2)

        assets = bb.get_assets()
        assert len(assets) == 1
        merged = assets[0]
        assert len(merged.ports) == 2
        assert {p.port for p in merged.ports} == {80, 443}
        assert len(merged.endpoints) == 2

    def test_sqlite_persistence_across_instances(self, tmp_path):
        db_file = str(tmp_path / "blackboard.db")
        campaign_id = "test-camp-persist"
        bb1 = Blackboard(campaign_id=campaign_id, db_path=db_file)

        event = BlackboardEvent(
            event_type=EventType.TARGET_REGISTERED,
            source_agent="orchestrator",
            target="http://localhost:3000",
        )
        bb1.post_event(event)
        bb1.mark_handled(event.id, "recon-agent")

        asset = HostAsset(
            ip="127.0.0.1",
            hostname="localhost",
            ports=[PortInfo(port=3000, protocol="tcp", state="open")],
        )
        bb1.add_asset(asset)

        finding = Finding(
            title="Exposed Credentials",
            description="Found credentials in .env",
            severity=Severity.HIGH,
            target="http://localhost:3000",
            tool="ffuf",
        )
        bb1.add_finding(finding)

        # Instance 2 loads from same db_path
        bb2 = Blackboard(campaign_id=campaign_id, db_path=db_file)
        assert len(bb2.get_events()) == 1
        assert "recon-agent" in bb2.get_events()[0].handled_by
        assert len(bb2.get_assets()) == 1
        assert len(bb2.get_findings()) == 1
        assert bb2.get_findings()[0].title == "Exposed Credentials"


class TestStigmergicSwarmCascade:
    """Tests the multi-agent reactive loop from Target Seed to Confirmed Finding."""

    def test_full_stigmergic_orchestration_loop(self):
        # 1. Setup mock HTTPX Adapter
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
                    ports=[PortInfo(port=3000, protocol="tcp", state="open")],
                    endpoints=[
                        EndpointInfo(url="http://localhost:3000/api/users", title="Juice Shop API")
                    ],
                )
            ],
            findings=[],
        )

        # 2. Setup mock Nuclei Adapter
        mock_nuclei = MagicMock(spec=NucleiAdapter)
        mock_nuclei.name = "nuclei"
        mock_nuclei.run.return_value = AdapterResult(
            tool_name="nuclei",
            target="http://localhost:3000/api/users",
            exit_code=0,
            findings=[
                Finding(
                    title="BOLA Broken Object Level Authorization",
                    description="User records accessible without authorization",
                    severity=Severity.HIGH,
                    target="http://localhost:3000/api/users",
                    tool="nuclei",
                    cve="CVE-2024-TEST",
                    endpoint="http://localhost:3000/api/users",
                    reproduction_steps="curl http://localhost:3000/api/users/2",
                    evidence="HTTP/1.1 200 OK with sensitive records",
                )
            ],
        )

        # 3. Assemble the Swarm
        recon_agent = ReconAgent(httpx_adapter=mock_httpx)
        web_agent = WebAgent(nuclei_adapter=mock_nuclei)
        triage_agent = TriageAgent()

        blackboard = Blackboard()
        orchestrator = Orchestrator(
            blackboard=blackboard,
            agents=[recon_agent, web_agent, triage_agent],
        )

        scope = ScopeManifest(allowed_hosts=["localhost", "127.0.0.1"])

        # 4. Run Campaign
        summary = orchestrator.start_campaign("http://localhost:3000", scope)

        # 5. Verify the Stigmergic Cascade
        # Event 1: TARGET_REGISTERED (Seed)
        # Event 2: ReconAgent -> HOST_DISCOVERED, HTTP_ENDPOINT
        # Event 3: WebAgent reacts to HTTP_ENDPOINT -> VULNERABILITY_CANDIDATE
        # Event 4: TriageAgent reacts to VULNERABILITY_CANDIDATE -> VULNERABILITY_CONFIRMED
        # Event 5: CAMPAIGN_COMPLETE

        assert summary["total_assets"] == 1
        assert summary["total_findings"] == 1
        assert summary["findings_by_severity"]["HIGH"] == 1

        confirmed_findings = blackboard.get_findings()
        assert len(confirmed_findings) == 1
        assert confirmed_findings[0].title == "BOLA Broken Object Level Authorization"
        assert confirmed_findings[0].verified is True
        assert confirmed_findings[0].severity == Severity.HIGH

        events = blackboard.get_events()
        event_types = [e.event_type for e in events]
        assert EventType.TARGET_REGISTERED in event_types
        assert EventType.HTTP_ENDPOINT in event_types
        assert EventType.VULNERABILITY_CANDIDATE in event_types
        assert EventType.VULNERABILITY_CONFIRMED in event_types
        assert EventType.CAMPAIGN_COMPLETE in event_types

    def test_orchestrator_refuses_out_of_scope_target(self):
        """Orchestrator must refuse to start a campaign for an out-of-scope target."""
        orchestrator = Orchestrator()
        scope = ScopeManifest(allowed_domains=["target.corp"])

        with pytest.raises(ScopeViolationError) as exc_info:
            orchestrator.start_campaign("http://unauthorized.evil.com", scope)

        assert "SCOPE VIOLATION" in str(exc_info.value)
        assert len(orchestrator.blackboard.get_events()) == 0
