"""
REVENANT — Milestone 3.3: Mobile Application Security Test Suite
Unit, integration, and live-binary tests for MobsfscanAdapter, MobSFAdapter,
MobileAgent, and Attack Graph / MITRE correlation.
"""

import json
import os
from pathlib import Path
import pytest

from adapters.mobile.mobsf_adapter import MobSFAdapter
from adapters.mobile.mobsfscan_adapter import MobsfscanAdapter
from control_plane.schemas.models import Finding, HostAsset, Severity
from control_plane.schemas.scope import ScopeManifest, ScopeViolationError
from orchestrator.agents.mobile_agent import MobileAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType
from orchestrator.correlation.attack_graph_engine import AttackGraphEngine
from reporting.mitre_mapper import MitreMapper

MOBILE_FIXTURE_DIR = str(Path("tests/fixtures/mobile_app").resolve())


@pytest.fixture
def mobile_scope() -> ScopeManifest:
    return ScopeManifest(allowed_repos=[MOBILE_FIXTURE_DIR], allowed_hosts=["127.0.0.1", "localhost"])


class TestMobsfscanAdapter:
    """Verifies MobsfscanAdapter scope enforcement, command synthesis, parsing, and live execution."""

    def test_scope_enforcement_refuses_unauthorized_target(self):
        adapter = MobsfscanAdapter()
        manifest = ScopeManifest(allowed_repos=["D:/AuthorizedProject"])

        with pytest.raises(ScopeViolationError):
            adapter.run("D:/UnauthorizedMobileApp", manifest)

    def test_build_command(self):
        adapter = MobsfscanAdapter(binary_override="mobsfscan", use_wsl=True)
        cmd = adapter.build_command("D:/REVENANT/app", {"output_file": "/tmp/out.json"})

        assert "mobsfscan" in cmd[0]
        assert "/mnt/d/REVENANT/app" in cmd
        assert "--json" in cmd
        assert "-o" in cmd
        assert "/tmp/out.json" in cmd

    def test_parse_output_json(self):
        adapter = MobsfscanAdapter()
        mock_output = json.dumps({
            "results": {
                "android_insecure_broadcast": {
                    "files": [
                        {
                            "file_path": "app/src/main/AndroidManifest.xml",
                            "match_lines": [12, 14],
                            "match_string": "<receiver android:name='.InsecureReceiver' android:exported='true' />"
                        }
                    ],
                    "metadata": {
                        "cwe": "CWE-926: Improper Export of Android Application Components",
                        "description": "Broadcast receiver is exported without permission.",
                        "masvs": "MASVS-PLATFORM-1",
                        "severity": "WARNING",
                        "reference": "https://mas.owasp.org"
                    }
                }
            }
        })

        findings, assets = adapter.parse_output(mock_output, "", "D:/REVENANT/app")
        assert len(findings) == 1
        f = findings[0]
        assert f.cwe == "CWE-926"
        assert f.severity == Severity.MEDIUM
        assert f.owasp_category == "MASVS-PLATFORM-1"
        assert f.code_location is not None
        assert f.code_location.start_line == 12
        assert "InsecureReceiver" in f.code_location.snippet

    def test_heuristic_scanner_detects_flaws(self):
        adapter = MobsfscanAdapter()
        findings = adapter.analyze_heuristics(MOBILE_FIXTURE_DIR)

        assert len(findings) >= 5
        cwes = {f.cwe for f in findings}
        assert "CWE-926" in cwes  # Exported components
        assert "CWE-319" in cwes  # Cleartext traffic
        assert "CWE-798" in cwes  # Hardcoded secret key
        assert "CWE-79" in cwes   # Insecure WebView JS

        secret_finding = next(f for f in findings if f.cwe == "CWE-798")
        assert secret_finding.severity == Severity.CRITICAL
        assert "REV-MOB-SECRET-KEY" in (secret_finding.code_location.snippet if secret_finding.code_location else "")

    def test_live_scan_against_mobile_fixture(self, mobile_scope: ScopeManifest):
        adapter = MobsfscanAdapter()
        if not adapter.is_installed():
            pytest.skip("mobsfscan binary not available in test environment")

        result = adapter.run(MOBILE_FIXTURE_DIR, mobile_scope)
        assert result.exit_code == 0
        assert len(result.findings) >= 6

        # Verify findings include both mobsfscan platform rules and heuristic detections
        rule_titles = [f.title for f in result.findings]
        assert any("certificate" in t.lower() or "tapjacking" in t.lower() or "cleartext" in t.lower() for t in rule_titles)


class TestMobSFAdapter:
    """Verifies MobSFAdapter API client, report parsing, and fallback logic."""

    def test_scope_enforcement(self):
        adapter = MobSFAdapter()
        manifest = ScopeManifest(allowed_repos=["D:/Authorized"])

        with pytest.raises(ScopeViolationError):
            adapter.run("D:/UnauthorizedApp", manifest)

    def test_build_command(self):
        adapter = MobSFAdapter(server_url="http://127.0.0.1:8000")
        cmd = adapter.build_command("app.apk")
        assert "mobsf_api" in cmd
        assert "--target" in cmd
        assert "app.apk" in cmd

    def test_parse_mobsf_json_report(self):
        adapter = MobSFAdapter()
        mock_report = json.dumps({
            "manifest_analysis": [
                {
                    "title": "Exported Activity Vulnerability",
                    "stat": "high",
                    "desc": "Activity is exported without intent filter permissions."
                }
            ],
            "code_analysis": {
                "hardcoded_credentials": {
                    "metadata": {
                        "severity": "high",
                        "description": "Found hardcoded AWS key in code.",
                        "cwe": "CWE-798"
                    },
                    "files": {"MainActivity.java": "15"}
                }
            }
        })

        findings, assets = adapter.parse_output(mock_report, "", "app.apk")
        assert len(findings) == 2
        manifest_f = next(f for f in findings if "Exported" in f.title)
        assert manifest_f.severity == Severity.HIGH
        assert manifest_f.cwe == "CWE-926"

        code_f = next(f for f in findings if "credentials" in f.title)
        assert code_f.severity == Severity.HIGH
        assert code_f.cwe == "CWE-798"

    def test_fallback_when_server_offline(self, mobile_scope: ScopeManifest):
        # Point to unreachable port to test fallback delegation
        adapter = MobSFAdapter(server_url="http://127.0.0.1:59999", api_key="dummy_key")
        result = adapter.run(MOBILE_FIXTURE_DIR, mobile_scope)
        # Should gracefully fall back to MobsfscanAdapter and succeed
        assert result.exit_code == 0
        assert len(result.findings) >= 5


class TestMobileAgentSwarm:
    """Verifies MobileAgent triggering predicates, blackboard event publishing, and correlation."""

    def test_agent_predicates(self):
        agent = MobileAgent()

        # Direct mobile event
        ev_mob = BlackboardEvent(
            event_type=EventType.MOBILE_APP_DISCOVERED,
            source_agent="recon",
            target="app-release.apk",
        )
        assert agent.can_handle(ev_mob) is True

        # Target registered with mobile extension
        ev_apk = BlackboardEvent(
            event_type=EventType.TARGET_REGISTERED,
            source_agent="orchestrator",
            target="com.example.app.apk",
        )
        assert agent.can_handle(ev_apk) is True

        # Target directory containing AndroidManifest.xml
        ev_dir = BlackboardEvent(
            event_type=EventType.TARGET_REGISTERED,
            source_agent="orchestrator",
            target=MOBILE_FIXTURE_DIR,
        )
        assert agent.can_handle(ev_dir) is True

        # Non-mobile event
        ev_other = BlackboardEvent(
            event_type=EventType.PORT_OPEN,
            source_agent="nmap",
            target="192.168.1.1",
            payload={"port": 80},
        )
        assert agent.can_handle(ev_other) is False

    def test_agent_handle_dispatches_events(self, mobile_scope: ScopeManifest):
        blackboard = Blackboard()
        agent = MobileAgent()

        ev = BlackboardEvent(
            event_type=EventType.MOBILE_APP_DISCOVERED,
            source_agent="recon",
            target=MOBILE_FIXTURE_DIR,
        )

        out_events = agent.handle(ev, blackboard, mobile_scope)
        assert len(out_events) > 0
        assert len(blackboard.get_findings()) >= 5

        # Check emitted event types
        event_types = {e.event_type for e in out_events}
        assert EventType.MOBILE_VULNERABILITY_CONFIRMED in event_types
        assert EventType.VULNERABILITY_CONFIRMED in event_types

    def test_attack_graph_and_mitre_correlation(self, mobile_scope: ScopeManifest):
        blackboard = Blackboard()
        agent = MobileAgent()

        ev = BlackboardEvent(
            event_type=EventType.MOBILE_APP_DISCOVERED,
            source_agent="recon",
            target=MOBILE_FIXTURE_DIR,
        )
        agent.handle(ev, blackboard, mobile_scope)

        # 1. Attack Graph Engine Synthesis
        engine = AttackGraphEngine()
        graph = engine.build_graph(blackboard.get_assets(), blackboard.get_findings())

        assert len(graph.nodes) > 5
        assert len(graph.edges) > 5
        # Verify Chain G created mobile objective node
        assert "obj_mobile_ipc_takeover" in graph.nodes
        assert graph.nodes["obj_mobile_ipc_takeover"].label == "Mobile Application Component Hijack & Data Theft"

        # 2. MITRE ATT&CK Mapper Verification
        mapper = MitreMapper()
        summary = mapper.generate_matrix_summary(blackboard.get_findings())
        assert summary["total_tactics_hit"] > 0
        assert len(summary["tactics"]) > 0
