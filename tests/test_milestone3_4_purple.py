"""
REVENANT — Milestone 3.4 Purple Teaming & Adversary Emulation Test Suite
Validates AtomicRedTeamAdapter (safety sandbox, atomic catalog, live execution),
DetectionGapEngine (Sigma rules, telemetry evaluation, visibility scores),
CalderaAdapter (API operation & fallback), and autonomous PurpleAgent swarm integration.
"""

from __future__ import annotations

import json
import pytest

from adapters.purple.atomic_adapter import (
    ATOMIC_TESTS_CATALOG,
    AtomicRedTeamAdapter,
    AtomicTest,
    SafetyViolationError,
)
from adapters.purple.caldera_adapter import CalderaAdapter
from adapters.purple.detection_engine import (
    DEFAULT_SIGMA_CATALOG,
    DetectionCoverageReport,
    DetectionGapEngine,
    DetectionRule,
)
from control_plane.schemas.models import Finding, HostAsset, Severity
from control_plane.schemas.scope import ScopeManifest, ScopeViolationError
from orchestrator.agents.purple_agent import PurpleAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType
from orchestrator.correlation.attack_graph_engine import AttackGraphEngine
from reporting.mitre_mapper import MitreMapper


@pytest.fixture
def purple_scope() -> ScopeManifest:
    return ScopeManifest(
        allowed_hosts=["127.0.0.1", "localhost"],
        allowed_cidrs=["127.0.0.1/32"],
    )


class TestAtomicRedTeamAdapter:
    """Verifies AtomicRedTeamAdapter safety controls, scope checks, and live execution."""

    def test_scope_enforcement_refuses_unauthorized_target(self, purple_scope: ScopeManifest):
        adapter = AtomicRedTeamAdapter()
        with pytest.raises(ScopeViolationError):
            adapter.run("192.168.100.50", purple_scope)

    def test_safety_sandbox_blocks_destructive_commands(self):
        adapter = AtomicRedTeamAdapter()

        # Commands that must trigger SafetyViolationError
        prohibited = [
            "rm -rf /",
            "rm -r /var/log",
            "del /s /q C:\\Windows",
            "format D: /fs:NTFS",
            "mkfs.ext4 /dev/sda1",
            "shutdown /s /t 0",
            ":(){ :|:& };:",
            "drop database production;",
        ]

        for cmd in prohibited:
            with pytest.raises(SafetyViolationError):
                adapter.validate_safety(cmd)

    def test_safety_sandbox_allows_benign_atomic_commands(self):
        adapter = AtomicRedTeamAdapter()

        # Benign commands that must pass safety validation
        benign = [
            "whoami /all",
            "systeminfo",
            "net user",
            "ipconfig /all",
            "Get-Process | Select-Object -First 10 Id, ProcessName",
            "uname -a",
            "cat /etc/os-release",
            "id; whoami",
        ]

        for cmd in benign:
            # Should not raise
            adapter.validate_safety(cmd)

    def test_build_command(self):
        adapter = AtomicRedTeamAdapter()
        cmd = adapter.build_command("127.0.0.1", technique_id="T1082")
        assert "atomic_exec" in cmd
        assert "--technique T1082" in cmd

    def test_parse_output(self):
        adapter = AtomicRedTeamAdapter()
        stdout = "OS Name: Microsoft Windows 11 Pro\nOS Version: 10.0.26100\n"
        findings, assets = adapter.parse_output(
            stdout, "", "127.0.0.1", technique_id="T1082", test_name="Host OS Info"
        )

        assert len(findings) == 1
        finding = findings[0]
        assert finding.mitre_attack_ids == ["T1082"]
        assert finding.tool == "atomic_red_team"
        assert finding.severity == Severity.INFO
        assert "T1082" in finding.title
        assert "Windows 11" in finding.evidence

        assert len(assets) == 1
        assert assets[0].ip == "127.0.0.1"

    def test_live_execution_against_local_target(self, purple_scope: ScopeManifest):
        """Live execution of benign discovery techniques against authorized localhost."""
        adapter = AtomicRedTeamAdapter()
        assert adapter.is_installed()

        # Run safe T1082 technique
        result = adapter.run("127.0.0.1", purple_scope, technique_id="T1082")
        assert result.exit_code == 0
        assert len(result.findings) >= 1
        assert result.findings[0].mitre_attack_ids == ["T1082"]
        assert len(result.raw_stdout) > 0


class TestDetectionGapEngine:
    """Verifies DetectionGapEngine Sigma rule correlation, coverage scoring, and blind spot detection."""

    def test_full_detection_coverage(self):
        engine = DetectionGapEngine()
        executed = ["T1082", "T1087.001", "T1057"]

        report = engine.evaluate_emulation(executed, target="127.0.0.1")
        assert report.total_tested == 3
        assert report.detected_count == 3
        assert report.blind_spot_count == 0
        assert report.visibility_score == 100.0
        assert report.detection_score == 100.0
        assert len(report.blind_spot_findings) == 0

    def test_partial_detection_coverage_flags_blind_spots(self):
        engine = DetectionGapEngine()
        executed = ["T1082", "T1087.001", "T1059.001", "T1518.001"]

        # Simulate defense that only has active rules for T1082
        active_rules = {"sigma_proc_creation_win_sysinfo_discovery"}

        report = engine.evaluate_emulation(
            executed, active_rules=active_rules, target="127.0.0.1"
        )

        assert report.total_tested == 4
        assert report.detected_count == 1
        assert report.blind_spot_count == 3
        assert report.visibility_score == 25.0
        assert report.detection_score == 25.0

        # Verify blind spot findings generated with Sigma rule remediation
        assert len(report.blind_spot_findings) == 3
        blind_spot_tids = {f.mitre_attack_ids[0] for f in report.blind_spot_findings}
        assert "T1059.001" in blind_spot_tids
        assert "T1518.001" in blind_spot_tids
        assert "T1087.001" in blind_spot_tids

        for f in report.blind_spot_findings:
            assert "Blind Spot" in f.title
            assert "sigma" in f.remediation.lower()
            assert f.tool == "detection_engine"

    def test_telemetry_logging_score(self):
        engine = DetectionGapEngine()
        executed = ["T1082", "T1049"]

        # No active alerting rules, but telemetry captured the netstat execution
        telemetry = [{"event_type": "process_creation", "command": "netstat -ano", "technique": "T1049"}]

        report = engine.evaluate_emulation(
            executed, active_rules=set(), telemetry_events=telemetry, target="127.0.0.1"
        )

        assert report.detected_count == 0
        assert report.logged_count == 1  # T1049 was logged
        assert report.blind_spot_count == 1  # T1082 had neither
        assert report.visibility_score == 50.0  # (1 logged) / 2 = 50%
        assert report.detection_score == 0.0

    def test_markdown_summary_generation(self):
        engine = DetectionGapEngine()
        executed = ["T1082", "T1087.001"]
        report = engine.evaluate_emulation(executed, active_rules={"T1082"})

        summary = engine.generate_markdown_summary(report)
        assert "Purple Team Adversary Emulation & Detection Matrix" in summary
        assert "T1082" in summary
        assert "DETECTED" in summary
        assert "BLIND SPOT" in summary


class TestCalderaAdapter:
    """Verifies CalderaAdapter REST client and fallback execution."""

    def test_scope_enforcement(self, purple_scope: ScopeManifest):
        adapter = CalderaAdapter()
        with pytest.raises(ScopeViolationError):
            adapter.run("10.10.10.10", purple_scope)

    def test_build_command(self):
        adapter = CalderaAdapter(server_url="http://127.0.0.1:8888", adversary_profile="hunter")
        cmd = adapter.build_command("127.0.0.1")
        assert "caldera_operation" in cmd
        assert "--adversary hunter" in cmd
        assert "127.0.0.1" in cmd

    def test_parse_caldera_json_output(self):
        adapter = CalderaAdapter()
        mock_report = json.dumps({
            "steps": [
                {
                    "technique_id": "T1082",
                    "ability_name": "Identify System OS",
                    "status": 0,
                    "output": "Windows 11 Enterprise",
                }
            ]
        })

        findings, assets = adapter.parse_output(mock_report, "", "127.0.0.1")
        assert len(findings) == 1
        assert findings[0].mitre_attack_ids == ["T1082"]
        assert "Identify System OS" in findings[0].title
        assert findings[0].tool == "caldera"

    def test_fallback_when_server_offline(self, purple_scope: ScopeManifest):
        """When Caldera API daemon is offline, falls back to AtomicRedTeamAdapter."""
        adapter = CalderaAdapter(server_url="http://127.0.0.1:59999")  # Non-existent port
        result = adapter.run("127.0.0.1", purple_scope, technique_id="T1082")

        assert result.exit_code == 0
        assert len(result.findings) >= 1
        assert result.findings[0].mitre_attack_ids == ["T1082"]


class TestPurpleAgentSwarm:
    """Verifies autonomous PurpleAgent swarm subscription, event dispatch, and correlation."""

    def test_agent_predicates(self):
        agent = PurpleAgent()

        # Events that should trigger PurpleAgent
        assert agent.can_handle(BlackboardEvent(
            event_type=EventType.HOST_DISCOVERED,
            source_agent="recon-agent",
            target="127.0.0.1",
            payload={"tags": ["purple"]},
        ))

        assert agent.can_handle(BlackboardEvent(
            event_type=EventType.IDENTITY_ASSET_DISCOVERED,
            source_agent="identity-agent",
            target="127.0.0.1",
        ))

        assert agent.can_handle(BlackboardEvent(
            event_type=EventType.TARGET_REGISTERED,
            source_agent="user",
            target="127.0.0.1",
            payload={"tags": ["purple", "emulation"]},
        ))

        # Events that should NOT trigger PurpleAgent
        assert not agent.can_handle(BlackboardEvent(
            event_type=EventType.TTP_EMULATED,
            source_agent="purple-agent",
            target="127.0.0.1",
        ))

        assert not agent.can_handle(BlackboardEvent(
            event_type=EventType.CRAWL_COMPLETED,
            source_agent="crawl-agent",
            target="http://localhost:3000",
        ))

    def test_agent_handle_dispatches_emulation_and_detection_events(self, purple_scope: ScopeManifest):
        # Setup mock detection engine with partial coverage to produce blind spots
        det_engine = DetectionGapEngine()
        agent = PurpleAgent(detection_engine=det_engine)
        # Limit active rules to only T1082 so that other executed techniques become blind spots
        det_engine.rules["T1087.001"].enabled = False

        blackboard = Blackboard()
        event = BlackboardEvent(
            event_type=EventType.HOST_DISCOVERED,
            source_agent="recon-agent",
            target="127.0.0.1",
            payload={"tags": ["purple"]},
        )

        agent.handle(event, blackboard, purple_scope)

        # Confirm findings were registered on blackboard
        findings = blackboard.get_findings()
        assert len(findings) >= 2

        # Check emitted events
        event_types = [e.event_type for e in blackboard.get_events()]
        assert EventType.TTP_EMULATED in event_types
        assert EventType.DETECTION_GAP_IDENTIFIED in event_types

        # Verify blind spot finding details
        gap_finding = next((f for f in findings if "Blind Spot" in f.title), None)
        assert gap_finding is not None
        assert gap_finding.tool == "detection_engine"
        assert "sigma" in gap_finding.remediation.lower()

    def test_attack_graph_and_mitre_correlation(self):
        from reporting.mitre_mapper import TECHNIQUES_DEF
        assert "T1082" in TECHNIQUES_DEF
        assert "T1087.001" in TECHNIQUES_DEF
        assert "T1057" in TECHNIQUES_DEF

        # Test AttackGraph correlation for purple team findings
        engine = AttackGraphEngine()
        finding = Finding(
            title="Defensive Blind Spot: Undetected TTP T1087.001 (Local Account Enumeration)",
            description="TTP executed undetected.",
            severity=Severity.HIGH,
            target="127.0.0.1",
            tool="detection_engine",
            mitre_attack_ids=["T1087.001"],
        )
        asset = HostAsset(ip="127.0.0.1", hostname="localhost")

        graph = engine.build_graph([asset], [finding], target_name="127.0.0.1")

        # Verify Chain H created destination objective
        assert "obj_unmonitored_adversary_path" in graph.nodes
        obj_node = graph.nodes["obj_unmonitored_adversary_path"]
        assert "Unmonitored Adversary Attack Path" in obj_node.label
        assert obj_node.severity == Severity.HIGH

        # Verify edge escalates to objective
        purple_edges = [
            e for e in graph.edges if e.target == "obj_unmonitored_adversary_path"
        ]
        assert len(purple_edges) == 1
        assert purple_edges[0].label == "Evasion / Blind Spot"


# ============================================================================
# Purple Teaming — Live Telemetry  [REAL-TOOL-vs-REAL-OS-TELEMETRY]
# ============================================================================

import json
import os
from pathlib import Path

from adapters.purple.telemetry_collector import TelemetryCollector, TELEMETRY_JSON_PATH


@pytest.mark.live
class TestPurpleLiveTelemetry:
    """
    LABEL: REAL-TOOL-vs-REAL-OS-TELEMETRY
    Runs real atomic tests on localhost and verifies that:
    1. evidence_live/telemetry_events.json is written with real execution data
    2. DetectionGapEngine reads the real telemetry and changes scoring based on it
    """

    @classmethod
    def setup_class(cls):
        """Clean up any stale telemetry from previous runs."""
        if TELEMETRY_JSON_PATH.exists():
            TELEMETRY_JSON_PATH.unlink()

    def test_atomic_execution_writes_real_telemetry(self):
        """
        REAL-TOOL-vs-REAL-OS-TELEMETRY:
        Run T1082 (System Info Discovery) and T1033 (User Discovery) atomics on localhost.
        Verify evidence_live/telemetry_events.json is written with real command output.
        """
        scope = ScopeManifest(
            allowed_hosts=["127.0.0.1", "localhost"],
            allowed_cidrs=["127.0.0.1/32"],
        )
        adapter = AtomicRedTeamAdapter()
        assert adapter.is_installed()

        # Run two real atomic tests
        result_t1082 = adapter.run("127.0.0.1", scope, technique_id="T1082")
        result_t1033 = adapter.run("127.0.0.1", scope, technique_id="T1033")

        assert result_t1082.exit_code == 0
        assert result_t1033.exit_code == 0
        assert len(result_t1082.raw_stdout) > 0, "T1082 produced no stdout"
        assert len(result_t1033.raw_stdout) > 0, "T1033 produced no stdout"

        print(f"\n[T1082 real output snippet]: {result_t1082.raw_stdout[:300]}")
        print(f"\n[T1033 real output snippet]: {result_t1033.raw_stdout[:300]}")

        # Verify telemetry JSON was written
        assert TELEMETRY_JSON_PATH.exists(), (
            f"Telemetry file not created at {TELEMETRY_JSON_PATH}"
        )

        with open(TELEMETRY_JSON_PATH, "r") as f:
            events = json.load(f)

        print(f"\n[Telemetry JSON] ({len(events)} events):")
        for ev in events:
            print(f"  technique={ev.get('technique_id')}, exit_code={ev.get('exit_code')}, "
                  f"timestamp={ev.get('timestamp')}, stdout_snippet={ev.get('stdout_snippet', '')[:80]}")

        assert len(events) >= 2, f"Expected >= 2 telemetry events, got {len(events)}"

        technique_ids = {ev["technique_id"] for ev in events}
        assert "T1082" in technique_ids, "T1082 telemetry event missing"
        assert "T1033" in technique_ids, "T1033 telemetry event missing"

        # Verify real content: timestamps must be ISO format, stdout must be non-empty
        for ev in events:
            assert ev.get("timestamp"), "Telemetry event missing timestamp"
            assert ev.get("source") == "atomic_red_team"
            assert len(ev.get("stdout_snippet", "")) > 0, (
                f"Empty stdout in telemetry event for {ev.get('technique_id')}"
            )

    def test_detection_engine_reads_live_telemetry(self):
        """
        REAL-TOOL-vs-REAL-OS-TELEMETRY:
        Feed real telemetry from evidence_live/telemetry_events.json into DetectionGapEngine.
        Techniques that are in the telemetry but have no active detection rules should
        transition from BLIND_SPOT to LOGGED_ONLY, proving the engine reads real evidence.
        """
        # Ensure telemetry exists (run previous test first, or skip)
        if not TELEMETRY_JSON_PATH.exists():
            pytest.skip("No telemetry file found — run test_atomic_execution_writes_real_telemetry first")

        with open(TELEMETRY_JSON_PATH) as f:
            events = json.load(f)
        print(f"\n[Telemetry file has {len(events)} real events]")

        # Evaluate with NO active detection rules — forces blind spot unless telemetry rescues
        engine = DetectionGapEngine()
        executed = list({ev["technique_id"] for ev in events})
        print(f"[Executed techniques from real telemetry]: {executed}")

        # Without live telemetry — everything is blind spot since no rules active
        report_without = engine.evaluate_emulation(
            executed,
            active_rules=set(),  # No detection rules active
            collect_live_telemetry=False,
            target="127.0.0.1",
        )
        print(f"[Without telemetry] blind_spots={report_without.blind_spot_count}, logged={report_without.logged_count}")

        # With live telemetry — techniques logged in JSON get LOGGED_ONLY status
        report_with = engine.evaluate_emulation(
            executed,
            active_rules=set(),  # Same: no detection rules
            collect_live_telemetry=True,  # But now reads real JSON
            target="127.0.0.1",
        )
        print(f"[With telemetry] blind_spots={report_with.blind_spot_count}, logged={report_with.logged_count}")

        # With real telemetry, at least some techniques should move from blind spot to logged
        assert report_with.logged_count > 0, (
            "Expected at least one technique to be LOGGED_ONLY via real telemetry, "
            "but got logged_count=0. This means telemetry was not read."
        )
        assert report_with.blind_spot_count < report_without.blind_spot_count or report_with.logged_count > 0, (
            "Live telemetry did not improve detection coverage score"
        )

        # Print the coverage change as evidence
        print(f"\n[EVIDENCE] Visibility score change: "
              f"{report_without.visibility_score}% -> {report_with.visibility_score}%")
        print(f"[EVIDENCE] BLIND_SPOT count change: "
              f"{report_without.blind_spot_count} -> {report_with.blind_spot_count}")
        print(f"[EVIDENCE] LOGGED_ONLY count change: "
              f"{report_without.logged_count} -> {report_with.logged_count}")

    def test_telemetry_collector_loads_json(self):
        """Verify TelemetryCollector correctly reads the written JSON file."""
        if not TELEMETRY_JSON_PATH.exists():
            pytest.skip("No telemetry file to read")

        collector = TelemetryCollector()
        events = collector.load_from_json()

        assert len(events) >= 1
        for ev in events:
            assert "technique_id" in ev
            assert "timestamp" in ev
            assert "source" in ev
        print(f"\n[TelemetryCollector loaded {len(events)} events from real JSON]")
