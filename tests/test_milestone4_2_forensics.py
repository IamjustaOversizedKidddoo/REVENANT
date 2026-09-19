"""
REVENANT — Phase 4, Milestone 4.2 Test Suite: Endpoint Forensics & Memory Analysis Engine
Tests Volatility 3, Velociraptor, ForensicsAgent, and Attack Graph Correlation for
process injection, memory implants, C2 sockets, and endpoint persistence.
"""

import json
import os
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from adapters.forensics.velociraptor_adapter import VelociraptorAdapter
from adapters.forensics.volatility_adapter import Volatility3Adapter
from control_plane.schemas.models import Finding, HostAsset, Severity
from control_plane.schemas.scope import ScopeManifest
from orchestrator.agents.forensics_agent import ForensicsAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType
from orchestrator.correlation.attack_graph_engine import AttackGraphEngine


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures" / "forensics"


@pytest.fixture
def permissive_scope() -> ScopeManifest:
    return ScopeManifest(
        allowed_hosts=["192.168.1.105", "127.0.0.1", "memory.dmp", "victim.dmp", "LAPTOP-8IAE4RB0"],
        allowed_cidrs=["192.168.1.0/24", "127.0.0.0/8"],
    )


class TestVolatility3Adapter:
    """Unit tests for Volatility 3 Memory Forensics Adapter."""

    def test_build_command(self):
        adapter = Volatility3Adapter(use_wsl=False)
        cmd = adapter.build_command("mem.dmp", {"plugin": "windows.malfind.Malfind"})
        assert cmd == ["vol", "-r", "json", "-f", "mem.dmp", "windows.malfind.Malfind"]

    def test_parse_malfind_json(self, fixtures_dir):
        adapter = Volatility3Adapter(use_wsl=False)
        content = (fixtures_dir / "volatility_malfind.json").read_text()
        findings, assets = adapter.parse_output(content, "", "mem.dmp")

        assert len(findings) == 1
        finding = findings[0]
        assert "Memory Injection Detected in svchost.exe" in finding.title
        assert finding.severity == Severity.CRITICAL
        assert "T1055" in finding.mitre_attack_ids
        assert "PAGE_EXECUTE_READWRITE" in finding.description
        assert "MZ header" in finding.description

    def test_parse_netscan_json(self, fixtures_dir):
        adapter = Volatility3Adapter(use_wsl=False)
        content = (fixtures_dir / "volatility_netscan.json").read_text()
        findings, assets = adapter.parse_output(content, "", "mem.dmp")

        assert len(findings) == 1
        finding = findings[0]
        assert "Suspicious Outbound C2 Socket" in finding.title
        assert finding.severity == Severity.HIGH
        assert "T1071" in finding.mitre_attack_ids
        assert "198.51.100.44:4444" in finding.target

    def test_parse_pslist_json(self, fixtures_dir):
        adapter = Volatility3Adapter(use_wsl=False)
        content = (fixtures_dir / "volatility_pslist.json").read_text()
        findings, assets = adapter.parse_output(content, "", "mem.dmp")

        assert len(findings) == 1
        finding = findings[0]
        assert "Anomalous Process Lineage" in finding.title
        assert "PID: 4812, PPID: 1337" in finding.title
        assert "T1057" in finding.mitre_attack_ids

    def test_empty_or_malformed_output(self):
        adapter = Volatility3Adapter(use_wsl=False)
        empty_f, _ = adapter.parse_output("", "", "mem.dmp")
        assert len(empty_f) == 0

        malformed_f, _ = adapter.parse_output("FATAL ERROR: invalid magic byte", "", "mem.dmp")
        assert len(malformed_f) == 0


class TestVelociraptorAdapter:
    """Unit tests for Velociraptor DFIR Artifact Adapter."""

    def test_build_command(self):
        adapter = VelociraptorAdapter(binary_override="/usr/local/bin/velociraptor", use_wsl=False)
        cmd_artifact = adapter.build_command("endpoint1", {"artifact": "Windows.Persistence.Registry"})
        assert cmd_artifact == ["/usr/local/bin/velociraptor", "artifacts", "collect", "Windows.Persistence.Registry", "--format", "json"]

        cmd_query = adapter.build_command("endpoint1", {"query": "SELECT * FROM info()"})
        assert cmd_query == ["/usr/local/bin/velociraptor", "query", "SELECT * FROM info()", "--format", "json"]

    def test_parse_persistence_json(self, fixtures_dir):
        adapter = VelociraptorAdapter(use_wsl=False)
        content = (fixtures_dir / "velociraptor_persistence.json").read_text()
        findings, assets = adapter.parse_output(content, "", "target_host")

        assert len(findings) == 2
        runkey = next(f for f in findings if "SecurityUpdateService" in f.title)
        assert runkey.severity == Severity.HIGH
        assert "T1547.001" in runkey.mitre_attack_ids
        assert "svchost.exe --beacon" in runkey.description

        runonce = next(f for f in findings if "UpdaterTask" in f.title)
        assert runonce.severity == Severity.CRITICAL
        assert "T1059.001" in runonce.mitre_attack_ids

    def test_empty_or_malformed_output(self):
        adapter = VelociraptorAdapter(use_wsl=False)
        res_f, _ = adapter.parse_output("{bad-json}", "", "target_host")
        assert len(res_f) == 0


class TestLiveVelociraptorExecution:
    """Live execution tests invoking real /usr/local/bin/velociraptor binary in WSL2."""

    @pytest.mark.live
    def test_live_velociraptor_query_info(self, permissive_scope):
        adapter = VelociraptorAdapter(binary_override="/usr/local/bin/velociraptor", use_wsl=True)
        res = adapter.run("127.0.0.1", permissive_scope, params={"query": "SELECT * FROM info()"})

        assert res.exit_code == 0
        assert len(res.discovered_assets) >= 1
        asset = res.discovered_assets[0]
        assert asset.metadata.get("os") == "linux"
        assert "ubuntu" in asset.metadata.get("platform", "").lower()
        print(f"\n[LIVE VELOCIRAPTOR PROOF] Hostname: {asset.hostname}, OS: {asset.metadata.get('os')}, Kernel: {asset.metadata.get('kernel')}")

    @pytest.mark.live
    def test_live_velociraptor_collect_netstat(self, permissive_scope):
        adapter = VelociraptorAdapter(binary_override="/usr/local/bin/velociraptor", use_wsl=True)
        res = adapter.run("127.0.0.1", permissive_scope, params={"artifact": "Linux.Network.Netstat"})

        assert res.exit_code == 0
        assert len(res.raw_stdout) > 0
        decoder = json.JSONDecoder()
        parsed = []
        idx = 0
        raw = res.raw_stdout.strip()
        while idx < len(raw):
            while idx < len(raw) and raw[idx].isspace():
                idx += 1
            if idx >= len(raw):
                break
            try:
                obj, end_idx = decoder.raw_decode(raw, idx)
                if isinstance(obj, list):
                    parsed.extend(obj)
                elif isinstance(obj, dict):
                    parsed.append(obj)
                idx = end_idx
            except json.JSONDecodeError:
                idx += 1
        assert isinstance(parsed, list)
        assert len(parsed) > 0
        # Verify smbd or systemd listening sockets are present
        ports = [item.get("LocalPort") for item in parsed if isinstance(item, dict)]
        assert any(p in ports for p in (53, 139, 445))
        print(f"\n[LIVE VELOCIRAPTOR PROOF] Netstat retrieved {len(parsed)} active sockets from WSL2. Ports: {set(ports)}")


class TestForensicsAgent:
    """Unit tests for ForensicsAgent lifecycle and blackboard dispatch."""

    def test_can_handle_predicate(self):
        agent = ForensicsAgent()

        ev_mem = BlackboardEvent(
            event_type=EventType.TARGET_REGISTERED,
            source_agent="orchestrator",
            target="victim_workstation.raw",
            payload={"target_type": "MEMORY"},
        )
        assert agent.can_handle(ev_mem) is True

        ev_triage = BlackboardEvent(
            event_type=EventType.FORENSICS_ARTIFACT_DISCOVERED,
            source_agent="orchestrator",
            target="192.168.1.105",
            payload={"mode": "endpoint"},
        )
        assert agent.can_handle(ev_triage) is True

        ev_web = BlackboardEvent(
            event_type=EventType.TARGET_REGISTERED,
            source_agent="orchestrator",
            target="https://example.com/api",
            payload={},
        )
        assert agent.can_handle(ev_web) is False

    def test_handle_memory_dump_dispatches_events(self, fixtures_dir, permissive_scope):
        malfind_json = (fixtures_dir / "volatility_malfind.json").read_text()
        netscan_json = (fixtures_dir / "volatility_netscan.json").read_text()

        from adapters.base import AdapterResult

        vol_adapter = Volatility3Adapter(use_wsl=False)

        def mock_vol_run(target, scope, params=None):
            plugin = (params or {}).get("plugin", "")
            if "malfind" in plugin:
                f, a = vol_adapter.parse_output(malfind_json, "", target)
                return AdapterResult(tool_name="volatility3", target=target, findings=f, discovered_assets=a)
            elif "netscan" in plugin:
                f, a = vol_adapter.parse_output(netscan_json, "", target)
                return AdapterResult(tool_name="volatility3", target=target, findings=f, discovered_assets=a)
            return AdapterResult(tool_name="volatility3", target=target, findings=[], discovered_assets=[])

        vol_adapter.run = mock_vol_run

        agent = ForensicsAgent(volatility_adapter=vol_adapter)
        bb = Blackboard()

        event = BlackboardEvent(
            event_type=EventType.TARGET_REGISTERED,
            source_agent="orchestrator",
            target="victim.dmp",
            payload={"mode": "memory"},
        )

        out_events = agent.handle(event, bb, permissive_scope)
        findings = bb.get_findings()

        assert len(findings) == 2
        assert any("Memory Injection" in f.title for f in findings)
        assert any("C2 Socket" in f.title for f in findings)
        assert len(out_events) == 2
        assert all(e.event_type == EventType.VULNERABILITY_CONFIRMED for e in out_events)


class TestForensicsAttackGraphIntegration:
    """Tests AttackGraph correlation for memory injection, implants, and persistence."""

    def test_memory_injection_and_persistence_exploit_chain(self):
        engine = AttackGraphEngine()
        bb = Blackboard()

        f_inject = Finding(
            title="Memory Injection Detected in svchost.exe (PID: 4812)",
            description="Injected PE detected in RWX memory",
            severity=Severity.CRITICAL,
            target="192.168.1.105:svchost.exe:4812",
            tool="volatility3",
            mitre_attack_ids=["T1055"],
        )

        f_persist = Finding(
            title="Malicious Persistence Registry Entry: UpdaterTask",
            description="Auto-run executes encoded PowerShell stager",
            severity=Severity.CRITICAL,
            target="192.168.1.105:RunOnce:UpdaterTask",
            tool="velociraptor",
            mitre_attack_ids=["T1547.001", "T1059.001"],
        )

        f_c2 = Finding(
            title="Suspicious Outbound C2 Socket in svchost.exe -> 198.51.100.44:4444",
            description="Active TCP beacon to foreign command server",
            severity=Severity.HIGH,
            target="192.168.1.105:198.51.100.44:4444",
            tool="volatility3",
            mitre_attack_ids=["T1071"],
        )

        bb.add_finding(f_inject)
        bb.add_finding(f_persist)
        bb.add_finding(f_c2)

        graph = engine.build_graph(bb.get_assets(), bb.get_findings())

        # Verify synthesized objectives
        assert "obj_in_memory_implant" in graph.nodes
        assert "obj_endpoint_persistence" in graph.nodes
        assert "obj_c2_channel" in graph.nodes

        # Verify edges
        edges_to_implant = [e for e in graph.edges if e.target == "obj_in_memory_implant"]
        assert len(edges_to_implant) >= 1
        assert edges_to_implant[0].label == "Process Hollow / Injection"

        edges_to_persist = [e for e in graph.edges if e.target == "obj_endpoint_persistence"]
        assert len(edges_to_persist) >= 1
        assert edges_to_persist[0].label == "Autostart Registry / Service"

        edges_to_c2 = [e for e in graph.edges if e.target == "obj_c2_channel"]
        assert len(edges_to_c2) >= 1
        assert edges_to_c2[0].label == "Outbound C2"
