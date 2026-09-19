"""
REVENANT — Phase 4, Milestone 4.4 Test Suite: Binary Fuzzing & Firmware / IoT Security Engine
Tests BinwalkAdapter, AFLFuzzingAdapter, FirmwareAgent, and Attack Graph Correlation.
"""

import os
import pytest
from pathlib import Path
from unittest.mock import MagicMock

from adapters.base import AdapterResult
from adapters.firmware.binwalk_adapter import BinwalkAdapter
from adapters.fuzzing.afl_adapter import AFLFuzzingAdapter
from control_plane.schemas.models import Finding, HostAsset, Severity
from control_plane.schemas.scope import ScopeManifest
from orchestrator.agents.firmware_agent import FirmwareAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType
from orchestrator.correlation.attack_graph_engine import AttackGraphEngine


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures" / "firmware"


@pytest.fixture
def permissive_scope(fixtures_dir) -> ScopeManifest:
    return ScopeManifest(
        allowed_hosts=["127.0.0.1", "localhost", "synthetic_firmware.bin", "asan_crash.txt"],
        allowed_cidrs=["127.0.0.0/8", "192.168.1.0/24"],
        allowed_repos=[str(fixtures_dir)],
    )


class TestBinwalkAdapter:
    """Unit tests for Binwalk firmware signature carving adapter."""

    def test_build_command(self):
        adapter = BinwalkAdapter(use_wsl=False)
        cmd = adapter.build_command("router_firmware.bin", {})
        assert cmd == ["binwalk", "-B", "router_firmware.bin"]

    def test_parse_output(self):
        adapter = BinwalkAdapter(use_wsl=False)
        raw_output = (
            "DECIMAL       HEXADECIMAL     DESCRIPTION\n"
            "--------------------------------------------------------------------------------\n"
            "22            0x16            gzip compressed data, maximum compression\n"
            "225           0xE1            PEM RSA private key\n"
        )
        findings, assets = adapter.parse_output(raw_output, "", "firmware.bin")

        assert len(findings) == 2
        assert len(assets) == 1

        key_finding = next(f for f in findings if "Cryptographic Key" in f.title)
        assert key_finding.severity == Severity.CRITICAL
        assert "T1552.004" in key_finding.mitre_attack_ids
        assert "0xE1" in key_finding.evidence

        fs_finding = next(f for f in findings if "Embedded Filesystem" in f.title)
        assert fs_finding.severity == Severity.INFO

    def test_empty_output(self):
        adapter = BinwalkAdapter(use_wsl=False)
        findings, assets = adapter.parse_output("", "", "empty.bin")
        assert len(findings) == 0


class TestAFLFuzzingAdapter:
    """Unit tests for AFL++ and Sanitizer crash triage adapter."""

    def test_parse_asan_crash(self, fixtures_dir):
        adapter = AFLFuzzingAdapter(use_wsl=False)
        content = (fixtures_dir / "asan_crash.txt").read_text()
        findings, assets = adapter.parse_output(content, "", "asan_crash.txt")

        assert len(findings) == 1
        f = findings[0]
        assert "Heap Buffer Overflow in parse_packet" in f.title
        assert f.severity == Severity.CRITICAL
        assert f.cwe == "CWE-122"
        assert "T1190" in f.mitre_attack_ids
        assert "parse_packet" in f.evidence

    def test_use_after_free_crash(self):
        adapter = AFLFuzzingAdapter(use_wsl=False)
        uaf_trace = (
            "==5120==ERROR: AddressSanitizer: heap-use-after-free on address 0x603000000040\n"
            "READ of size 8 at 0x603000000040 thread T0\n"
            "    #0 0x402100 in dispatch_event /src/engine.c:88\n"
        )
        findings, assets = adapter.parse_output(uaf_trace, "", "uaf_crash.txt")

        assert len(findings) == 1
        f = findings[0]
        assert "Use-After-Free" in f.title
        assert f.severity == Severity.CRITICAL
        assert f.cwe == "CWE-416"
        assert "T1190" in f.mitre_attack_ids

    def test_empty_or_malformed(self):
        adapter = AFLFuzzingAdapter(use_wsl=False)
        findings, assets = adapter.parse_output("", "", "clean.txt")
        assert len(findings) == 0


class TestLiveBinwalkScan:
    """Live execution test running real Binwalk in WSL2 against synthetic firmware fixture."""

    @pytest.mark.live
    def test_live_binwalk_scan_on_fixture(self, fixtures_dir, permissive_scope):
        target_path = str(fixtures_dir / "synthetic_firmware.bin")
        adapter = BinwalkAdapter(use_wsl=True)

        res = adapter.run(target_path, permissive_scope)

        assert res.exit_code == 0
        assert len(res.findings) >= 2

        key_finding = next(f for f in res.findings if "Cryptographic Key" in f.title)
        assert key_finding.severity == Severity.CRITICAL
        assert "T1552.004" in key_finding.mitre_attack_ids

        gz_finding = next(f for f in res.findings if "Embedded Filesystem" in f.title)
        assert "gzip" in gz_finding.title.lower()

        print(f"\n[LIVE BINWALK PROOF] Found {len(res.findings)} signatures in firmware:")
        for f in res.findings:
            print(f"  - {f.title} (Severity: {f.severity.value}, MITRE: {f.mitre_attack_ids})")


class TestFirmwareAgent:
    """Unit tests for FirmwareAgent lifecycle and blackboard dispatch."""

    def test_can_handle_predicate(self):
        agent = FirmwareAgent()

        ev_fw = BlackboardEvent(
            event_type=EventType.TARGET_REGISTERED,
            source_agent="orchestrator",
            target="router_fw.bin",
            payload={},
        )
        assert agent.can_handle(ev_fw) is True

        ev_crash = BlackboardEvent(
            event_type=EventType.TARGET_REGISTERED,
            source_agent="orchestrator",
            target="fuzz_asan_crash.txt",
            payload={"mode": "fuzzing"},
        )
        assert agent.can_handle(ev_crash) is True

        ev_web = BlackboardEvent(
            event_type=EventType.TARGET_REGISTERED,
            source_agent="orchestrator",
            target="https://api.example.com",
            payload={},
        )
        assert agent.can_handle(ev_web) is False

    def test_handle_firmware_and_fuzzing_events(self, permissive_scope):
        bw_mock = BinwalkAdapter(use_wsl=False)
        fuzz_mock = AFLFuzzingAdapter(use_wsl=False)

        f_fw = Finding(
            title="Hardcoded Cryptographic Key in Firmware: PEM RSA private key",
            description="Embedded private key",
            severity=Severity.CRITICAL,
            target="firmware.bin:0xE1",
            tool="binwalk",
            mitre_attack_ids=["T1552.004"],
        )
        bw_mock.run = MagicMock(return_value=AdapterResult(tool_name="binwalk", target="firmware.bin", findings=[f_fw]))

        agent = FirmwareAgent(binwalk_adapter=bw_mock, fuzzing_adapter=fuzz_mock)
        bb = Blackboard()

        event = BlackboardEvent(
            event_type=EventType.TARGET_REGISTERED,
            source_agent="orchestrator",
            target="firmware.bin",
            payload={},
        )

        out_events = agent.handle(event, bb, permissive_scope)
        findings = bb.get_findings()

        assert len(findings) == 1
        assert "Cryptographic Key" in findings[0].title
        assert len(out_events) == 1
        assert out_events[0].event_type == EventType.VULNERABILITY_CONFIRMED


class TestFirmwareAttackGraphIntegration:
    """Tests AttackGraph correlation for firmware backdoors and zero-day memory corruption."""

    def test_firmware_backdoor_and_rce_chains(self):
        engine = AttackGraphEngine()
        bb = Blackboard()

        f_key = Finding(
            title="Hardcoded Cryptographic Key in Firmware: PEM RSA private key",
            description="Private root key",
            severity=Severity.CRITICAL,
            target="192.168.1.1:firmware.bin",
            tool="binwalk",
            mitre_attack_ids=["T1552.004"],
        )

        f_crash = Finding(
            title="Heap Buffer Overflow in parse_packet (protocol.c)",
            description="Fuzzing discovered exploitable heap overflow",
            severity=Severity.CRITICAL,
            target="192.168.1.1:protocol",
            tool="afl_fuzzer",
            mitre_attack_ids=["T1190"],
        )

        bb.add_finding(f_key)
        bb.add_finding(f_crash)

        graph = engine.build_graph(bb.get_assets(), bb.get_findings())

        assert "obj_firmware_backdoor" in graph.nodes
        assert "obj_zero_day_rce" in graph.nodes

        edges_to_fw = [e for e in graph.edges if e.target == "obj_firmware_backdoor"]
        assert len(edges_to_fw) >= 1
        assert edges_to_fw[0].label == "Firmware Key Exploit"

        edges_to_rce = [e for e in graph.edges if e.target == "obj_zero_day_rce"]
        assert len(edges_to_rce) >= 1
        assert edges_to_rce[0].label == "Memory Corruption RCE"
