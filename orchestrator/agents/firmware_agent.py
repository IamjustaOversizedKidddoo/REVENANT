"""
REVENANT — Firmware & Embedded Systems Specialist Agent
Orchestrates IoT firmware analysis and binary fuzzing crash triage:
- Runs Binwalk for filesystem signature carving and hardcoded private key extraction
- Runs AFL++ / ASan crash triage for memory corruption vulnerabilities
- Pushes discovered embedded vulnerabilities into the stigmergic blackboard.
"""

from __future__ import annotations

import os
from typing import List, Optional

from adapters.firmware.binwalk_adapter import BinwalkAdapter
from adapters.fuzzing.afl_adapter import AFLFuzzingAdapter
from control_plane.schemas.scope import ScopeManifest
from orchestrator.agents.base_agent import BaseAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType


class FirmwareAgent(BaseAgent):
    """Specialist agent for embedded firmware auditing, IoT analysis, and fuzzing crash triage."""

    def __init__(
        self,
        binwalk_adapter: Optional[BinwalkAdapter] = None,
        fuzzing_adapter: Optional[AFLFuzzingAdapter] = None,
    ):
        super().__init__(name="firmware-agent", role="Firmware & Binary Fuzzing Specialist")
        self.binwalk = binwalk_adapter or BinwalkAdapter()
        self.fuzzer = fuzzing_adapter or AFLFuzzingAdapter()

    def can_handle(self, event: BlackboardEvent) -> bool:
        if event.event_type == EventType.TARGET_REGISTERED:
            target = event.target.lower()
            if any(target.endswith(ext) for ext in [".bin", ".img", ".rom", ".fw", ".squashfs"]):
                return True
            if any(k in target for k in ["firmware", "binwalk", "fuzz", "crash", "iot", "embedded", "rom", "afl", "asan"]):
                return True
            if event.payload.get("target_type") in ["FIRMWARE", "IOT", "FUZZING", "EMBEDDED"]:
                return True

        return False

    def handle(
        self,
        event: BlackboardEvent,
        blackboard: Blackboard,
        scope: ScopeManifest,
    ) -> List[BlackboardEvent]:
        new_events: List[BlackboardEvent] = []
        target = event.target
        target_lower = target.lower()

        is_fuzz_crash = any(k in target_lower for k in ["crash", "asan", "fuzz", "trace"]) or event.payload.get("mode") == "fuzzing"

        # 1. Fuzzing Crash Triage
        if is_fuzz_crash:
            try:
                fuzz_res = self.fuzzer.run(target, scope, params=event.payload)
                for asset in fuzz_res.discovered_assets:
                    blackboard.add_asset(asset)
                for f in fuzz_res.findings:
                    blackboard.add_finding(f)
                    new_events.append(
                        BlackboardEvent(
                            event_type=EventType.VULNERABILITY_CONFIRMED,
                            source_agent=self.name,
                            target=f.target,
                            payload={
                                "title": f.title,
                                "severity": f.severity.value,
                                "mitre_ids": f.mitre_attack_ids,
                                "type": "FUZZING_CRASH",
                            },
                        )
                    )
            except Exception as e:
                self.logger.warning(f"Fuzzing triage failed on {target}: {e}")

        # 2. Firmware Signature & Key Carving
        if not is_fuzz_crash or event.payload.get("run_binwalk"):
            try:
                bw_res = self.binwalk.run(target, scope, params=event.payload)
                for asset in bw_res.discovered_assets:
                    blackboard.add_asset(asset)
                for f in bw_res.findings:
                    blackboard.add_finding(f)
                    new_events.append(
                        BlackboardEvent(
                            event_type=EventType.VULNERABILITY_CONFIRMED,
                            source_agent=self.name,
                            target=f.target,
                            payload={
                                "title": f.title,
                                "severity": f.severity.value,
                                "mitre_ids": f.mitre_attack_ids,
                                "type": "FIRMWARE_VULNERABILITY",
                            },
                        )
                    )
            except Exception as e:
                self.logger.warning(f"Binwalk firmware analysis failed on {target}: {e}")

        return new_events
