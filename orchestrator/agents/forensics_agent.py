"""
REVENANT — Forensics & Incident Response Specialist Agent (DFIR)
Ingests endpoint triage artifacts, memory dumps, and VQL queries.
Runs Volatility 3 and Velociraptor adapters to identify process injection,
in-memory executable implants, rogue network sockets, and persistence mechanisms.
"""

from __future__ import annotations

import os
from typing import List, Optional

from adapters.forensics.velociraptor_adapter import VelociraptorAdapter
from adapters.forensics.volatility_adapter import Volatility3Adapter
from control_plane.schemas.scope import ScopeManifest
from orchestrator.agents.base_agent import BaseAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType


class ForensicsAgent(BaseAgent):
    """Specialist agent for Digital Forensics and Incident Response (DFIR)."""

    def __init__(
        self,
        volatility_adapter: Optional[Volatility3Adapter] = None,
        velociraptor_adapter: Optional[VelociraptorAdapter] = None,
    ):
        super().__init__(name="forensics-agent", role="Forensics & Incident Response (DFIR)")
        self.volatility = volatility_adapter or Volatility3Adapter()
        self.velociraptor = velociraptor_adapter or VelociraptorAdapter()

    def can_handle(self, event: BlackboardEvent) -> bool:
        if event.event_type == EventType.FORENSICS_ARTIFACT_DISCOVERED:
            return True

        if event.event_type == EventType.TARGET_REGISTERED:
            target = event.target.lower()
            # File extensions commonly used for memory dumps & forensic packages
            if any(target.endswith(ext) for ext in [".raw", ".dmp", ".vmem", ".mem", ".lime"]):
                return True
            # Keywords indicating forensics or endpoint triage
            if any(k in target for k in ["memory", "dump", "forensic", "volatility", "velociraptor", "dfir", "triage"]):
                return True
            if event.payload.get("target_type") in ["FORENSICS", "MEMORY", "ENDPOINT", "DFIR"]:
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

        is_memory = any(target_lower.endswith(ext) for ext in [".raw", ".dmp", ".vmem", ".mem", ".lime"]) or any(
            k in target_lower for k in ["memory", "dump", "volatility"]
        )

        # 1. Memory Forensics via Volatility 3
        if is_memory or event.payload.get("mode") in ["memory", "all", None]:
            try:
                # Run Malfind for injected code
                malfind_res = self.volatility.run(target, scope, params={"plugin": "windows.malfind.Malfind"})
                for asset in malfind_res.discovered_assets:
                    blackboard.add_asset(asset)
                for f in malfind_res.findings:
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
                                "type": "MEMORY_INJECTION",
                            },
                        )
                    )

                # Run NetScan for outbound C2 sockets
                netscan_res = self.volatility.run(target, scope, params={"plugin": "windows.netscan.NetScan"})
                for f in netscan_res.findings:
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
                                "type": "C2_SOCKET",
                            },
                        )
                    )
            except Exception as e:
                self.logger.warning(f"Volatility analysis failed on {target}: {e}")

        # 2. Endpoint Artifact Triage via Velociraptor
        if not is_memory or event.payload.get("mode") in ["endpoint", "all", "persistence"]:
            try:
                vr_res = self.velociraptor.run(target, scope, params=event.payload)
                for asset in vr_res.discovered_assets:
                    blackboard.add_asset(asset)
                for f in vr_res.findings:
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
                                "type": "ENDPOINT_PERSISTENCE",
                            },
                        )
                    )
            except Exception as e:
                self.logger.warning(f"Velociraptor triage failed on {target}: {e}")

        return new_events
