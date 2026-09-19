"""
REVENANT — Purple Teaming & Adversary Emulation Agent
Autonomous swarm agent subscribing to HOST_DISCOVERED, IDENTITY_ASSET_DISCOVERED,
TARGET_REGISTERED, and TTP_EMULATED events.
Executes safe Atomic Red Team TTPs and evaluates defensive detection coverage via DetectionGapEngine.
"""

from __future__ import annotations

import logging
from typing import List, Optional, Set

from adapters.purple.atomic_adapter import AtomicRedTeamAdapter
from adapters.purple.caldera_adapter import CalderaAdapter
from adapters.purple.detection_engine import DetectionGapEngine
from control_plane.schemas.models import Finding, Severity
from control_plane.schemas.scope import ScopeManifest
from orchestrator.agents.base_agent import BaseAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType

logger = logging.getLogger("revenant.agents.purple")

PURPLE_TAGS = {"purple", "adversary_emulation", "ttp", "atomic", "emulation_host", "mitre"}


class PurpleAgent(BaseAgent):
    """Specialist agent for adversary emulation and defensive visibility validation."""

    def __init__(
        self,
        atomic_adapter: Optional[AtomicRedTeamAdapter] = None,
        caldera_adapter: Optional[CalderaAdapter] = None,
        detection_engine: Optional[DetectionGapEngine] = None,
    ):
        super().__init__(
            name="purple-agent",
            role="Adversary Emulation & Defensive Detection Gap Validation",
        )
        self.atomic = atomic_adapter or AtomicRedTeamAdapter()
        self.caldera = caldera_adapter or CalderaAdapter()
        self.detection_engine = detection_engine or DetectionGapEngine()

    def can_handle(self, event: BlackboardEvent) -> bool:
        """Evaluate if event triggers adversary emulation or detection gap analysis."""
        if event.event_type in [
            EventType.TTP_EMULATED,
            EventType.DETECTION_GAP_IDENTIFIED,
            EventType.CAMPAIGN_COMPLETE,
            EventType.CRAWL_COMPLETED,
            EventType.SECRET_EXPOSED,
            EventType.DAST_CANDIDATE,
        ]:
            return False

        payload = event.payload or {}
        tags = [str(t).lower() for t in payload.get("tags", [])]

        if event.event_type == EventType.TARGET_REGISTERED:
            target_type = str(payload.get("target_type", "")).upper()
            if target_type in ["EMULATION_HOST"]:
                return True
            if any(t in PURPLE_TAGS for t in tags):
                return True

        if event.event_type == EventType.HOST_DISCOVERED:
            if any(t in PURPLE_TAGS for t in tags):
                return True

        if event.event_type == EventType.IDENTITY_ASSET_DISCOVERED:
            return True

        if event.event_type == EventType.VULNERABILITY_CONFIRMED:
            tool = payload.get("tool", "")
            if tool in ["atomic_red_team", "caldera"]:
                return True

        return False

    def handle(
        self, event: BlackboardEvent, blackboard: Blackboard, scope_manifest: ScopeManifest
    ) -> List[BlackboardEvent]:
        target = event.target
        logger.info("[purple-agent] Initiating adversary emulation against %s", target)
        out_events: List[BlackboardEvent] = []

        # Select techniques based on event context
        requested_techniques = ["T1082", "T1087.001", "T1057", "T1016", "T1033"]
        if event.event_type == EventType.IDENTITY_ASSET_DISCOVERED:
            requested_techniques = ["T1087.001", "T1033"]

        emulated_tids: List[str] = []
        emulation_findings: List[Finding] = []

        # Execute safe atomic tests
        for tid in requested_techniques:
            try:
                res = self.atomic.run(target, scope_manifest, technique_id=tid)
                if res.findings:
                    emulation_findings.extend(res.findings)
                    emulated_tids.append(tid)
                    for f in res.findings:
                        blackboard.add_finding(f)
                        evt = BlackboardEvent(
                            event_type=EventType.TTP_EMULATED,
                            source_agent=self.name,
                            target=target,
                            payload={"technique_id": tid, "title": f.title, "tool": "atomic_red_team"},
                        )
                        blackboard.post_event(evt)
                        out_events.append(evt)
            except Exception as ex:
                logger.warning("[purple-agent] Failed atomic test %s against %s: %s", tid, target, ex)

        if not emulated_tids:
            return out_events

        # Evaluate detection coverage against defensive Sigma catalog
        coverage_report = self.detection_engine.evaluate_emulation(
            executed_techniques=emulated_tids,
            target=target,
        )

        logger.info(
            "[purple-agent] Emulation evaluated for %s: Visibility Score=%s%%, Blind Spots=%d",
            target,
            coverage_report.visibility_score,
            coverage_report.blind_spot_count,
        )

        # Post detection gap findings to blackboard
        for gap_finding in coverage_report.blind_spot_findings:
            blackboard.add_finding(gap_finding)
            e1 = BlackboardEvent(
                event_type=EventType.DETECTION_GAP_IDENTIFIED,
                source_agent=self.name,
                target=target,
                payload={
                    "technique_id": gap_finding.mitre_attack_ids[0] if gap_finding.mitre_attack_ids else "UNKNOWN",
                    "title": gap_finding.title,
                    "severity": gap_finding.severity.value,
                    "tool": "detection_engine",
                },
            )
            blackboard.post_event(e1)
            out_events.append(e1)

            e2 = BlackboardEvent(
                event_type=EventType.VULNERABILITY_CONFIRMED,
                source_agent=self.name,
                target=target,
                payload={
                    "finding_id": gap_finding.id,
                    "title": gap_finding.title,
                    "severity": gap_finding.severity.value,
                    "tool": "detection_engine",
                },
            )
            blackboard.post_event(e2)
            out_events.append(e2)

        return out_events
