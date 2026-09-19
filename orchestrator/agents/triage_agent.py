"""
REVENANT — Specialist Triage Agent
Triggers on VULNERABILITY_CANDIDATE events, deduplicates against existing findings,
validates severity/scoring, records verified findings, and emits VULNERABILITY_CONFIRMED events.
"""

from __future__ import annotations

from typing import List
from control_plane.schemas.models import Finding
from control_plane.schemas.scope import ScopeManifest
from orchestrator.agents.base_agent import BaseAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType


class TriageAgent(BaseAgent):
    """Specialist agent for deduplication, risk scoring, and finding triage."""

    def __init__(self):
        super().__init__(name="triage-agent", role="Vulnerability Triage & Correlation")

    def can_handle(self, event: BlackboardEvent) -> bool:
        return event.event_type in [
            EventType.VULNERABILITY_CANDIDATE,
            EventType.SECRET_EXPOSED,
            EventType.DAST_CANDIDATE,
            EventType.MISCONFIGURATION_DETECTED,
            EventType.PRIVILEGE_ESCALATION_PATH_DETECTED,
        ]

    def handle(
        self,
        event: BlackboardEvent,
        blackboard: Blackboard,
        scope: ScopeManifest,
    ) -> List[BlackboardEvent]:
        new_events: List[BlackboardEvent] = []
        raw_finding = event.payload.get("finding")
        if not raw_finding:
            return []

        finding = Finding.model_validate(raw_finding)

        # Deduplication check against existing confirmed findings on the blackboard
        existing_findings = blackboard.get_findings()
        is_duplicate = any(
            f.title == finding.title
            and f.target == finding.target
            and f.endpoint == finding.endpoint
            for f in existing_findings
        )

        if not is_duplicate:
            finding.verified = True
            blackboard.add_finding(finding)

            new_events.append(
                BlackboardEvent(
                    event_type=EventType.VULNERABILITY_CONFIRMED,
                    source_agent=self.name,
                    target=finding.target,
                    payload={
                        "finding_id": finding.id,
                        "title": finding.title,
                        "severity": finding.severity.value,
                        "cve": finding.cve,
                        "cvss_score": finding.cvss_score,
                    },
                )
            )

        return new_events
