"""
REVENANT — Specialist Web Agent
Triggers on HTTP_ENDPOINT events, dispatches vulnerability scanning (Nuclei),
and publishes VULNERABILITY_CANDIDATE events to the blackboard.
"""

from __future__ import annotations

import urllib.parse
from typing import List, Optional

from adapters.web.nuclei_adapter import NucleiAdapter
from control_plane.schemas.scope import ScopeManifest
from orchestrator.agents.base_agent import BaseAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType


class WebAgent(BaseAgent):
    """Specialist agent for web application vulnerability detection."""

    def __init__(self, nuclei_adapter: Optional[NucleiAdapter] = None):
        super().__init__(name="web-agent", role="Web Vulnerability Assessment")
        self.nuclei = nuclei_adapter or NucleiAdapter()
        self._scanned_roots: set[str] = set()

    def can_handle(self, event: BlackboardEvent) -> bool:
        if event.event_type != EventType.HTTP_ENDPOINT:
            return False
        parsed = urllib.parse.urlparse(event.target)
        root = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else event.target
        return root not in self._scanned_roots

    def handle(
        self,
        event: BlackboardEvent,
        blackboard: Blackboard,
        scope: ScopeManifest,
    ) -> List[BlackboardEvent]:
        new_events: List[BlackboardEvent] = []
        endpoint_url = event.target
        parsed = urllib.parse.urlparse(endpoint_url)
        root = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else endpoint_url
        if root in self._scanned_roots:
            return []
        self._scanned_roots.add(root)

        # Execute nuclei tool adapter with Layer 3 scope verification
        result = self.nuclei.run(
            endpoint_url,
            scope,
            params={"tags": ["exposure", "misconfig", "tech"]},
            timeout_seconds=20,
        )

        # For every candidate finding, publish a VULNERABILITY_CANDIDATE event
        for finding in result.findings:
            new_events.append(
                BlackboardEvent(
                    event_type=EventType.VULNERABILITY_CANDIDATE,
                    source_agent=self.name,
                    target=finding.target,
                    payload={"finding": finding.model_dump(mode="json")},
                )
            )

        return new_events
