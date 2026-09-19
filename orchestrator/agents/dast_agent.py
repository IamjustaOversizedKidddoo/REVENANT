"""
REVENANT — Specialist DAST (Dynamic Application Security Testing) Agent
Triggers on PARAMETER_DISCOVERED or CRAWL_COMPLETED events, executes DastAdapter
against discovered parameter surfaces, and publishes DAST_CANDIDATE events.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from adapters.web.dast_adapter import DastAdapter
from control_plane.schemas.models import EndpointInfo
from control_plane.schemas.scope import ScopeManifest
from orchestrator.agents.base_agent import BaseAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType

logger = logging.getLogger("revenant.agents.dast")


class DastAgent(BaseAgent):
    """Specialist agent for active web application vulnerability testing (DAST)."""

    def __init__(self, dast_adapter: Optional[DastAdapter] = None):
        super().__init__(name="dast-agent", role="Dynamic Application Security Testing")
        self.dast = dast_adapter or DastAdapter()
        self._fuzzed_urls: set[str] = set()

    def can_handle(self, event: BlackboardEvent) -> bool:
        if event.event_type == EventType.PARAMETER_DISCOVERED:
            return event.target not in self._fuzzed_urls
        return False

    def handle(
        self,
        event: BlackboardEvent,
        blackboard: Blackboard,
        scope: ScopeManifest,
    ) -> List[BlackboardEvent]:
        new_events: List[BlackboardEvent] = []
        target = event.target
        endpoints: List[EndpointInfo] = []

        if event.event_type == EventType.PARAMETER_DISCOVERED:
            raw_ep = event.payload.get("endpoint")
            if raw_ep:
                endpoints = [EndpointInfo.model_validate(raw_ep)]
            else:
                endpoints = [EndpointInfo(url=target)]

        # Filter out endpoints already tested
        endpoints_to_test = [ep for ep in endpoints if ep.url not in self._fuzzed_urls]
        if not endpoints_to_test:
            return []

        for ep in endpoints_to_test:
            self._fuzzed_urls.add(ep.url)

        # Execute active DAST injection testing
        res = self.dast.run(target, scope, params={"endpoints": endpoints})

        for asset in res.discovered_assets:
            blackboard.add_asset(asset)

        for finding in res.findings:
            new_events.append(
                BlackboardEvent(
                    event_type=EventType.DAST_CANDIDATE,
                    source_agent=self.name,
                    target=finding.target,
                    payload={"finding": finding.model_dump(mode="json")},
                )
            )

        return new_events
