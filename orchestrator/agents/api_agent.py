"""
REVENANT — Specialist API Security Agent
Triggers on API schema endpoints (openapi.json, swagger.json, /api/),
dispatches Schemathesis property fuzzing, and publishes VULNERABILITY_CANDIDATE events.
"""

from __future__ import annotations

from typing import List, Optional
from adapters.api.schemathesis_adapter import SchemathesisAdapter
from control_plane.schemas.scope import ScopeManifest
from orchestrator.agents.base_agent import BaseAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType

API_INDICATORS = ["swagger", "openapi", "api-docs", ".json", "/v1", "/v2", "/api"]


class ApiAgent(BaseAgent):
    """Specialist agent for automated API security testing."""

    def __init__(self, schemathesis_adapter: Optional[SchemathesisAdapter] = None):
        super().__init__(name="api-agent", role="API Fuzzing & Schema Security")
        self.schemathesis = schemathesis_adapter or SchemathesisAdapter()

    def can_handle(self, event: BlackboardEvent) -> bool:
        if event.event_type != EventType.HTTP_ENDPOINT:
            return False
        url_lower = event.target.lower()
        return any(ind in url_lower for ind in API_INDICATORS)

    def handle(
        self,
        event: BlackboardEvent,
        blackboard: Blackboard,
        scope: ScopeManifest,
    ) -> List[BlackboardEvent]:
        new_events: List[BlackboardEvent] = []
        endpoint_url = event.target

        result = self.schemathesis.run(endpoint_url, scope)

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
