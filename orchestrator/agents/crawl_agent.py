"""
REVENANT — Specialist Web Crawling & Endpoint Mapping Agent
Triggers on TARGET_REGISTERED (web URLs) or HTTP_ENDPOINT events, executes
Katana deep crawler, extracts links, forms, and parameter surfaces, and
publishes CRAWL_COMPLETED and PARAMETER_DISCOVERED events.
"""

from __future__ import annotations

import logging
from typing import List, Optional
import urllib.parse

from adapters.web.katana_adapter import KatanaAdapter
from control_plane.schemas.scope import ScopeManifest
from orchestrator.agents.base_agent import BaseAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType

logger = logging.getLogger("revenant.agents.crawl")


class CrawlAgent(BaseAgent):
    """Specialist agent for deep web application crawling and attack surface discovery."""

    def __init__(self, katana_adapter: Optional[KatanaAdapter] = None):
        super().__init__(name="crawl-agent", role="Web Crawling & Attack Surface Mapping")
        self.katana = katana_adapter or KatanaAdapter()
        self._crawled_urls: set[str] = set()

    def can_handle(self, event: BlackboardEvent) -> bool:
        if event.target in self._crawled_urls:
            return False

        if event.event_type == EventType.HTTP_ENDPOINT:
            return True

        if event.event_type == EventType.TARGET_REGISTERED:
            target = event.target
            # Check if target is an HTTP/HTTPS web target
            if target.startswith("http://") or target.startswith("https://"):
                return True
            if event.payload.get("target_type") in ["DOMAIN", "URL"]:
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
        if target in self._crawled_urls:
            return []
        self._crawled_urls.add(target)

        # Execute deep crawling with Katana
        crawl_res = self.katana.run(target, scope)

        for asset in crawl_res.discovered_assets:
            blackboard.add_asset(asset)

            # Check all endpoints discovered
            all_endpoints = asset.endpoints or []
            parameterized_endpoints = [
                ep for ep in all_endpoints if ep.parameters or ep.forms
            ]

            # Emit CRAWL_COMPLETED event
            new_events.append(
                BlackboardEvent(
                    event_type=EventType.CRAWL_COMPLETED,
                    source_agent=self.name,
                    target=target,
                    payload={
                        "total_endpoints": len(all_endpoints),
                        "parameterized_count": len(parameterized_endpoints),
                        "endpoints": [ep.model_dump(mode="json") for ep in all_endpoints],
                    },
                )
            )

            # Emit PARAMETER_DISCOVERED for endpoints with attack surfaces
            for ep in parameterized_endpoints:
                new_events.append(
                    BlackboardEvent(
                        event_type=EventType.PARAMETER_DISCOVERED,
                        source_agent=self.name,
                        target=ep.url,
                        payload={"endpoint": ep.model_dump(mode="json")},
                    )
                )

        return new_events
