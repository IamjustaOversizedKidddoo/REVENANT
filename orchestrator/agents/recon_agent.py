"""
REVENANT — Specialist Recon Agent
Triggers on TARGET_REGISTERED events, dispatches HTTP probing (httpx),
indexes discovered hosts and endpoints into the blackboard, and publishes HTTP_ENDPOINT events.
"""

from __future__ import annotations

from adapters.recon.httpx_adapter import HTTPXAdapter
from adapters.recon.subfinder_adapter import SubfinderAdapter
from adapters.web.ffuf_adapter import FfufAdapter
from control_plane.schemas.scope import ScopeEngine, ScopeManifest
from orchestrator.agents.base_agent import BaseAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType


class ReconAgent(BaseAgent):
    """Specialist agent for network/web reconnaissance."""

    def __init__(
        self,
        httpx_adapter: Optional[HTTPXAdapter] = None,
        subfinder_adapter: Optional[SubfinderAdapter] = None,
        ffuf_adapter: Optional[FfufAdapter] = None,
    ):
        super().__init__(name="recon-agent", role="Network & HTTP Reconnaissance")
        self.httpx = httpx_adapter or HTTPXAdapter()
        self.subfinder = subfinder_adapter or SubfinderAdapter()
        self.ffuf = ffuf_adapter

    def can_handle(self, event: BlackboardEvent) -> bool:
        return event.event_type == EventType.TARGET_REGISTERED

    def handle(
        self,
        event: BlackboardEvent,
        blackboard: Blackboard,
        scope: ScopeManifest,
    ) -> List[BlackboardEvent]:
        new_events: List[BlackboardEvent] = []
        target = event.target
        host = ScopeEngine.extract_host(target)

        # 1. If target is a root domain, run passive subdomain enumeration with Subfinder
        if "." in host and not host.replace(".", "").isdigit() and not host.startswith("localhost"):
            subfinder_result = self.subfinder.run(host, scope)
            for sub_asset in subfinder_result.discovered_assets:
                blackboard.add_asset(sub_asset)
                new_events.append(
                    BlackboardEvent(
                        event_type=EventType.HOST_DISCOVERED,
                        source_agent=self.name,
                        target=sub_asset.hostname or host,
                        payload={"source": "subfinder", "hostname": sub_asset.hostname},
                    )
                )

        # 2. Execute httpx tool adapter with Layer 3 scope verification
        result = self.httpx.run(target, scope)

        # Index discovered assets into the blackboard
        for asset in result.discovered_assets:
            blackboard.add_asset(asset)

            # Emit HOST_DISCOVERED
            if asset.ip or asset.hostname:
                new_events.append(
                    BlackboardEvent(
                        event_type=EventType.HOST_DISCOVERED,
                        source_agent=self.name,
                        target=asset.ip or asset.hostname or target,
                        payload={"asset_id": asset.id, "ports": [p.port for p in asset.ports]},
                    )
                )

            # Emit HTTP_ENDPOINT for each discovered web endpoint
            for ep in asset.endpoints:
                new_events.append(
                    BlackboardEvent(
                        event_type=EventType.HTTP_ENDPOINT,
                        source_agent=self.name,
                        target=ep.url,
                        payload={
                            "url": ep.url,
                            "status_code": ep.status_code,
                            "title": ep.title,
                            "tech_stack": ep.tech_stack,
                        },
                    )
                )

        # Index informational findings (e.g. tech stack fingerprints)
        for finding in result.findings:
            blackboard.add_finding(finding)
            new_events.append(
                BlackboardEvent(
                    event_type=EventType.TECH_DETECTED,
                    source_agent=self.name,
                    target=finding.target,
                    payload={"finding_id": finding.id, "title": finding.title},
                )
            )

        # 3. Web endpoint fuzzing with Ffuf if available
        if self.ffuf and target.startswith("http"):
            try:
                ffuf_res = self.ffuf.run(target, scope)
                for f_asset in ffuf_res.discovered_assets:
                    blackboard.add_asset(f_asset)
                    for ep in f_asset.endpoints:
                        new_events.append(
                            BlackboardEvent(
                                event_type=EventType.HTTP_ENDPOINT,
                                source_agent=self.name,
                                target=ep.url,
                                payload={"url": ep.url, "status_code": ep.status_code},
                            )
                        )
                for finding in ffuf_res.findings:
                    blackboard.add_finding(finding)
                    new_events.append(
                        BlackboardEvent(
                            event_type=EventType.VULNERABILITY_CANDIDATE,
                            source_agent=self.name,
                            target=finding.target,
                            payload={"finding": finding.model_dump(mode="json")},
                        )
                    )
            except Exception:
                pass

        return new_events
