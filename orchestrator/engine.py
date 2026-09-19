"""
REVENANT — Stigmergic Orchestrator Engine
Drives the autonomous multi-agent loop, dispatching events to specialist agents,
updating the shared blackboard state, and enforcing scope boundaries at Layer 2.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from control_plane.schemas.scope import ScopeEngine, ScopeManifest
from orchestrator.agents.ai_redteam_agent import AiRedTeamAgent
from orchestrator.agents.api_agent import ApiAgent
from orchestrator.agents.base_agent import BaseAgent
from orchestrator.agents.cloud_agent import CloudAgent
from orchestrator.agents.code_agent import CodeAgent
from orchestrator.agents.crawl_agent import CrawlAgent
from orchestrator.agents.dast_agent import DastAgent
from orchestrator.agents.identity_agent import IdentityAgent
from orchestrator.agents.mobile_agent import MobileAgent
from orchestrator.agents.purple_agent import PurpleAgent
from orchestrator.agents.recon_agent import ReconAgent
from orchestrator.agents.triage_agent import TriageAgent
from orchestrator.agents.web_agent import WebAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType

logger = logging.getLogger("revenant.orchestrator")


class Orchestrator:
    """Multi-agent campaign coordinator."""

    def __init__(
        self,
        blackboard: Optional[Blackboard] = None,
        agents: Optional[List[BaseAgent]] = None,
    ):
        self.blackboard = blackboard or Blackboard()
        self.agents: List[BaseAgent] = agents or [
            ReconAgent(),
            CrawlAgent(),
            WebAgent(),
            DastAgent(),
            ApiAgent(),
            CodeAgent(),
            CloudAgent(),
            IdentityAgent(),
            AiRedTeamAgent(),
            MobileAgent(),
            PurpleAgent(),
            TriageAgent(),
        ]

    def register_agent(self, agent: BaseAgent) -> None:
        """Register an additional specialist agent into the swarm."""
        self.agents.append(agent)

    def start_campaign(
        self,
        target: str,
        scope: ScopeManifest,
        max_iterations: int = 25,
    ) -> Dict[str, Any]:
        """
        Execute an autonomous red teaming campaign within authorized scope.
        Returns a summary report of discovered assets and confirmed findings.
        """
        # 1. LAYER 2 SCOPE ENFORCEMENT (Orchestrator Pre-flight Gate)
        scope_engine = ScopeEngine(scope)
        scope_engine.validate_or_raise(target)

        # 2. Seed the blackboard with the initial target
        seed_event = BlackboardEvent(
            event_type=EventType.TARGET_REGISTERED,
            source_agent="orchestrator",
            target=target,
            payload={"initial_target": target},
        )
        self.blackboard.post_event(seed_event)

        # 3. Autonomous Stigmergic Loop
        iteration = 0
        while iteration < max_iterations:
            iteration += 1
            events_processed_this_cycle = 0

            for agent in self.agents:
                unhandled = self.blackboard.get_unhandled_events(agent.name)
                for event in unhandled:
                    # Mark handled so this agent doesn't re-process the exact same event
                    self.blackboard.mark_handled(event.id, agent.name)

                    if agent.can_handle(event):
                        events_processed_this_cycle += 1
                        try:
                            # Agent executes its tool / analysis
                            new_events = agent.handle(event, self.blackboard, scope)
                            for ne in new_events:
                                self.blackboard.post_event(ne)
                        except Exception as e:
                            logger.error(f"Agent {agent.name} encountered error: {e}", exc_info=True)

            # If no agent acted on any event this cycle, the swarm has quiesced
            if events_processed_this_cycle == 0:
                break

        # 4. Campaign Completion
        complete_event = BlackboardEvent(
            event_type=EventType.CAMPAIGN_COMPLETE,
            source_agent="orchestrator",
            target=target,
            payload={"iterations": iteration},
        )
        self.blackboard.post_event(complete_event)

        # 5. Return campaign results summary
        summary = self.blackboard.get_summary()
        summary["iterations_run"] = iteration
        summary["quiesced"] = (iteration < max_iterations)
        return summary
