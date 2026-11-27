"""
REVENANT — Stigmergic Orchestrator Engine
Drives the autonomous multi-agent loop, dispatching events to specialist agents,
updating the shared blackboard state, and enforcing scope boundaries at Layer 2.
"""

from __future__ import annotations

import importlib
import logging
from typing import Any, Callable, Dict, List, Optional
from control_plane.schemas.scope import ScopeEngine, ScopeManifest
from orchestrator.agents.base_agent import BaseAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType

logger = logging.getLogger("revenant.orchestrator")


def _agent(module: str, cls: str) -> Callable[[], BaseAgent]:
    """Return a thunk that imports and constructs an agent only when first needed.

    Agent modules are heavy (each pulls in its domain's adapters), so we import
    lazily: a `recon` run never imports the cloud/identity/malware stacks.
    """
    return lambda: getattr(importlib.import_module(f"orchestrator.agents.{module}"), cls)()


# profile agent-name -> lazy constructor. Keys match MissionProfile.active_agents.
AGENT_REGISTRY: Dict[str, Callable[[], BaseAgent]] = {
    "recon": _agent("recon_agent", "ReconAgent"),
    "crawl": _agent("crawl_agent", "CrawlAgent"),
    "web": _agent("web_agent", "WebAgent"),
    "dast": _agent("dast_agent", "DastAgent"),
    "api": _agent("api_agent", "ApiAgent"),
    "code": _agent("code_agent", "CodeAgent"),
    "cloud": _agent("cloud_agent", "CloudAgent"),
    "identity": _agent("identity_agent", "IdentityAgent"),
    "ai": _agent("ai_redteam_agent", "AiRedTeamAgent"),
    "ai-redteam": _agent("ai_redteam_agent", "AiRedTeamAgent"),
    "mobile": _agent("mobile_agent", "MobileAgent"),
    "purple": _agent("purple_agent", "PurpleAgent"),
    "triage": _agent("triage_agent", "TriageAgent"),
    "kubernetes": _agent("kubernetes_agent", "KubernetesAgent"),
    "forensics": _agent("forensics_agent", "ForensicsAgent"),
    "malware": _agent("malware_agent", "MalwareAgent"),
    "firmware": _agent("firmware_agent", "FirmwareAgent"),
}

# Swarm built when no explicit agents/profile are supplied (preserves prior behavior).
DEFAULT_AGENTS: List[str] = [
    "recon", "crawl", "web", "dast", "api", "code",
    "cloud", "identity", "ai", "mobile", "purple", "triage",
]


def build_agents(active_agents: List[str]) -> List[BaseAgent]:
    """Instantiate only the named agents, in order, skipping unknown names."""
    agents: List[BaseAgent] = []
    for name in active_agents:
        factory = AGENT_REGISTRY.get(str(name).lower().strip())
        if factory is None:
            logger.warning("Unknown agent '%s' requested; skipping.", name)
            continue
        agents.append(factory())
    return agents


class Orchestrator:
    """Multi-agent campaign coordinator."""

    def __init__(
        self,
        blackboard: Optional[Blackboard] = None,
        agents: Optional[List[BaseAgent]] = None,
        active_agents: Optional[List[str]] = None,
    ):
        self.blackboard = blackboard or Blackboard()
        if agents is not None:
            self.agents: List[BaseAgent] = agents
        else:
            self.agents = build_agents(active_agents or DEFAULT_AGENTS)
            if not self.agents:
                # Every requested agent was unknown; fall back to the full default swarm.
                self.agents = build_agents(DEFAULT_AGENTS)

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
