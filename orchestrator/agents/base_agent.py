"""
REVENANT — Base Autonomous Security Agent
Abstract interface for specialist agents in the stigmergic multi-agent swarm.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import List

from control_plane.schemas.scope import ScopeManifest
from orchestrator.blackboard import Blackboard, BlackboardEvent

logger = logging.getLogger("revenant.agent")


class BaseAgent(ABC):
    """Abstract specialist agent."""

    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role

    @abstractmethod
    def can_handle(self, event: BlackboardEvent) -> bool:
        """Predicate checking if this agent triggers on the given event."""
        pass

    @abstractmethod
    def handle(
        self,
        event: BlackboardEvent,
        blackboard: Blackboard,
        scope: ScopeManifest,
    ) -> List[BlackboardEvent]:
        """
        Execute task in response to the event.
        Returns a list of new events to publish back to the blackboard.
        """
        pass
