"""
REVENANT — Specialist Code & Secret Audit Agent
Triggers on TARGET_REGISTERED (repo/directory paths) or REPO_DISCOVERED events,
dispatches Gitleaks, TruffleHog, and Semgrep, and publishes SECRET_EXPOSED and
VULNERABILITY_CANDIDATE events to the blackboard.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

from adapters.sast.gitleaks_adapter import GitleaksAdapter
from adapters.sast.semgrep_adapter import SemgrepAdapter
from adapters.sast.trufflehog_adapter import TruffleHogAdapter
from control_plane.schemas.scope import ScopeManifest
from orchestrator.agents.base_agent import BaseAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType


class CodeAgent(BaseAgent):
    """Specialist agent for static code analysis, SAST, and secret harvesting."""

    def __init__(
        self,
        gitleaks_adapter: Optional[GitleaksAdapter] = None,
        trufflehog_adapter: Optional[TruffleHogAdapter] = None,
        semgrep_adapter: Optional[SemgrepAdapter] = None,
    ):
        super().__init__(name="code-agent", role="Source Code & Secret Auditing")
        self.gitleaks = gitleaks_adapter or GitleaksAdapter()
        self.trufflehog = trufflehog_adapter or TruffleHogAdapter()
        self.semgrep = semgrep_adapter or SemgrepAdapter()

    def can_handle(self, event: BlackboardEvent) -> bool:
        if event.event_type == EventType.REPO_DISCOVERED:
            return True

        if event.event_type == EventType.TARGET_REGISTERED:
            target = event.target
            # Check if target is a filesystem directory, file, or repo
            if os.path.exists(target) or target.endswith(".git") or "repo" in target.lower():
                return True
            if event.payload.get("target_type") in ["REPO", "FILE"]:
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

        # 1. Execute Gitleaks secret scanner
        gitleaks_res = self.gitleaks.run(target, scope)
        for asset in gitleaks_res.discovered_assets:
            blackboard.add_asset(asset)

        for finding in gitleaks_res.findings:
            new_events.append(
                BlackboardEvent(
                    event_type=EventType.SECRET_EXPOSED,
                    source_agent=self.name,
                    target=finding.target,
                    payload={"finding": finding.model_dump(mode="json")},
                )
            )

        # 2. Execute TruffleHog deep credential & entropy scanner
        trufflehog_res = self.trufflehog.run(target, scope)
        for asset in trufflehog_res.discovered_assets:
            blackboard.add_asset(asset)

        for finding in trufflehog_res.findings:
            new_events.append(
                BlackboardEvent(
                    event_type=EventType.SECRET_EXPOSED,
                    source_agent=self.name,
                    target=finding.target,
                    payload={"finding": finding.model_dump(mode="json")},
                )
            )

        # 3. Execute Semgrep / AST static code analysis
        semgrep_res = self.semgrep.run(target, scope)
        for asset in semgrep_res.discovered_assets:
            blackboard.add_asset(asset)

        for finding in semgrep_res.findings:
            new_events.append(
                BlackboardEvent(
                    event_type=EventType.VULNERABILITY_CANDIDATE,
                    source_agent=self.name,
                    target=finding.target,
                    payload={"finding": finding.model_dump(mode="json")},
                )
            )

        return new_events
