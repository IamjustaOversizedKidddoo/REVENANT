"""REVENANT — LLM Planner Agent (in-swarm reasoning).

An opt-in specialist that reasons over the current blackboard state and proposes the
single best next action. It triggers on high-signal events (confirmed vulns,
misconfigurations, privilege-escalation paths, new HTTP endpoints) and on
CAMPAIGN_COMPLETE for a final plan.

Safety:
    * It NEVER invents new targets. Any suggested event it emits must reference an asset
      already on the blackboard and within the authorized scope — the orchestrator's
      existing 3-layer scope gate still applies to whatever it posts.
    * It rate-limits itself to ``REVENANT_PLANNER_BUDGET`` reasoning calls per campaign
      to control cost.
    * With no LLM configured it degrades to a deterministic heuristic recommendation and
      never raises.

The plan is recorded as an informational :class:`Finding` so it lands in the report.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

from control_plane.schemas.models import Finding, Severity
from control_plane.schemas.scope import ScopeEngine, ScopeManifest
from orchestrator.agents.base_agent import BaseAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType

logger = logging.getLogger("revenant.agent.planner")

DEFAULT_BUDGET = 5

TRIGGER_EVENTS = {
    EventType.VULNERABILITY_CONFIRMED,
    EventType.AI_VULNERABILITY_CONFIRMED,
    EventType.MISCONFIGURATION_DETECTED,
    EventType.PRIVILEGE_ESCALATION_PATH_DETECTED,
    EventType.HTTP_ENDPOINT,
    EventType.CAMPAIGN_COMPLETE,
}


def _planner_budget() -> int:
    try:
        return max(0, int(os.environ.get("REVENANT_PLANNER_BUDGET", "").strip() or DEFAULT_BUDGET))
    except (TypeError, ValueError):
        return DEFAULT_BUDGET


class LlmPlannerAgent(BaseAgent):
    """Autonomous reasoning & next-action planning agent."""

    def __init__(self, llm_client: Optional[Any] = None, budget: Optional[int] = None):
        super().__init__(name="llm-planner", role="Autonomous reasoning & next-action planning")
        self.budget = budget if budget is not None else _planner_budget()
        self._calls = 0
        # Lazy default client; injectable for tests. Imported here to keep the agent
        # importable even if the intelligence package layout changes.
        if llm_client is not None:
            self.llm = llm_client
        else:
            from intelligence.llm_client import LlmClient

            self.llm = LlmClient()

    # -- triggering --------------------------------------------------------

    def can_handle(self, event: BlackboardEvent) -> bool:
        if self._calls >= self.budget:
            return False
        return event.event_type in TRIGGER_EVENTS

    # -- reasoning ---------------------------------------------------------

    def handle(
        self,
        event: BlackboardEvent,
        blackboard: Blackboard,
        scope: ScopeManifest,
    ) -> List[BlackboardEvent]:
        # Budget guard (defensive — can_handle already checks).
        if self._calls >= self.budget:
            return []
        self._calls += 1

        state = self._snapshot(blackboard)
        plan = self._reason(state, event)

        # Record the plan as an informational finding so it reaches the report.
        note = Finding(
            title=f"[AI Planner] {plan.get('recommended_action', 'Next-action recommendation')}",
            description=(
                f"Reasoning: {plan.get('reasoning', '')}\n"
                f"Expected outcome: {plan.get('expected_outcome', '')}\n"
                f"Downstream risk: {plan.get('downstream_risk', '')}"
            ),
            severity=Severity.INFO,
            target=event.target or state.get("target", ""),
            tool="llm-planner",
            remediation=plan.get("recommended_action"),
            raw_data={"plan": plan, "trigger_event": event.event_type.value, "mode": plan.get("mode")},
        )
        blackboard.add_finding(note)

        new_events: List[BlackboardEvent] = []

        # Optionally emit a suggested event — ONLY if it references an in-scope asset
        # that already exists on the blackboard. The orchestrator re-validates scope.
        suggested = plan.get("suggested_event")
        if suggested:
            ev = self._safe_suggested_event(suggested, blackboard, scope)
            if ev is not None:
                new_events.append(ev)

        return new_events

    # -- helpers -----------------------------------------------------------

    def _snapshot(self, blackboard: Blackboard) -> Dict[str, Any]:
        findings = blackboard.get_findings()
        assets = blackboard.get_assets()
        asset_targets = []
        for a in assets:
            if a.hostname:
                asset_targets.append(a.hostname)
            if a.ip:
                asset_targets.append(a.ip)
            for ep in a.endpoints:
                asset_targets.append(ep.url)
        summary = blackboard.get_summary()
        return {
            "target": summary.get("campaign_id", ""),
            "summary": summary,
            "asset_targets": sorted(set(asset_targets)),
            "findings": [
                {
                    "title": f.title,
                    "severity": getattr(f.severity, "value", f.severity),
                    "endpoint": f.endpoint or f.target,
                    "cwe": f.cwe,
                }
                for f in findings
            ],
        }

    def _reason(self, state: Dict[str, Any], event: BlackboardEvent) -> Dict[str, Any]:
        """Return a structured plan dict. LLM path, with deterministic fallback."""
        if getattr(self.llm, "available", lambda: False)():
            try:
                return self._reason_llm(state, event)
            except Exception as exc:  # LLMUnavailable or any SDK/network error
                logger.info("Planner LLM path unavailable (%s); using heuristic.", exc)
        return self._reason_heuristic(state, event)

    def _reason_llm(self, state: Dict[str, Any], event: BlackboardEvent) -> Dict[str, Any]:
        from intelligence.llm_client import LLMUnavailable

        system = (
            "You are the reasoning core of an autonomous, AUTHORIZED red-team swarm. Given the "
            "current blackboard state and the allowed scope, decide the SINGLE best next action. "
            "You may only reference assets already present in asset_targets — never invent new "
            "hosts, domains, or endpoints. Respond with ONE JSON object and nothing else."
        )
        schema = (
            '{"reasoning": str, "recommended_action": str, "expected_outcome": str, '
            '"downstream_risk": str, "suggested_event": null | '
            '{"event_type": str, "target": str (must be in asset_targets)}}'
        )
        user = (
            f"Triggering event: {event.event_type.value} on {event.target}\n\n"
            f"State:\n{json.dumps(state, indent=2)}\n\n"
            f"Return JSON matching exactly:\n{schema}\nJSON only."
        )
        raw = self.llm.complete(system, user)
        data = _extract_json(raw)
        if not isinstance(data, dict) or "recommended_action" not in data:
            raise LLMUnavailable("Planner response was not valid plan JSON.")
        data.setdefault("reasoning", "")
        data.setdefault("expected_outcome", "")
        data.setdefault("downstream_risk", "")
        data.setdefault("suggested_event", None)
        data["mode"] = "llm"
        return data

    def _reason_heuristic(self, state: Dict[str, Any], event: BlackboardEvent) -> Dict[str, Any]:
        """Deterministic, free next-action recommendation — never raises."""
        findings = state.get("findings", [])
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        actionable = sorted(
            (f for f in findings if f["severity"] in ("CRITICAL", "HIGH")),
            key=lambda f: sev_rank.get(f["severity"], 9),
        )
        if event.event_type == EventType.CAMPAIGN_COMPLETE:
            return {
                "reasoning": f"Campaign quiesced with {len(findings)} findings; "
                f"{len(actionable)} are high/critical.",
                "recommended_action": "Validate and remediate the high/critical findings, then re-scan to confirm closure."
                if actionable
                else "No high-severity findings; broaden coverage with an authorized full-spectrum pass.",
                "expected_outcome": "Prioritized remediation backlog with verification plan.",
                "downstream_risk": "Low — analysis and scoped re-testing only.",
                "suggested_event": None,
                "mode": "heuristic",
            }
        if actionable:
            top = actionable[0]
            return {
                "reasoning": f"Highest-impact open finding is {top['title']} ({top['severity']}) at {top['endpoint']}.",
                "recommended_action": f"Deepen exploitation safety-check on {top['title']} at {top['endpoint']} to confirm blast radius.",
                "expected_outcome": "Confirmed impact and evidence for the remediation ticket.",
                "downstream_risk": "Low — non-destructive verification within scope.",
                "suggested_event": None,
                "mode": "heuristic",
            }
        return {
            "reasoning": f"Event {event.event_type.value} observed; no high-severity findings yet.",
            "recommended_action": "Continue enumeration on discovered endpoints to expand the tested surface.",
            "expected_outcome": "Additional parameters/endpoints for injection testing.",
            "downstream_risk": "Low — passive/active enumeration within scope.",
            "suggested_event": None,
            "mode": "heuristic",
        }

    def _safe_suggested_event(
        self,
        suggested: Dict[str, Any],
        blackboard: Blackboard,
        scope: ScopeManifest,
    ) -> Optional[BlackboardEvent]:
        """Build a BlackboardEvent from a suggestion only if it is in-scope & known."""
        if not isinstance(suggested, dict):
            return None
        target = str(suggested.get("target") or "").strip()
        raw_type = str(suggested.get("event_type") or "").strip()
        if not target or not raw_type:
            return None

        # The suggested target MUST already be an asset on the board (no new targets).
        state = self._snapshot(blackboard)
        if target not in state["asset_targets"]:
            logger.info("Planner suggested unknown target %r; dropping.", target)
            return None

        # Must be a real EventType.
        try:
            event_type = EventType(raw_type)
        except ValueError:
            logger.info("Planner suggested unknown event_type %r; dropping.", raw_type)
            return None

        # Must survive the scope engine (defense in depth; orchestrator checks too).
        try:
            ScopeEngine(scope).validate_or_raise(target)
        except Exception as exc:
            logger.info("Planner suggestion for %r failed scope gate (%s); dropping.", target, exc)
            return None

        return BlackboardEvent(
            event_type=event_type,
            source_agent=self.name,
            target=target,
            payload={"suggested_by": "llm-planner", "rationale": suggested.get("rationale", "")},
        )


def _extract_json(text: str) -> Any:
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    return None
