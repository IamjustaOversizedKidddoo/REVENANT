"""Unit tests for the in-swarm LLM Planner agent (orchestrator.agents.llm_planner_agent).

All LLM access is mocked; nothing hits the network. Covers the BaseAgent contract,
triggering, the deterministic heuristic fallback, the per-campaign call budget, and the
scope-safety guard (no new / out-of-scope targets).
"""
from __future__ import annotations

import json

import pytest

from control_plane.schemas.models import Finding, HostAsset, Severity
from control_plane.schemas.scope import ScopeManifest
from orchestrator.agents.base_agent import BaseAgent
from orchestrator.agents.llm_planner_agent import LlmPlannerAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType


class _OfflineLLM:
    model = "offline-test"

    def available(self) -> bool:
        return False

    def complete(self, system, user):  # pragma: no cover
        raise AssertionError("LLM must not be called when unavailable")


class _ScriptedLLM:
    """Available LLM returning a fixed JSON plan — for the suggested-event tests."""

    model = "scripted-test"

    def __init__(self, payload: dict):
        self._payload = payload
        self.calls = 0

    def available(self) -> bool:
        return True

    def complete(self, system, user):
        self.calls += 1
        return json.dumps(self._payload)


def _blackboard_with_state():
    bb = Blackboard()
    bb.add_asset(HostAsset(ip="127.0.0.1", hostname="localhost"))
    bb.add_finding(Finding(
        title="SQL Injection in 'username'",
        description="injectable",
        severity=Severity.CRITICAL,
        target="127.0.0.1",
        tool="dast-fuzzer",
        cwe="CWE-89",
        endpoint="http://127.0.0.1:3000/login",
    ))
    return bb


def _scope():
    return ScopeManifest(allowed_hosts=["127.0.0.1", "localhost"], allowed_cidrs=["127.0.0.1/32"])


def _trigger_event():
    return BlackboardEvent(
        event_type=EventType.VULNERABILITY_CONFIRMED,
        source_agent="triage-agent",
        target="127.0.0.1",
        payload={"title": "SQL Injection"},
    )


def test_follows_base_agent_contract():
    agent = LlmPlannerAgent(llm_client=_OfflineLLM())
    assert isinstance(agent, BaseAgent)
    assert agent.name == "llm-planner"
    assert agent.role


def test_can_handle_matches_high_signal_events_only():
    agent = LlmPlannerAgent(llm_client=_OfflineLLM())
    for et in (
        EventType.VULNERABILITY_CONFIRMED,
        EventType.MISCONFIGURATION_DETECTED,
        EventType.PRIVILEGE_ESCALATION_PATH_DETECTED,
        EventType.HTTP_ENDPOINT,
        EventType.CAMPAIGN_COMPLETE,
    ):
        ev = BlackboardEvent(event_type=et, source_agent="x", target="127.0.0.1")
        assert agent.can_handle(ev) is True
    # A low-signal event must not trigger it.
    noise = BlackboardEvent(event_type=EventType.PORT_OPEN, source_agent="x", target="127.0.0.1")
    assert agent.can_handle(noise) is False


def test_handle_without_llm_returns_heuristic_and_records_note():
    bb = _blackboard_with_state()
    agent = LlmPlannerAgent(llm_client=_OfflineLLM())
    before = len(bb.get_findings())

    out = agent.handle(_trigger_event(), bb, _scope())

    # Never raises, emits no out-of-scope events.
    assert out == []
    # Plan recorded as an informational finding.
    findings = bb.get_findings()
    assert len(findings) == before + 1
    note = next(f for f in findings if f.tool == "llm-planner")
    assert note.severity == Severity.INFO
    assert note.raw_data["plan"]["mode"] == "heuristic"
    assert note.raw_data["plan"]["recommended_action"]


def test_respects_per_campaign_budget():
    bb = _blackboard_with_state()
    agent = LlmPlannerAgent(llm_client=_OfflineLLM(), budget=1)
    ev = _trigger_event()

    assert agent.can_handle(ev) is True
    agent.handle(ev, bb, _scope())          # consumes the single call
    assert agent.can_handle(ev) is False     # budget exhausted
    # A defensive second handle must still be safe and add nothing.
    before = len(bb.get_findings())
    assert agent.handle(ev, bb, _scope()) == []
    assert len(bb.get_findings()) == before


def test_suggested_event_out_of_scope_target_is_dropped():
    bb = _blackboard_with_state()
    # LLM suggests probing a target that is NOT an asset on the board.
    llm = _ScriptedLLM({
        "reasoning": "r",
        "recommended_action": "probe",
        "expected_outcome": "o",
        "downstream_risk": "low",
        "suggested_event": {"event_type": "HTTP_ENDPOINT", "target": "10.9.9.9"},
    })
    agent = LlmPlannerAgent(llm_client=llm, budget=3)
    out = agent.handle(_trigger_event(), bb, _scope())
    assert llm.calls == 1
    assert out == [], "an unknown/out-of-scope target must never be emitted"


def test_suggested_event_in_scope_known_asset_is_emitted():
    bb = _blackboard_with_state()
    llm = _ScriptedLLM({
        "reasoning": "r",
        "recommended_action": "probe login",
        "expected_outcome": "o",
        "downstream_risk": "low",
        "suggested_event": {"event_type": "HTTP_ENDPOINT", "target": "127.0.0.1"},
    })
    agent = LlmPlannerAgent(llm_client=llm, budget=3)
    out = agent.handle(_trigger_event(), bb, _scope())
    assert len(out) == 1
    assert out[0].target == "127.0.0.1"
    assert out[0].source_agent == "llm-planner"


def test_campaign_complete_produces_final_plan():
    bb = _blackboard_with_state()
    agent = LlmPlannerAgent(llm_client=_OfflineLLM())
    ev = BlackboardEvent(event_type=EventType.CAMPAIGN_COMPLETE, source_agent="orchestrator", target="127.0.0.1")
    agent.handle(ev, bb, _scope())
    note = next(f for f in bb.get_findings() if f.tool == "llm-planner")
    assert "remediate" in note.raw_data["plan"]["recommended_action"].lower()
