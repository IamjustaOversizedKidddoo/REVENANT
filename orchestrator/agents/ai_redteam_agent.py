"""
REVENANT — Specialist Generative AI & LLM Red Teaming Agent
Autonomous agent subscribing to AI_ENDPOINT_DISCOVERED, HTTP_ENDPOINT, and TARGET_REGISTERED
events targeting conversational APIs and LLM services. Dispatches NativeAiProbeAdapter,
PromptfooAdapter, and GarakAdapter to systematically assess OWASP Top 10 for LLMs.
"""

from __future__ import annotations

import logging
from typing import List, Optional
from urllib.parse import urlparse

from adapters.ai.garak_adapter import GarakAdapter
from adapters.ai.native_probe_adapter import NativeAiProbeAdapter
from adapters.ai.promptfoo_adapter import PromptfooAdapter
from control_plane.schemas.models import Finding, Severity
from control_plane.schemas.scope import ScopeManifest
from orchestrator.agents.base_agent import BaseAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType

logger = logging.getLogger("revenant.agents.ai_redteam")

# Typical AI / LLM service path patterns
AI_ENDPOINT_PATHS = [
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/messages",
    "/api/generate",
    "/api/chat",
    "/api/agent",
    "/chat",
    "/query",
    "/ask",
    "/predict",
]


class AiRedTeamAgent(BaseAgent):
    """Specialist agent for AI, LLM application, and autonomous agent red teaming."""

    def __init__(
        self,
        native_probe_adapter: Optional[NativeAiProbeAdapter] = None,
        promptfoo_adapter: Optional[PromptfooAdapter] = None,
        garak_adapter: Optional[GarakAdapter] = None,
    ):
        super().__init__(name="ai-redteam-agent", role="Generative AI & LLM Red Teaming")
        self.native_probe = native_probe_adapter or NativeAiProbeAdapter()
        self.promptfoo = promptfoo_adapter or PromptfooAdapter()
        self.garak = garak_adapter or GarakAdapter()

    def can_handle(self, event: BlackboardEvent) -> bool:
        """Evaluate if the blackboard event involves an AI / LLM endpoint or target."""
        if event.event_type in [EventType.AI_ENDPOINT_DISCOVERED]:
            return True

        target_str = str(event.target).lower()
        payload = event.payload or {}
        tags = [str(t).lower() for t in payload.get("tags", [])]

        # 1. Target registered as AI asset
        if event.event_type == EventType.TARGET_REGISTERED:
            target_type = str(payload.get("target_type", "")).upper()
            if target_type in ["AI_ENDPOINT", "AI_MODEL", "LLM", "GENAI"]:
                return True
            if any(tag in ["ai", "llm", "genai", "gpt", "rag", "chatbot"] for tag in tags):
                return True
            if any(path in target_str for path in AI_ENDPOINT_PATHS):
                return True

        # 2. HTTP endpoint discovered matching AI signatures
        if event.event_type == EventType.HTTP_ENDPOINT:
            if any(tag in ["ai", "llm", "genai"] for tag in tags):
                return True
            if any(path in target_str for path in AI_ENDPOINT_PATHS):
                return True
            if payload.get("service") in ["llm", "ai", "ollama", "openai"]:
                return True

        # 3. Host discovered with AI tags or ports (e.g. 11434 for Ollama, 8000/8080 for inference servers)
        if event.event_type == EventType.HOST_DISCOVERED:
            if any(tag in ["ai", "llm", "genai"] for tag in tags):
                return True

        return False

    def handle(
        self, event: BlackboardEvent, blackboard: Blackboard, scope_manifest: ScopeManifest
    ) -> List[BlackboardEvent]:
        """Execute the multi-tier AI red teaming cascade against the target."""
        target = event.target
        logger.info("[AiRedTeamAgent] Activated for target: %s", target)
        out_events: List[BlackboardEvent] = []

        all_findings: List[Finding] = []

        # 1. Tier 1: Native Adversarial Probing (OWASP LLM Top 10 heuristics)
        try:
            logger.info("[AiRedTeamAgent] Executing NativeAiProbeAdapter on %s", target)
            probe_result = self.native_probe.run(target, scope_manifest)
            for f in probe_result.findings:
                blackboard.add_finding(f)
                all_findings.append(f)
            for a in probe_result.discovered_assets:
                blackboard.add_asset(a)
        except Exception as e:
            logger.warning("[AiRedTeamAgent] Native AI probe failed on %s: %s", target, e)

        # 2. Tier 2: Promptfoo evaluation (if installed, or if specified in payload)
        if self.promptfoo.is_installed() or event.payload.get("use_promptfoo"):
            try:
                logger.info("[AiRedTeamAgent] Executing PromptfooAdapter on %s", target)
                pf_result = self.promptfoo.run(target, scope_manifest)
                for f in pf_result.findings:
                    blackboard.add_finding(f)
                    all_findings.append(f)
                for a in pf_result.discovered_assets:
                    blackboard.add_asset(a)
            except Exception as e:
                logger.warning("[AiRedTeamAgent] Promptfoo evaluation failed on %s: %s", target, e)

        # 3. Tier 3: Garak scanner (if installed or requested)
        if self.garak.is_installed() or event.payload.get("use_garak"):
            try:
                logger.info("[AiRedTeamAgent] Executing GarakAdapter on %s", target)
                garak_result = self.garak.run(target, scope_manifest)
                for f in garak_result.findings:
                    blackboard.add_finding(f)
                    all_findings.append(f)
                for a in garak_result.discovered_assets:
                    blackboard.add_asset(a)
            except Exception as e:
                logger.warning("[AiRedTeamAgent] Garak scan failed on %s: %s", target, e)

        # Emit confirmation events for discovered vulnerabilities
        for finding in all_findings:
            out_ev = BlackboardEvent(
                event_type=EventType.AI_VULNERABILITY_CONFIRMED,
                source_agent=self.name,
                target=target,
                payload={
                    "finding_id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "cwe": finding.cwe,
                    "owasp_category": finding.owasp_category,
                    "mitre_attack_ids": finding.mitre_attack_ids,
                },
            )
            blackboard.post_event(out_ev)
            out_events.append(out_ev)

            # Also emit generic VULNERABILITY_CONFIRMED so AttackGraphEngine captures it
            gen_ev = BlackboardEvent(
                event_type=EventType.VULNERABILITY_CONFIRMED,
                source_agent=self.name,
                target=target,
                payload={
                    "finding_id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "cwe": finding.cwe,
                },
            )
            blackboard.post_event(gen_ev)
            out_events.append(gen_ev)

        logger.info(
            "[AiRedTeamAgent] Completed audit for %s. Total AI findings: %d",
            target,
            len(all_findings),
        )
        return out_events
