"""
REVENANT — Continuous Attack Surface Management (ASM) Daemon
Autonomous background monitoring daemon that:
1. Manages continuous discovery cycles across registered attack surface assets
2. Detects asset and vulnerability state drift (new vulnerabilities, resolved findings, changed attack surfaces)
3. Automatically triggers RemediationEngine and SOAR notification dispatch on critical drift
4. Re-computes attack graphs to maintain living adversary paths
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Dict, List, Optional, Set

from control_plane.schemas.models import Finding, HostAsset, Severity
from orchestrator.blackboard import BlackboardEvent, EventType, StigmergicBlackboard
from orchestrator.correlation.attack_graph_engine import AttackGraphEngine
from orchestrator.remediation.remediation_engine import RemediationArtifact, RemediationEngine
from adapters.soar.webhook_adapter import SOARPlatform, SOARWebhookAdapter

logger = logging.getLogger("revenant.orchestrator.asm")


class DriftReport:
    """Report detailing security posture delta between assessment cycles."""

    def __init__(
        self,
        new_findings: List[Finding],
        resolved_findings: List[Finding],
        persistent_findings: List[Finding],
    ):
        self.new_findings = new_findings
        self.resolved_findings = resolved_findings
        self.persistent_findings = persistent_findings

    @property
    def has_critical_drift(self) -> bool:
        return any(f.severity in [Severity.CRITICAL, Severity.HIGH] for f in self.new_findings)

    def summary(self) -> Dict[str, int]:
        return {
            "new_count": len(self.new_findings),
            "resolved_count": len(self.resolved_findings),
            "persistent_count": len(self.persistent_findings),
        }


class ASMDaemon:
    """Continuous attack surface management orchestrator."""

    def __init__(
        self,
        blackboard: Optional[StigmergicBlackboard] = None,
        poll_interval_seconds: int = 300,
        soar_url: Optional[str] = None,
        soar_platform: SOARPlatform = SOARPlatform.GENERIC,
        soar_secret: Optional[str] = None,
    ):
        self.blackboard = blackboard or StigmergicBlackboard()
        self.poll_interval = poll_interval_seconds
        self.soar_url = soar_url
        self.soar_platform = soar_platform
        self.soar_secret = soar_secret

        self.remediation_engine = RemediationEngine()
        self.soar_adapter = SOARWebhookAdapter()
        self.attack_graph_engine = AttackGraphEngine()

        self._registered_targets: List[str] = []
        self._baseline_findings: Dict[str, Finding] = {}
        self._is_running = False
        self._cycle_count = 0

    def register_target(self, target: str) -> None:
        """Add asset/target to continuous attack surface scope."""
        if target not in self._registered_targets:
            self._registered_targets.append(target)
            logger.info(f"ASM: Registered continuous target: {target}")

    def detect_drift(self, current_findings: List[Finding]) -> DriftReport:
        """Compare current findings against historical baseline to detect security posture delta."""
        current_map = {f.id or f.title: f for f in current_findings}

        new_findings: List[Finding] = []
        for fid, f in current_map.items():
            if fid not in self._baseline_findings:
                new_findings.append(f)

        resolved_findings: List[Finding] = []
        for fid, f in self._baseline_findings.items():
            if fid not in current_map:
                resolved_findings.append(f)

        persistent_findings: List[Finding] = []
        for fid, f in current_map.items():
            if fid in self._baseline_findings:
                persistent_findings.append(f)

        # Update baseline
        self._baseline_findings = current_map

        return DriftReport(
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            persistent_findings=persistent_findings,
        )

    def execute_cycle(self, simulated_cycle_findings: Optional[List[Finding]] = None) -> Dict[str, Any]:
        """
        Execute one complete ASM cycle:
        1. Query blackboard or cycle findings
        2. Detect posture drift
        3. Trigger automated remediation for new critical/high findings
        4. Dispatch SOAR notifications if configured
        5. Re-compute attack graphs
        """
        self._cycle_count += 1
        logger.info(f"ASM: Starting assessment cycle #{self._cycle_count}")

        # Gather findings from input or blackboard state
        findings: List[Finding] = simulated_cycle_findings or []
        if not findings:
            for ev in self.blackboard.get_events(EventType.VULNERABILITY_CONFIRMED):
                if isinstance(ev.payload, dict) and "finding" in ev.payload:
                    try:
                        f_data = ev.payload["finding"]
                        if isinstance(f_data, dict):
                            findings.append(Finding(**f_data))
                        elif isinstance(f_data, Finding):
                            findings.append(f_data)
                    except Exception as e:
                        logger.debug(f"Could not parse finding from blackboard event: {e}")

        # 2. Detect Drift
        drift = self.detect_drift(findings)
        logger.info(f"ASM Cycle #{self._cycle_count} Drift Summary: {drift.summary()}")

        # 3. Autonomous Remediation for New Findings
        generated_artifacts: List[RemediationArtifact] = []
        if drift.new_findings:
            generated_artifacts = self.remediation_engine.remediate_campaign(drift.new_findings)
            logger.info(f"ASM: Generated {len(generated_artifacts)} autonomous remediation artifacts.")

        # 4. SOAR Dispatch on Critical Drift
        soar_result = None
        if self.soar_url and drift.has_critical_drift:
            soar_result = self.soar_adapter.dispatch(
                endpoint_url=self.soar_url,
                platform=self.soar_platform,
                event_title=f"ASM Cycle #{self._cycle_count} - New Critical Assets / Findings Detected",
                findings=drift.new_findings,
                secret=self.soar_secret,
                metadata={"cycle": self._cycle_count, "targets": self._registered_targets},
            )

        # 5. Attack Graph Synthesis
        graph = self.attack_graph_engine.build_graph(assets=[], findings=findings)

        return {
            "cycle": self._cycle_count,
            "drift": drift.summary(),
            "has_critical_drift": drift.has_critical_drift,
            "remediation_artifacts_count": len(generated_artifacts),
            "remediation_artifacts": generated_artifacts,
            "attack_graph_nodes": len(graph.nodes),
            "attack_graph_edges": len(graph.edges),
            "soar_result": soar_result,
        }

    async def run_daemon(self, max_cycles: Optional[int] = None) -> None:
        """Run continuous ASM loop asynchronously."""
        self._is_running = True
        cycles = 0
        while self._is_running:
            self.execute_cycle()
            cycles += 1
            if max_cycles and cycles >= max_cycles:
                break
            await asyncio.sleep(self.poll_interval)

    def stop(self) -> None:
        """Stop background daemon loop."""
        self._is_running = False
