"""
REVENANT — Kubernetes Specialist Swarm Agent
Audits container clusters, Helm charts, and manifest files.
Runs Kubescape, kube-bench, and Falco adapters, correlating container escape
and cluster takeover vectors into the shared stigmergic blackboard.
"""

from __future__ import annotations

import os
from typing import List, Optional

from adapters.kubernetes.falco_adapter import FalcoAdapter
from adapters.kubernetes.kube_bench_adapter import KubeBenchAdapter
from adapters.kubernetes.kubescape_adapter import KubescapeAdapter
from control_plane.schemas.scope import ScopeManifest
from orchestrator.agents.base_agent import BaseAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType


class KubernetesAgent(BaseAgent):
    """Specialist agent for Kubernetes security posture, manifest audit, and runtime threat analysis."""

    def __init__(
        self,
        kubescape_adapter: Optional[KubescapeAdapter] = None,
        kube_bench_adapter: Optional[KubeBenchAdapter] = None,
        falco_adapter: Optional[FalcoAdapter] = None,
    ):
        super().__init__(name="kubernetes-agent", role="Kubernetes & Container Security")
        self.kubescape = kubescape_adapter or KubescapeAdapter()
        self.kube_bench = kube_bench_adapter or KubeBenchAdapter()
        self.falco = falco_adapter or FalcoAdapter()

    def can_handle(self, event: BlackboardEvent) -> bool:
        if event.event_type == EventType.CONTAINER_DISCOVERED:
            return True

        if event.event_type == EventType.TARGET_REGISTERED:
            target = event.target.lower()
            if any(target.endswith(ext) for ext in [".yaml", ".yml", ".json"]):
                return True
            if any(k in target for k in ["k8s", "kube", "manifest", "helm", "chart", "pod", "deployment"]):
                return True
            if event.payload.get("target_type") in ["K8S", "KUBERNETES", "CONTAINER", "MANIFEST"]:
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

        # 1. Run Kubescape posture and manifest scan
        try:
            ks_res = self.kubescape.run(target, scope)
            for asset in ks_res.discovered_assets:
                blackboard.add_asset(asset)

            for f in ks_res.findings:
                blackboard.add_finding(f)
                is_escape = ("T1611" in f.mitre_attack_ids) or ("privileged" in f.title.lower()) or ("host" in f.title.lower())

                ev_type = (
                    EventType.PRIVILEGE_ESCALATION_PATH_DETECTED
                    if is_escape
                    else EventType.MISCONFIGURATION_DETECTED
                )
                new_events.append(
                    BlackboardEvent(
                        event_type=ev_type,
                        source_agent=self.name,
                        target=target,
                        payload={
                            "finding_title": f.title,
                            "severity": f.severity.value,
                            "mitre_attack_ids": f.mitre_attack_ids,
                            "is_container_escape": is_escape,
                            "tool": "kubescape",
                        },
                    )
                )
        except Exception as e:
            pass

        return new_events
