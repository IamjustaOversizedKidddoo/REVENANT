"""
REVENANT — Specialist Cloud Infrastructure & Container Security Agent
Triggers on CONTAINER_DISCOVERED, CLOUD_ASSET_DISCOVERED, or TARGET_REGISTERED
(container images, Dockerfiles, Terraform manifests, Kubernetes specs),
dispatches TrivyAdapter and ProwlerAdapter, and publishes MISCONFIGURATION_DETECTED,
SECRET_EXPOSED, and VULNERABILITY_CANDIDATE events to the blackboard.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import List, Optional

from adapters.cloud.checkov_adapter import CheckovAdapter
from adapters.cloud.cloudfox_adapter import CloudFoxAdapter
from adapters.cloud.prowler_adapter import ProwlerAdapter
from adapters.cloud.trivy_adapter import TrivyAdapter
from control_plane.schemas.scope import ScopeManifest
from orchestrator.agents.base_agent import BaseAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType

logger = logging.getLogger("revenant.agents.cloud")


class CloudAgent(BaseAgent):
    """Specialist agent for cloud infrastructure, IaC, and container security audits."""

    def __init__(
        self,
        trivy_adapter: Optional[TrivyAdapter] = None,
        prowler_adapter: Optional[ProwlerAdapter] = None,
        checkov_adapter: Optional[CheckovAdapter] = None,
        cloudfox_adapter: Optional[CloudFoxAdapter] = None,
    ):
        super().__init__(name="cloud-agent", role="Cloud Infrastructure & Container Security Auditing")
        self.trivy = trivy_adapter or TrivyAdapter()
        self.prowler = prowler_adapter or ProwlerAdapter()
        self.checkov = checkov_adapter or CheckovAdapter()
        self.cloudfox = cloudfox_adapter or CloudFoxAdapter()

    def can_handle(self, event: BlackboardEvent) -> bool:
        if event.event_type in [EventType.CLOUD_ASSET_DISCOVERED, EventType.CONTAINER_DISCOVERED]:
            return True

        if event.event_type == EventType.REPO_DISCOVERED:
            return True

        if event.event_type == EventType.TARGET_REGISTERED:
            target = event.target
            target_type = str(event.payload.get("target_type", "")).upper()
            if target_type in ["CONTAINER_IMAGE", "IAC_CONFIG", "CLOUD", "CONTAINER"]:
                return True

            # Check filesystem paths
            if os.path.exists(target):
                target_path = Path(target)
                if target_path.is_file():
                    ext = target_path.suffix.lower()
                    name = target_path.name.lower()
                    if ext in [".tf", ".yaml", ".yml", ".json"] or "dockerfile" in name or "containerfile" in name:
                        return True
                elif target_path.is_dir():
                    # Target is a directory containing potential IaC or container files
                    return True

            # Container image reference format check (e.g., "alpine:3.18", "corp/app:latest")
            # Exclude Windows drive letters (e.g. C:\) and HTTP URLs
            if ":" in target and not target.startswith("http://") and not target.startswith("https://"):
                if not (len(target) > 1 and target[1] == ":" and target[2:3] in ["\\", "/"]):
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

        # 1. Execute Trivy container & Dockerfile scanner
        try:
            trivy_res = self.trivy.run(target, scope)
            for asset in trivy_res.discovered_assets:
                blackboard.add_asset(asset)

            for finding in trivy_res.findings:
                ev_type = (
                    EventType.SECRET_EXPOSED
                    if finding.cwe == "CWE-798"
                    else EventType.MISCONFIGURATION_DETECTED
                )
                new_events.append(
                    BlackboardEvent(
                        event_type=ev_type,
                        source_agent=self.name,
                        target=finding.target,
                        payload={"finding": finding.model_dump(mode="json")},
                    )
                )
        except Exception as e:
            logger.warning(f"[{self.name}] Trivy scan failed on target '{target}': {e}")

        # 2. Execute Prowler cloud posture & CIS benchmark engine
        try:
            prowler_res = self.prowler.run(target, scope)
            for asset in prowler_res.discovered_assets:
                blackboard.add_asset(asset)

            for finding in prowler_res.findings:
                new_events.append(
                    BlackboardEvent(
                        event_type=EventType.MISCONFIGURATION_DETECTED,
                        source_agent=self.name,
                        target=finding.target,
                        payload={"finding": finding.model_dump(mode="json")},
                    )
                )
        except Exception as e:
            logger.warning(f"[{self.name}] Prowler scan failed on target '{target}': {e}")

        # 3. Execute Checkov Infrastructure as Code (IaC) security scanner
        try:
            checkov_res = self.checkov.run(target, scope)
            for asset in checkov_res.discovered_assets:
                blackboard.add_asset(asset)

            for finding in checkov_res.findings:
                ev_type = (
                    EventType.SECRET_EXPOSED
                    if finding.cwe == "CWE-798"
                    else EventType.MISCONFIGURATION_DETECTED
                )
                new_events.append(
                    BlackboardEvent(
                        event_type=ev_type,
                        source_agent=self.name,
                        target=finding.target,
                        payload={"finding": finding.model_dump(mode="json")},
                    )
                )
        except Exception as e:
            logger.debug(f"[{self.name}] Checkov scan on '{target}': {e}")

        # 4. Execute CloudFox offensive cloud enumeration
        is_cloud_target = (
            os.path.isfile(target) and ("cloudfox" in target.lower() or target.endswith(".loot") or "cloud" in target.lower())
        ) or any(kw in target.lower() for kw in ["aws", "azure", "gcp", "s3://", "arn:aws", "cloudfox"])

        if is_cloud_target:
            try:
                cf_res = self.cloudfox.run(target, scope)
                for asset in cf_res.discovered_assets:
                    blackboard.add_asset(asset)

                for finding in cf_res.findings:
                    new_events.append(
                        BlackboardEvent(
                            event_type=EventType.PRIVILEGE_ESCALATION_PATH_DETECTED
                            if finding.cwe == "CWE-250"
                            else EventType.MISCONFIGURATION_DETECTED,
                            source_agent=self.name,
                            target=finding.target,
                            payload={"finding": finding.model_dump(mode="json")},
                        )
                    )
            except Exception as e:
                logger.debug(f"[{self.name}] CloudFox probe on '{target}': {e}")

        return new_events
