"""
REVENANT — Specialist Active Directory & Identity Security Agent
Triggers on IDENTITY_ASSET_DISCOVERED, TARGET_REGISTERED (AD domain, LDAP endpoints,
or directories containing BloodHound / Certipy JSON or ZIP exports), dispatches
BloodHoundAdapter and CertipyAdapter, and publishes PRIVILEGE_ESCALATION_PATH_DETECTED
and MISCONFIGURATION_DETECTED events to the blackboard.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import List, Optional

from adapters.identity.bloodhound_adapter import BloodHoundAdapter
from adapters.identity.certipy_adapter import CertipyAdapter
from adapters.identity.netexec_adapter import NetExecAdapter
from control_plane.schemas.models import Severity
from control_plane.schemas.scope import ScopeManifest
from orchestrator.agents.base_agent import BaseAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType

logger = logging.getLogger("revenant.agents.identity")


class IdentityAgent(BaseAgent):
    """Specialist agent for Active Directory, Kerberos, and enterprise PKI security audits."""

    def __init__(
        self,
        bloodhound_adapter: Optional[BloodHoundAdapter] = None,
        certipy_adapter: Optional[CertipyAdapter] = None,
        netexec_adapter: Optional[NetExecAdapter] = None,
    ):
        super().__init__(name="identity-agent", role="Active Directory & Identity Security Auditing")
        self.bloodhound = bloodhound_adapter or BloodHoundAdapter()
        self.certipy = certipy_adapter or CertipyAdapter()
        self.netexec = netexec_adapter or NetExecAdapter()

    def can_handle(self, event: BlackboardEvent) -> bool:
        if event.event_type == EventType.IDENTITY_ASSET_DISCOVERED:
            return True

        if event.event_type == EventType.TARGET_REGISTERED:
            target = event.target
            target_type = str(event.payload.get("target_type", "")).upper()
            if target_type in ["IDENTITY_ACCOUNT", "IDENTITY_DOMAIN", "CERT_TEMPLATE", "AD_IDENTITY"]:
                return True

            # Check filesystem paths
            if os.path.exists(target):
                target_path = Path(target)
                if target_path.is_file():
                    name = target_path.name.lower()
                    if name.endswith(".zip") or name.endswith(".json"):
                        return True
                elif target_path.is_dir():
                    # Target directory can be inspected for BloodHound / Certipy exports
                    return True

            # Domain naming heuristic (e.g. CORP.LOCAL, LAB.INTERNAL, domain controllers)
            clean_target = target.lower()
            if any(clean_target.endswith(tld) for tld in [".local", ".internal", ".corp", ".lan", ".ad"]):
                return True
            if any(kw in clean_target for kw in ["ldap://", "ldaps://", "adcs", "bloodhound"]):
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

        # 1. Execute BloodHound Active Directory assessment
        try:
            bh_res = self.bloodhound.run(target, scope)
            for asset in bh_res.discovered_assets:
                blackboard.add_asset(asset)

            for finding in bh_res.findings:
                new_events.append(
                    BlackboardEvent(
                        event_type=EventType.PRIVILEGE_ESCALATION_PATH_DETECTED,
                        source_agent=self.name,
                        target=finding.target,
                        payload={"finding": finding.model_dump(mode="json")},
                    )
                )
        except Exception as e:
            logger.warning(f"[{self.name}] BloodHound audit failed on '{target}': {e}")

        # 2. Execute Certipy AD CS PKI assessment
        try:
            cert_res = self.certipy.run(target, scope)
            for asset in cert_res.discovered_assets:
                blackboard.add_asset(asset)

            for finding in cert_res.findings:
                new_events.append(
                    BlackboardEvent(
                        event_type=EventType.PRIVILEGE_ESCALATION_PATH_DETECTED,
                        source_agent=self.name,
                        target=finding.target,
                        payload={"finding": finding.model_dump(mode="json")},
                    )
                )
        except Exception as e:
            logger.warning(f"[{self.name}] Certipy audit failed on '{target}': {e}")

        # 3. Execute NetExec active network protocol auditing
        try:
            nxc_res = self.netexec.run(target, scope)
            for asset in nxc_res.discovered_assets:
                blackboard.add_asset(asset)

            for finding in nxc_res.findings:
                new_events.append(
                    BlackboardEvent(
                        event_type=EventType.PRIVILEGE_ESCALATION_PATH_DETECTED
                        if finding.severity in [Severity.CRITICAL, Severity.HIGH]
                        else EventType.MISCONFIGURATION_DETECTED,
                        source_agent=self.name,
                        target=finding.target,
                        payload={"finding": finding.model_dump(mode="json")},
                    )
                )
        except Exception as e:
            logger.debug(f"[{self.name}] NetExec audit probe on '{target}': {e}")

        return new_events
