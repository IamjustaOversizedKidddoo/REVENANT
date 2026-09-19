"""
REVENANT — Specialist Mobile Application Security Agent
Autonomous agent subscribing to MOBILE_APP_DISCOVERED, TARGET_REGISTERED, and
REPO_DISCOVERED events for Android (APK/AAB/source) and iOS (IPA/source) targets.
Dispatches MobsfscanAdapter and MobSFAdapter to evaluate OWASP MASVS compliance.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import List, Optional

from adapters.mobile.mobsf_adapter import MobSFAdapter
from adapters.mobile.mobsfscan_adapter import MobsfscanAdapter
from control_plane.schemas.models import Finding
from control_plane.schemas.scope import ScopeManifest
from orchestrator.agents.base_agent import BaseAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType

logger = logging.getLogger("revenant.agents.mobile")

MOBILE_EXTENSIONS = {".apk", ".aab", ".ipa"}


class MobileAgent(BaseAgent):
    """Specialist agent for mobile application static and dynamic security assessments."""

    def __init__(
        self,
        mobsfscan_adapter: Optional[MobsfscanAdapter] = None,
        mobsf_adapter: Optional[MobSFAdapter] = None,
    ):
        super().__init__(name="mobile-agent", role="Mobile Application Security Auditing (Android/iOS)")
        self.mobsfscan = mobsfscan_adapter or MobsfscanAdapter()
        self.mobsf = mobsf_adapter or MobSFAdapter()

    def can_handle(self, event: BlackboardEvent) -> bool:
        """Evaluate if the event involves a mobile artifact, package, or codebase."""
        if event.event_type in [EventType.MOBILE_APP_DISCOVERED]:
            return True

        target_str = str(event.target)
        payload = event.payload or {}
        tags = [str(t).lower() for t in payload.get("tags", [])]

        if event.event_type == EventType.TARGET_REGISTERED:
            target_type = str(payload.get("target_type", "")).upper()
            if target_type in ["MOBILE_APP", "MOBILE_PACKAGE", "APK", "IPA", "ANDROID", "IOS"]:
                return True
            if any(t in ["mobile", "android", "ios", "apk", "ipa", "masvs"] for t in tags):
                return True
            if any(target_str.lower().endswith(ext) for ext in MOBILE_EXTENSIONS):
                return True

            # Check directory contents for mobile manifest files
            if os.path.isdir(target_str):
                p = Path(target_str)
                if list(p.rglob("AndroidManifest.xml")) or list(p.rglob("Info.plist")):
                    return True

        if event.event_type == EventType.REPO_DISCOVERED:
            if os.path.isdir(target_str):
                p = Path(target_str)
                if list(p.rglob("AndroidManifest.xml")) or list(p.rglob("Info.plist")):
                    return True

        return False

    def handle(
        self, event: BlackboardEvent, blackboard: Blackboard, scope_manifest: ScopeManifest
    ) -> List[BlackboardEvent]:
        """Execute the mobile security auditing cascade against the target."""
        target = event.target
        logger.info("[MobileAgent] Activated for mobile target: %s", target)
        out_events: List[BlackboardEvent] = []
        all_findings: List[Finding] = []

        # 1. Static Analysis via mobsfscan (WSL2 native binary + heuristics)
        try:
            logger.info("[MobileAgent] Executing MobsfscanAdapter on %s", target)
            scan_res = self.mobsfscan.run(target, scope_manifest)
            for f in scan_res.findings:
                blackboard.add_finding(f)
                all_findings.append(f)
            for a in scan_res.discovered_assets:
                blackboard.add_asset(a)
        except Exception as e:
            logger.warning("[MobileAgent] mobsfscan audit failed on %s: %s", target, e)

        # 2. MobSF API integration (if configured/available or requested)
        if self.mobsf.is_installed() or event.payload.get("use_mobsf"):
            try:
                logger.info("[MobileAgent] Executing MobSFAdapter on %s", target)
                mobsf_res = self.mobsf.run(target, scope_manifest)
                for f in mobsf_res.findings:
                    blackboard.add_finding(f)
                    all_findings.append(f)
                for a in mobsf_res.discovered_assets:
                    blackboard.add_asset(a)
            except Exception as e:
                logger.warning("[MobileAgent] MobSF scan failed on %s: %s", target, e)

        # Emit events for discovered vulnerabilities
        for finding in all_findings:
            out_ev = BlackboardEvent(
                event_type=EventType.MOBILE_VULNERABILITY_CONFIRMED,
                source_agent=self.name,
                target=target,
                payload={
                    "finding_id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "cwe": finding.cwe,
                    "masvs": finding.owasp_category,
                },
            )
            blackboard.post_event(out_ev)
            out_events.append(out_ev)

            # Also emit generic VULNERABILITY_CONFIRMED for AttackGraphEngine
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

        logger.info("[MobileAgent] Audit completed for %s. Total findings: %d", target, len(all_findings))
        return out_events
