"""
REVENANT — MITRE Caldera Automated Adversary Emulation Adapter
Integrates with MITRE Caldera REST API (v2) for adversary profile execution,
autonomous operation sequencing, and defensive telemetry validation,
with graceful fallback to AtomicRedTeamAdapter when the Caldera daemon is offline.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from adapters.base import AdapterResult, BaseAdapter
from adapters.purple.atomic_adapter import AtomicRedTeamAdapter
from control_plane.schemas.models import Finding, HostAsset, Severity
from control_plane.schemas.scope import ScopeEngine, ScopeManifest, ScopeViolationError

logger = logging.getLogger("revenant.adapter.caldera")


class CalderaAdapter(BaseAdapter):
    """
    Adapter for MITRE Caldera adversary emulation framework.
    Interacts with Caldera REST API for adversary profile operations,
    falling back to local atomic emulation if Caldera is unavailable.
    """

    def __init__(
        self,
        server_url: str = "http://127.0.0.1:8888",
        api_key: str = "ADMIN123",
        adversary_profile: str = "adversary_discovery",
        timeout_seconds: int = 60,
    ):
        super().__init__(
            name="caldera",
            category="adversary_emulation",
            binary_override="caldera",
        )
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.adversary_profile = adversary_profile
        self.timeout_seconds = timeout_seconds
        self.atomic_adapter = AtomicRedTeamAdapter()

    def is_installed(self) -> bool:
        """Check if Caldera server is reachable or fallback atomic adapter is available."""
        try:
            req = urllib.request.Request(
                f"{self.server_url}/api/v2/health",
                headers={"KEY": self.api_key},
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        # Fallback is always available through native shells
        return self.atomic_adapter.is_installed()

    def validate_target_scope(self, target: str, manifest: ScopeManifest) -> None:
        """Enforce target authorization via ScopeEngine."""
        scope_engine = ScopeEngine(manifest)
        allowed, reason = scope_engine.is_allowed(target)
        if not allowed:
            raise ScopeViolationError(
                target, f"Caldera emulation target '{target}' is not within authorized scope manifest: {reason}"
            )

    def build_command(self, target: str, **kwargs) -> str:
        adv = kwargs.get("adversary_profile", self.adversary_profile)
        return f"caldera_operation --server {self.server_url} --adversary {adv} --target {target}"

    def parse_output(
        self, stdout: str, stderr: str, target: str, **kwargs
    ) -> Tuple[List[Finding], List[HostAsset]]:
        """Parse Caldera operation report or fallback execution results."""
        findings: List[Finding] = []
        assets: List[HostAsset] = []

        try:
            data = json.loads(stdout)
            steps = data.get("steps", [])
            for step in steps:
                tid = step.get("technique_id", "T1082")
                name = step.get("ability_name", "Caldera Ability")
                status = step.get("status", 0)

                findings.append(
                    Finding(
                        title=f"Caldera Emulation: {tid} - {name}",
                        description=(
                            f"Adversary operation executed ability `{name}` ({tid}) against `{target}`. "
                            f"Exit code: {status}."
                        ),
                        severity=Severity.INFO,
                        target=target,
                        tool="caldera",
                        mitre_attack_ids=[tid],
                        evidence=str(step.get("output", ""))[:500],
                        raw_data=step,
                    )
                )
        except Exception:
            # Plain text fallback parsing
            findings.append(
                Finding(
                    title=f"Caldera Operation Completed against {target}",
                    description=f"Adversary emulation profile {self.adversary_profile} finished.",
                    severity=Severity.INFO,
                    target=target,
                    tool="caldera",
                    evidence=stdout[:500],
                    raw_data={"stdout": stdout[:1000]},
                )
            )

        assets.append(HostAsset(hostname=target, metadata={"caldera_tested": True}))
        return findings, assets

    def trigger_remote_operation(self, target: str, adversary_id: str) -> Optional[Dict[str, Any]]:
        """Attempt to launch an operation via Caldera v2 REST API."""
        payload = json.dumps({
            "name": f"revenant_{int(time.time())}",
            "adversary": {"adversary_id": adversary_id},
            "planner": {"planner_id": "atomic"},
            "group": "red",
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{self.server_url}/api/v2/operations",
            data=payload,
            headers={"KEY": self.api_key, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                if resp.status in (200, 201):
                    return json.loads(resp.read().decode("utf-8"))
        except Exception as ex:
            logger.debug("Caldera API offline or unreachable: %s", ex)
        return None

    def run(self, target: str, manifest: ScopeManifest, **kwargs) -> AdapterResult:
        """Run Caldera adversary operation or trigger fallback atomic suite."""
        self.validate_target_scope(target, manifest)

        adv_profile = kwargs.get("adversary_profile", self.adversary_profile)
        remote_result = self.trigger_remote_operation(target, adv_profile)

        if remote_result:
            stdout_str = json.dumps(remote_result, indent=2)
            findings, assets = self.parse_output(stdout_str, "", target)
            return AdapterResult(
                tool_name=self.name,
                target=target,
                findings=findings,
                discovered_assets=assets,
                raw_stdout=stdout_str,
                exit_code=0,
            )

        # Graceful fallback to local AtomicRedTeamAdapter
        logger.info("Caldera API server unreachable at %s. Falling back to AtomicRedTeamAdapter.", self.server_url)
        return self.atomic_adapter.run(target, manifest, **kwargs)
