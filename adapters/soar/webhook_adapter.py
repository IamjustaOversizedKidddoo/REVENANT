"""
REVENANT — SOAR & Webhook Integration Adapter
Dispatches high-fidelity incident notifications, vulnerability findings, and attack graph choke points
to external SecOps, SIEM, and SOAR platforms:
- Generic Webhooks (JSON with HMAC-SHA256 signature verification)
- Slack / Discord / MS Teams Webhooks (Rich markdown blocks, severity coloring)
- Splunk HEC (HTTP Event Collector) / Elastic SIEM
- OWASP DefectDojo (Automated test engagement ingestion)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import urllib.request
import urllib.error
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from adapters.base import BaseAdapter
from control_plane.schemas.models import Finding, HostAsset, Severity

logger = logging.getLogger("revenant.adapters.soar")


class SOARPlatform(str, Enum):
    GENERIC = "generic"
    SLACK = "slack"
    SPLUNK_HEC = "splunk_hec"
    DEFECTDOJO = "defectdojo"
    DISCORD = "discord"


class SOARNotificationPayload(BaseModel):
    platform: SOARPlatform
    event_title: str
    summary: str
    findings_count: int
    critical_count: int
    high_count: int
    raw_payload: Dict[str, Any]
    signature: Optional[str] = None


class SOARWebhookAdapter(BaseAdapter):
    """Adapter for dispatching structured security events to SOAR and SIEM webhooks."""

    def __init__(self, binary_override: Optional[str] = None, use_wsl: bool = False):
        super().__init__(
            name="soar_webhook",
            category="soar",
            version="1.0",
            binary_override=binary_override,
            use_wsl=use_wsl,
        )

    def is_installed(self) -> bool:
        return True

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        # Internal Python HTTP dispatcher; command-line representation for audit logs
        return ["curl", "-X", "POST", target]

    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        return [], []

    @staticmethod
    def sign_payload(secret: str, body_bytes: bytes) -> str:
        """Compute HMAC-SHA256 digest for payload authentication."""
        return hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()

    def format_payload(
        self,
        platform: SOARPlatform,
        event_title: str,
        findings: List[Finding],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Format findings into the native schema of the target SOAR platform."""
        crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        meta = metadata or {}

        # 1. Slack Incoming Webhook Blocks
        if platform == SOARPlatform.SLACK:
            color = "#E01E5A" if crit_count > 0 else "#ECB22E" if high_count > 0 else "#2EB67D"
            blocks = [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"🚨 REVENANT Security Alert: {event_title}"},
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Total Findings:* {len(findings)}"},
                        {"type": "mrkdwn", "text": f"*Critical / High:* {crit_count} / {high_count}"},
                        {"type": "mrkdwn", "text": f"*Timestamp:* {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}"},
                        {"type": "mrkdwn", "text": f"*Target Environment:* `{meta.get('environment', 'Production')}`"},
                    ],
                },
                {"type": "divider"},
            ]
            for f in findings[:5]:  # Top 5 findings in summary
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*{f.severity.value.upper()}* - *{f.title}*\nTarget: `{f.target}` | CWE: `{f.cwe or 'N/A'}`\n_{f.description[:180]}..._",
                    },
                })
            return {"attachments": [{"color": color, "blocks": blocks}]}

        # 2. Splunk HEC (HTTP Event Collector)
        elif platform == SOARPlatform.SPLUNK_HEC:
            return {
                "time": time.time(),
                "sourcetype": "revenant:finding",
                "index": meta.get("index", "security"),
                "event": {
                    "alert_title": event_title,
                    "metrics": {
                        "total": len(findings),
                        "critical": crit_count,
                        "high": high_count,
                        "medium": med_count,
                    },
                    "findings": [f.model_dump(mode="json") for f in findings],
                    "metadata": meta,
                },
            }

        # 3. DefectDojo Finding Import
        elif platform == SOARPlatform.DEFECTDOJO:
            return {
                "engagement_name": meta.get("engagement_name", "REVENANT Continuous Assessment"),
                "scan_type": "REVENANT Orchestrator Scan",
                "environment": meta.get("environment", "Production"),
                "findings": [
                    {
                        "title": f.title,
                        "description": f.description,
                        "severity": f.severity.value.capitalize(),
                        "cwe": int(f.cwe.replace("CWE-", "")) if f.cwe and f.cwe.startswith("CWE-") and f.cwe.replace("CWE-", "").isdigit() else None,
                        "mitigation": f.remediation,
                        "impact": f"Exploitable via MITRE ATT&CK: {', '.join(f.mitre_attack_ids)}",
                        "active": True,
                        "verified": True,
                    }
                    for f in findings
                ],
            }

        # 4. Generic JSON Webhook
        return {
            "source": "REVENANT Autonomous Cyber Warfare Platform",
            "version": "2.0",
            "event": event_title,
            "timestamp": time.time(),
            "summary": {
                "total_findings": len(findings),
                "critical": crit_count,
                "high": high_count,
                "medium": med_count,
            },
            "findings": [f.model_dump(mode="json") for f in findings],
            "metadata": meta,
        }

    def dispatch(
        self,
        endpoint_url: str,
        platform: SOARPlatform,
        event_title: str,
        findings: List[Finding],
        secret: Optional[str] = None,
        auth_token: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        """Send formatted webhook payload to the designated SOAR endpoint."""
        payload = self.format_payload(platform, event_title, findings, metadata)
        body_bytes = json.dumps(payload, indent=2, default=str).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "REVENANT-SOAR-Engine/2.0",
        }

        if auth_token:
            if platform == SOARPlatform.SPLUNK_HEC:
                headers["Authorization"] = f"Splunk {auth_token}"
            else:
                headers["Authorization"] = f"Bearer {auth_token}"

        if secret:
            sig = self.sign_payload(secret, body_bytes)
            headers["X-REVENANT-Signature"] = f"sha256={sig}"
            headers["X-Hub-Signature-256"] = f"sha256={sig}"

        req = urllib.request.Request(
            url=endpoint_url,
            data=body_bytes,
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                resp_code = response.getcode()
                resp_data = response.read().decode("utf-8", errors="replace")
                logger.info(f"Dispatched SOAR alert to {endpoint_url} (HTTP {resp_code})")
                return {
                    "success": True,
                    "status_code": resp_code,
                    "response": resp_data,
                    "dispatched_count": len(findings),
                }
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            logger.warning(f"SOAR endpoint returned HTTP {e.code}: {err_body}")
            return {
                "success": False,
                "status_code": e.code,
                "error": str(e),
                "response": err_body,
            }
        except Exception as e:
            logger.error(f"Failed to dispatch SOAR notification: {e}")
            return {
                "success": False,
                "status_code": 0,
                "error": str(e),
            }
