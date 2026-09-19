"""
REVENANT — Enterprise Vulnerability Management Exporters (Faraday & Dradis)
Serializes multi-domain mission findings, assets, and exploit paths into
standard Faraday JSON ingestion and Dradis Project Gateway templates.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from control_plane.schemas.models import Finding, HostAsset, Severity

# Severity translation mapping for Faraday
FARADAY_SEVERITY_MAP: Dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "med",
    Severity.LOW: "low",
    Severity.INFO: "info",
}


class FaradayExporter:
    """
    Exports mission results into Faraday Vulnerability Management Platform
    JSON import format (v3/v4 API compatible).
    """

    def export(
        self,
        campaign_id: str,
        target: str,
        assets: List[HostAsset],
        findings: List[Finding],
    ) -> Dict[str, Any]:
        """Convert findings and discovered assets into Faraday JSON schema."""
        hosts_payload = []
        host_id_map = {}

        # 1. Map discovered assets into Faraday Hosts and Services
        for idx, asset in enumerate(assets, 1):
            ip_val = asset.ip or (target if "." in target and not target.startswith("http") else "127.0.0.1")
            hostname_val = asset.hostname or target
            services_payload = []

            for p in asset.ports:
                services_payload.append({
                    "port": p.port,
                    "protocol": p.protocol,
                    "name": p.service or "tcp",
                    "status": p.state,
                    "version": p.version or "",
                    "banner": p.banner or "",
                })

            host_obj = {
                "id": idx,
                "ip": ip_val,
                "hostnames": [hostname_val] if hostname_val else [],
                "os": asset.os or "Unknown",
                "description": f"REVENANT Discovered Host: {asset.cloud_provider or 'Local'}",
                "services": services_payload,
                "default_gateway": "None",
            }
            hosts_payload.append(host_obj)
            host_id_map[asset.hostname or ip_val] = idx

        # 2. Map findings into Faraday Vulnerabilities
        vulns_payload = []
        for idx, f in enumerate(findings, 1):
            faraday_sev = FARADAY_SEVERITY_MAP.get(f.severity, "med")
            cve_list = [f.cve] if f.cve else []
            cwe_val = f.cwe or ""

            tags = list(f.mitre_attack_ids)
            tags.append(f"tool:{f.tool}")
            if f.owasp_category:
                tags.append(f"owasp:{f.owasp_category}")

            vuln_obj = {
                "id": idx,
                "name": f.title,
                "desc": f.description,
                "severity": faraday_sev,
                "confirmed": f.verified or f.verified_valid,
                "resolution": f.remediation or "Refer to standard remediation guidance.",
                "data": f.evidence or "",
                "cve": cve_list,
                "cwe": cwe_val,
                "cvss": f.cvss_score or (9.8 if f.severity == Severity.CRITICAL else (7.5 if f.severity == Severity.HIGH else 5.0)),
                "target": f.endpoint or f.target,
                "tool": f.tool,
                "tags": tags,
                "status": "opened",
                "easeofresolution": "undetermined",
            }
            vulns_payload.append(vuln_obj)

        return {
            "faraday_schema_version": "3.0",
            "workspace": f"revenant_{campaign_id[:8]}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "hosts": hosts_payload,
            "vulnerabilities": vulns_payload,
            "summary": {
                "total_hosts": len(hosts_payload),
                "total_vulnerabilities": len(vulns_payload),
            },
        }


class DradisExporter:
    """
    Exports mission results into Dradis Professional / Community Project
    Gateway import package with structured issue and node templates.
    """

    def export(
        self,
        campaign_id: str,
        target: str,
        assets: List[HostAsset],
        findings: List[Finding],
    ) -> Dict[str, Any]:
        """Convert findings and assets into Dradis project format."""
        nodes_payload = []
        issues_payload = []

        # 1. Project Nodes
        root_node = {
            "label": target,
            "type": "Target Root",
            "children": [],
        }

        for asset in assets:
            host_label = asset.hostname or asset.ip or asset.id
            child_node = {
                "label": host_label,
                "type": "Host",
                "ports": [p.port for p in asset.ports],
                "endpoints": [e.url for e in asset.endpoints],
            }
            root_node["children"].append(child_node)

        nodes_payload.append(root_node)

        # 2. Project Issues
        for idx, f in enumerate(findings, 1):
            cve_str = f"CVE: {f.cve}\n" if f.cve else ""
            cwe_str = f"CWE: {f.cwe}\n" if f.cwe else ""
            mitre_str = f"MITRE ATT&CK: {', '.join(f.mitre_attack_ids)}\n" if f.mitre_attack_ids else ""

            dradis_text = (
                f"#[Title]#\n{f.title}\n\n"
                f"#[Severity]#\n{f.severity.value}\n\n"
                f"#[Tool]#\n{f.tool}\n\n"
                f"#[References]#\n{cve_str}{cwe_str}{mitre_str}\n"
                f"#[Description]#\n{f.description}\n\n"
                f"#[Remediation]#\n{f.remediation or 'Apply vendor patches and harden configuration.'}\n\n"
                f"#[Evidence]#\n```\n{f.evidence or 'No live payload evidence captured.'}\n```\n"
            )

            issue_obj = {
                "id": idx,
                "title": f.title,
                "severity": f.severity.value,
                "fields": {
                    "Title": f.title,
                    "Severity": f.severity.value,
                    "Description": f.description,
                    "Remediation": f.remediation or "",
                    "CVE": f.cve or "",
                    "CWE": f.cwe or "",
                    "MITRE": f.mitre_attack_ids,
                    "Tool": f.tool,
                    "Target": f.endpoint or f.target,
                },
                "raw_template": dradis_text,
            }
            issues_payload.append(issue_obj)

        return {
            "dradis_template_version": "4.0",
            "project": {
                "title": f"REVENANT Assessment: {target}",
                "campaign_id": campaign_id,
                "author": "REVENANT Autonomous Agentic Red Team",
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
            "nodes": nodes_payload,
            "issues": issues_payload,
            "summary": {
                "total_nodes": len(nodes_payload),
                "total_issues": len(issues_payload),
            },
        }
