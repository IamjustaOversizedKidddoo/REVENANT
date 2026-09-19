"""
REVENANT — Multi-Format Evidence & Reporting Engine
Generates executive and technical reports in Markdown, HTML, SARIF v2.1.0, JSON,
and MITRE ATT&CK Navigator format with integrated Attack Graph synthesis.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from control_plane.schemas.attack_graph import AttackGraph
from control_plane.schemas.models import Finding, HostAsset, Severity
from orchestrator.correlation.attack_graph_engine import AttackGraphEngine
from reporting.compliance_mapper import ComplianceMapper
from reporting.enterprise_exporters import DradisExporter, FaradayExporter
from reporting.mitre_mapper import MitreMapper

SEVERITY_ORDER = {
    Severity.CRITICAL: 1,
    Severity.HIGH: 2,
    Severity.MEDIUM: 3,
    Severity.LOW: 4,
    Severity.INFO: 5,
}

SARIF_SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


class ReportGenerator:
    """Produces normalized assessment reports across multiple industry standards."""

    def __init__(
        self,
        campaign_id: str,
        target: str,
        assets: List[HostAsset],
        findings: List[Finding],
        metadata: Dict[str, Any] | None = None,
    ):
        self.campaign_id = campaign_id
        self.target = target
        self.assets = assets
        # Sort findings by severity
        self.findings = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 99),
        )
        self.metadata = metadata or {}
        self.generated_at = datetime.now(timezone.utc).isoformat()

        # Build attack graph and MITRE mapping
        self.graph_engine = AttackGraphEngine()
        self.mitre_mapper = MitreMapper()
        self.compliance_mapper = ComplianceMapper()
        self.faraday_exporter = FaradayExporter()
        self.dradis_exporter = DradisExporter()
        self.attack_graph: AttackGraph = self.graph_engine.build_graph(self.assets, self.findings, self.target)
        self.mitre_summary = self.mitre_mapper.generate_matrix_summary(self.findings)

    def get_summary_counts(self) -> Dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def generate_markdown(self) -> str:
        counts = self.get_summary_counts()
        lines = [
            f"# REVENANT Security Assessment Report",
            f"",
            f"**Target:** `{self.target}`  ",
            f"**Campaign ID:** `{self.campaign_id}`  ",
            f"**Date:** {self.generated_at}  ",
            f"**Total Discovered Assets:** {len(self.assets)}  ",
            f"**Total Findings:** {len(self.findings)}  ",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            f"REVENANT completed an automated multi-domain security assessment against `{self.target}`.",
            f"",
            f"| Severity | Count |",
            f"|:---|:---:|",
            f"| 🔴 CRITICAL | {counts['CRITICAL']} |",
            f"| 🟠 HIGH | {counts['HIGH']} |",
            f"| 🟡 MEDIUM | {counts['MEDIUM']} |",
            f"| 🔵 LOW | {counts['LOW']} |",
            f"| ⚪ INFO | {counts['INFO']} |",
            f"",
            f"---",
            f"",
            f"## Discovered Assets ({len(self.assets)})",
            f"",
        ]

        if not self.assets:
            lines.append("*No distinct host assets indexed.*")
        else:
            for a in self.assets:
                host_str = a.hostname or a.ip or "Unknown"
                ip_str = f" ({a.ip})" if a.ip and a.ip != host_str else ""
                lines.append(f"- **{host_str}**{ip_str}")
                if a.ports:
                    ports_str = ", ".join(f"{p.port}/{p.protocol} ({p.service or 'unknown'})" for p in a.ports)
                    lines.append(f"  - Ports: {ports_str}")
                if a.endpoints:
                    lines.append(f"  - Endpoints ({len(a.endpoints)}):")
                    for ep in a.endpoints[:5]:
                        lines.append(f"    - `{ep.url}` [{ep.status_code or 'N/A'}]")
                    if len(a.endpoints) > 5:
                        lines.append(f"    - *...and {len(a.endpoints) - 5} more*")

        # -------------------------------------------------------------
        # Attack Graph & Exploit Choke Points Section
        # -------------------------------------------------------------
        lines.extend([
            f"",
            f"---",
            f"",
            f"## Attack Graph & Exploit Chains",
            f"",
            f"The following directed attack graph illustrates cross-domain relationships synthesized from discovered assets, credentials, and vulnerabilities:",
            f"",
            self.attack_graph.to_mermaid(),
            f"",
        ])

        choke_points = self.attack_graph.find_choke_points()
        if choke_points:
            lines.extend([
                f"### Strategic Remediation Choke Points",
                f"Remediating the following bottleneck nodes breaks multiple intersecting exploit paths:",
                f"",
                f"| Node / Asset | Type | Severity | Paths Affected | Remediation Priority |",
                f"|:---|:---:|:---:|:---:|:---:|",
            ])
            for cp in choke_points:
                lines.append(
                    f"| `{cp['label']}` | {cp['node_type']} | {cp['severity']} | {cp['attack_paths_affected']} | **{cp['remediation_priority']}** |"
                )
            lines.append("")

        # -------------------------------------------------------------
        # MITRE ATT&CK Matrix Coverage Section
        # -------------------------------------------------------------
        lines.extend([
            f"---",
            f"",
            f"## MITRE ATT&CK Enterprise Matrix Coverage",
            f"",
            self.mitre_mapper.generate_markdown_heatmap(self.findings),
            f"",
        ])

        # Purple Teaming & Defensive Visibility Section
        purple_findings = [f for f in self.findings if f.tool in ["atomic_red_team", "detection_engine", "caldera"]]
        if purple_findings:
            from adapters.purple.detection_engine import DetectionGapEngine
            det_engine = DetectionGapEngine()
            executed_tids = []
            for f in purple_findings:
                executed_tids.extend(f.mitre_attack_ids)
            executed_tids = list(dict.fromkeys(executed_tids))
            if executed_tids:
                report = det_engine.evaluate_emulation(executed_tids, target=self.target)
                lines.extend([
                    f"---",
                    f"",
                    f"## Purple Teaming & Defensive Visibility Matrix",
                    f"",
                    det_engine.generate_markdown_summary(report),
                    f"",
                ])

        # -------------------------------------------------------------
        # Compliance & Regulatory Framework Section
        # -------------------------------------------------------------
        lines.extend([
            f"---",
            f"",
            f"## Regulatory & Framework Compliance Posture",
            f"",
            self.compliance_mapper.generate_markdown_summary(self.findings),
            f"",
        ])

        lines.extend([
            f"---",
            f"",
            f"## Detailed Findings",
            f"",
        ])

        if not self.findings:
            lines.append("*No vulnerabilities discovered.*")
        else:
            for idx, f in enumerate(self.findings, 1):
                cve_str = f" [{f.cve}]" if f.cve else ""
                cwe_str = f" ({f.cwe})" if f.cwe else ""
                cvss_str = f" | CVSS: {f.cvss_score}" if f.cvss_score else ""
                mitre_str = f" | MITRE: {', '.join(f.mitre_attack_ids)}" if f.mitre_attack_ids else ""

                lines.extend([
                    f"### {idx}. [{f.severity.value}] {f.title}{cve_str}{cwe_str}",
                    f"- **Target / Endpoint:** `{f.endpoint or f.target}`",
                    f"- **Tool:** `{f.tool}`{cvss_str}{mitre_str}",
                    f"- **Description:** {f.description}",
                ])
                if f.remediation:
                    lines.append(f"- **Remediation:** {f.remediation}")
                if f.code_location:
                    lines.append(f"- **Code Location:** `{f.code_location.file_path}:{f.code_location.start_line}`")
                    if f.code_location.snippet:
                        lines.append(f"- **Snippet:** `{f.code_location.snippet}`")
                if f.reproduction_steps:
                    lines.extend([
                        f"- **Reproduction:**",
                        f"  ```bash",
                        f"  {f.reproduction_steps}",
                        f"  ```",
                    ])
                if f.evidence:
                    lines.extend([
                        f"- **Evidence:**",
                        f"  ```text",
                        f"  {f.evidence}",
                        f"  ```",
                    ])
                lines.append("")

        return "\n".join(lines)

    def generate_html(self) -> str:
        counts = self.get_summary_counts()
        mermaid_code = self.attack_graph.to_mermaid().replace("```mermaid\n", "").replace("\n```", "")
        mitre_html = self.mitre_mapper.generate_html_heatmap(self.findings)
        choke_points = self.attack_graph.find_choke_points()

        choke_points_html = ""
        if choke_points:
            cp_rows = "".join(
                f"<tr><td><code>{cp['label']}</code></td><td>{cp['node_type']}</td>"
                f"<td><span class='badge badge-{cp['severity']}'>{cp['severity']}</span></td>"
                f"<td style='text-align:center;'>{cp['attack_paths_affected']}</td>"
                f"<td><strong>{cp['remediation_priority']}</strong></td></tr>"
                for cp in choke_points
            )
            choke_points_html = f"""
            <h3>Strategic Remediation Choke Points</h3>
            <table style="width:100%; border-collapse:collapse; margin-bottom:24px;">
                <thead>
                    <tr style="background:#21262d; text-align:left;">
                        <th style="padding:8px; border:1px solid #30363d;">Node / Component</th>
                        <th style="padding:8px; border:1px solid #30363d;">Type</th>
                        <th style="padding:8px; border:1px solid #30363d;">Severity</th>
                        <th style="padding:8px; border:1px solid #30363d;">Paths Broken</th>
                        <th style="padding:8px; border:1px solid #30363d;">Priority</th>
                    </tr>
                </thead>
                <tbody>{cp_rows}</tbody>
            </table>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>REVENANT Assessment — {self.target}</title>
    <script type="module">
        import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
        mermaid.initialize({{ startOnLoad: true, theme: 'dark' }});
    </script>
    <style>
        :root {{
            --bg: #0d1117;
            --surface: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-heading: #f0f6fc;
            --critical: #f85149;
            --high: #db61a2;
            --medium: #d29922;
            --low: #58a6ff;
            --info: #8b949e;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.6;
            margin: 0;
            padding: 40px 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        h1, h2, h3 {{ color: var(--text-heading); }}
        .header {{
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background-color: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 20px;
            text-align: center;
        }}
        .summary-card .count {{
            font-size: 32px;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .finding-card {{
            background-color: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            color: #fff;
        }}
        .badge-CRITICAL {{ background-color: var(--critical); }}
        .badge-HIGH {{ background-color: var(--high); }}
        .badge-MEDIUM {{ background-color: var(--medium); color: #000; }}
        .badge-LOW {{ background-color: var(--low); }}
        .badge-INFO {{ background-color: var(--info); }}
        pre {{
            background-color: #030712;
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            border: 1px solid var(--border);
        }}
        code {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }}
        .graph-card {{
            background-color: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 24px;
            margin-bottom: 30px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>REVENANT Security Assessment</h1>
            <p><strong>Target:</strong> <code>{self.target}</code> | <strong>Campaign ID:</strong> <code>{self.campaign_id}</code> | <strong>Date:</strong> {self.generated_at}</p>
        </div>

        <div class="summary-grid">
            <div class="summary-card"><div class="count" style="color:var(--critical);">{counts['CRITICAL']}</div>CRITICAL</div>
            <div class="summary-card"><div class="count" style="color:var(--high);">{counts['HIGH']}</div>HIGH</div>
            <div class="summary-card"><div class="count" style="color:var(--medium);">{counts['MEDIUM']}</div>MEDIUM</div>
            <div class="summary-card"><div class="count" style="color:var(--low);">{counts['LOW']}</div>LOW</div>
            <div class="summary-card"><div class="count" style="color:var(--info);">{counts['INFO']}</div>INFO</div>
        </div>

        <h2>Attack Graph & Synthesized Exploit Chains</h2>
        <div class="graph-card">
            <pre class="mermaid">
{mermaid_code}
            </pre>
            {choke_points_html}
        </div>

        <h2>MITRE ATT&CK Enterprise Matrix Coverage</h2>
        <div style="margin-bottom:30px;">
            {mitre_html}
        </div>

        <h2>Detailed Findings ({len(self.findings)})</h2>
        {''.join(f'''
        <div class="finding-card">
            <div style="display:flex; align-items:center; gap:10px; margin-bottom:10px;">
                <span class="badge badge-{f.severity.value}">{f.severity.value}</span>
                <h3 style="margin:0;">{f.title}</h3>
            </div>
            <p><strong>Endpoint / Target:</strong> <code>{f.endpoint or f.target}</code> | <strong>Tool:</strong> <code>{f.tool}</code> {f'| <strong>CVE:</strong> {f.cve}' if f.cve else ''} {f'| <strong>CWE:</strong> {f.cwe}' if f.cwe else ''} {f'| <strong>MITRE:</strong> {", ".join(f.mitre_attack_ids)}' if f.mitre_attack_ids else ''}</p>
            {f'<p><strong>Code Location:</strong> <code>{f.code_location.file_path}:{f.code_location.start_line}</code></p>' if f.code_location else ''}
            <p>{f.description}</p>
            {f'<p><strong>Remediation:</strong> {f.remediation}</p>' if f.remediation else ''}
            {f'<p><strong>Reproduction:</strong></p><pre><code>{f.reproduction_steps}</code></pre>' if f.reproduction_steps else ''}
            {f'<p><strong>Evidence:</strong></p><pre><code>{f.evidence}</code></pre>' if f.evidence else ''}
        </div>
        ''' for f in self.findings)}
    </div>
</body>
</html>"""

    def generate_sarif(self) -> Dict[str, Any]:
        """
        Generate OASIS SARIF v2.1.0 standard output enriched with MITRE ATT&CK taxonomies.
        """
        rules = []
        results = []
        rule_ids = set()

        for idx, f in enumerate(self.findings):
            rule_id = f.cve or f.cwe or f"REV-{f.tool.upper()}-{idx}"
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": f.title.replace(" ", "_"),
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "help": {
                        "text": f.remediation or f.description,
                        "markdown": f"**Remediation Guidance:**\n\n{f.remediation}" if f.remediation else f.description,
                    },
                    "helpUri": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={f.cve}" if f.cve else "https://revenant.security",
                    "properties": {
                        "severity": f.severity.value,
                        "cvss": f.cvss_score,
                        "cwe": f.cwe,
                        "mitre_attack_ids": f.mitre_attack_ids,
                    },
                })

            loc_uri = f.code_location.file_path if f.code_location else (f.endpoint or f.target)
            formatted_uri = loc_uri.replace("\\", "/")
            phys_loc: Dict[str, Any] = {
                "artifactLocation": {"uri": formatted_uri}
            }
            if f.code_location:
                phys_loc["region"] = {
                    "startLine": f.code_location.start_line,
                    "endLine": f.code_location.end_line or f.code_location.start_line,
                }
                if f.code_location.snippet:
                    phys_loc["region"]["snippet"] = {"text": f.code_location.snippet}

            results.append({
                "ruleId": rule_id,
                "level": SARIF_SEVERITY_MAP.get(f.severity, "warning"),
                "message": {"text": f"{f.title}: {f.description}"},
                "locations": [{"physicalLocation": phys_loc}],
            })

        # Define MITRE ATT&CK taxonomy
        taxa = [
            {"id": tid, "name": f"MITRE ATT&CK Technique {tid}"}
            for tid in sorted({tid for f in self.findings for tid in f.mitre_attack_ids})
        ]

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "REVENANT",
                            "version": "2.0.0",
                            "informationUri": "https://github.com/revenant-security/revenant",
                            "rules": rules,
                            "supportedTaxonomies": [{"name": "MITRE ATT&CK", "index": 0}],
                        }
                    },
                    "taxonomies": [
                        {
                            "name": "MITRE ATT&CK",
                            "version": "14",
                            "organization": "MITRE",
                            "shortDescription": {"text": "MITRE ATT&CK Enterprise Matrix v14"},
                            "taxa": taxa,
                        }
                    ],
                    "results": results,
                }
            ],
        }

    def generate_json(self) -> Dict[str, Any]:
        """Complete structured raw JSON dump including attack graph and MITRE matrix."""
        return {
            "campaign_id": self.campaign_id,
            "target": self.target,
            "generated_at": self.generated_at,
            "summary": self.get_summary_counts(),
            "assets": [a.model_dump(mode="json") for a in self.assets],
            "findings": [f.model_dump(mode="json") for f in self.findings],
            "attack_graph": {
                "nodes": {nid: n.model_dump(mode="json") for nid, n in self.attack_graph.nodes.items()},
                "edges": [e.model_dump(mode="json") for e in self.attack_graph.edges],
                "choke_points": self.attack_graph.find_choke_points(),
                "critical_paths": self.attack_graph.find_attack_paths(),
            },
            "mitre_matrix": self.mitre_summary,
            "compliance_posture": self.generate_compliance_report(),
            "metadata": self.metadata,
        }

    def generate_attack_navigator(self) -> Dict[str, Any]:
        """Generate exportable MITRE ATT&CK Navigator v4.5 JSON layer."""
        return self.mitre_mapper.generate_navigator_layer(self.findings, self.campaign_id)

    def generate_faraday(self) -> Dict[str, Any]:
        """Generate Faraday Platform JSON ingestion format."""
        return self.faraday_exporter.export(self.campaign_id, self.target, self.assets, self.findings)

    def generate_dradis(self) -> Dict[str, Any]:
        """Generate Dradis Professional / Community project gateway export."""
        return self.dradis_exporter.export(self.campaign_id, self.target, self.assets, self.findings)

    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate compliance evaluation across NIST AI RMF, OWASP LLM, CIS v8, and OWASP MASVS."""
        return self.compliance_mapper.evaluate_compliance(self.findings)
