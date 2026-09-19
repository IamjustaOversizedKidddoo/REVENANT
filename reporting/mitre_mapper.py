"""
REVENANT — MITRE ATT&CK Enterprise Matrix Mapper & Heatmap Generator
Correlates CWEs, CVEs, and tool findings into MITRE ATT&CK Enterprise Matrix v14,
generating Navigator JSON layers, Markdown heatmaps, and HTML tactic matrices.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from control_plane.schemas.models import Finding, Severity

# MITRE ATT&CK Tactics
TACTICS_MAP: Dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

# Known Technique Definitions
TECHNIQUES_DEF: Dict[str, Dict[str, str]] = {
    "T1595": {"name": "Active Scanning", "tactic": "TA0043"},
    "T1595.001": {"name": "Scanning IP Blocks", "tactic": "TA0043"},
    "T1595.002": {"name": "Vulnerability Scanning", "tactic": "TA0043"},
    "T1596": {"name": "Search Open Technical Databases", "tactic": "TA0043"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "TA0001"},
    "T1189": {"name": "Drive-by Compromise", "tactic": "TA0001"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "TA0002"},
    "T1078": {"name": "Valid Accounts", "tactic": "TA0004"},
    "T1078.004": {"name": "Cloud Accounts", "tactic": "TA0004"},
    "T1558.001": {"name": "Steal or Forge Kerberos Tickets: Unconstrained Delegation", "tactic": "TA0004"},
    "T1611": {"name": "Escape to Host", "tactic": "TA0004"},
    "T1649": {"name": "Steal or Forge Authentication Certificates (AD CS)", "tactic": "TA0004"},
    "T1562": {"name": "Impair Defenses", "tactic": "TA0005"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "TA0006"},
    "T1552.001": {"name": "Credentials In Files", "tactic": "TA0006"},
    "T1558.003": {"name": "Steal or Forge Kerberos Tickets: Kerberoasting", "tactic": "TA0006"},
    "T1558.004": {"name": "Steal or Forge Kerberos Tickets: AS-REP Roasting", "tactic": "TA0006"},
    "T1187": {"name": "Forced Authentication (NTLM Relay)", "tactic": "TA0006"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "TA0007"},
    "T1046": {"name": "Network Service Discovery", "tactic": "TA0007"},
    "T1087": {"name": "Account Discovery", "tactic": "TA0007"},
    "T1530": {"name": "Data from Cloud Storage", "tactic": "TA0009"},
    "T1550": {"name": "Use Alternate Authentication Material", "tactic": "TA0008"},
    "AML.T0051": {"name": "LLM Prompt Injection", "tactic": "TA0001"},
    "AML.T0054": {"name": "LLM Jailbreak / Guardrail Bypass", "tactic": "TA0005"},
    "AML.T0057": {"name": "LLM System Prompt Extraction", "tactic": "TA0006"},
    "AML.T0043": {"name": "Craft Adversarial Data", "tactic": "TA0002"},
    "T1040": {"name": "Network Sniffing", "tactic": "TA0006"},
    "T1624": {"name": "Event Triggered Execution: Broadcast Receivers", "tactic": "TA0002"},
    "T1082": {"name": "System Information Discovery", "tactic": "TA0007"},
    "T1087.001": {"name": "Local Account Discovery", "tactic": "TA0007"},
    "T1057": {"name": "Process Discovery", "tactic": "TA0007"},
    "T1016": {"name": "System Network Configuration Discovery", "tactic": "TA0007"},
    "T1049": {"name": "System Network Connections Discovery", "tactic": "TA0007"},
    "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactic": "TA0002"},
    "T1033": {"name": "System Owner/User Discovery", "tactic": "TA0007"},
    "T1518.001": {"name": "Security Software Discovery", "tactic": "TA0007"},
}

# CWE to MITRE ATT&CK mapping rulebook
CWE_TO_ATTACK: Dict[str, List[str]] = {
    "CWE-798": ["T1552.001"],       # Hardcoded credentials
    "CWE-521": ["T1558.003"],       # Weak password / Kerberoasting
    "CWE-287": ["T1558.004"],       # AS-REP roasting
    "CWE-269": ["T1558.001"],       # Unconstrained delegation
    "CWE-295": ["T1649"],           # AD CS Certificate flaws (ESC1)
    "CWE-284": ["T1078"],           # Broken access control / Wildcard IAM
    "CWE-89":  ["T1190"],           # SQL Injection
    "CWE-79":  ["T1189"],           # Cross-site scripting
    "CWE-22":  ["T1083"],           # Path Traversal
    "CWE-601": ["T1189"],           # Open redirect
    "CWE-732": ["T1530"],           # Public S3 bucket
    "CWE-250": ["T1611"],           # Root container execution / Privileged K8s
    "CWE-1188": ["T1595.002"],      # Mutable container tag
    "CWE-77":  ["AML.T0051", "T1059"], # Prompt Injection / Command Injection
    "CWE-200": ["AML.T0057", "T1552"], # System Prompt Leak / Sensitive Information
    "CWE-926": ["T1190", "T1624"],  # Insecure Exported Android Component
    "CWE-319": ["T1040"],           # Cleartext Network Traffic
    "CWE-338": ["T1552"],           # Insecure Random Number Generator
    "CWE-215": ["T1059"],           # Debuggable Build Configuration
}


class MitreMapper:
    """Enterprise MITRE ATT&CK Matrix mapper and visual heatmap synthesizer."""

    def map_finding(self, finding: Finding) -> List[Dict[str, str]]:
        """Resolve all MITRE ATT&CK techniques associated with a finding."""
        mapped: List[Dict[str, str]] = []
        tech_ids: Set[str] = set()

        # 1. Explicit techniques already declared on finding
        for tid in finding.mitre_attack_ids:
            tech_ids.add(tid)

        # 2. Derive from CWE rulebook
        if finding.cwe and finding.cwe in CWE_TO_ATTACK:
            for tid in CWE_TO_ATTACK[finding.cwe]:
                tech_ids.add(tid)

        # 3. Tool-based heuristics
        if finding.tool in ["subfinder", "nmap"]:
            tech_ids.add("T1595.002")
        elif finding.tool == "gitleaks" or finding.tool == "trufflehog":
            tech_ids.add("T1552.001")

        for tid in tech_ids:
            tech_info = TECHNIQUES_DEF.get(tid, {})
            name = tech_info.get("name", f"Technique {tid}")
            tactic_id = tech_info.get("tactic", "TA0001")
            tactic_name = TACTICS_MAP.get(tactic_id, "Initial Access")
            mapped.append({
                "technique_id": tid,
                "technique_name": name,
                "tactic_id": tactic_id,
                "tactic_name": tactic_name,
            })

        return mapped

    def generate_matrix_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        """Aggregate all findings across MITRE ATT&CK tactics and techniques."""
        tactic_counts: Dict[str, Dict[str, Any]] = {
            tid: {"tactic_name": name, "techniques": {}, "total_findings": 0}
            for tid, name in TACTICS_MAP.items()
        }

        for f in findings:
            mapped_techniques = self.map_finding(f)
            for m in mapped_techniques:
                t_id = m["tactic_id"]
                tech_id = m["technique_id"]
                tech_name = m["technique_name"]

                if t_id in tactic_counts:
                    tactic_counts[t_id]["total_findings"] += 1
                    if tech_id not in tactic_counts[t_id]["techniques"]:
                        tactic_counts[t_id]["techniques"][tech_id] = {
                            "name": tech_name,
                            "count": 0,
                            "max_severity": f.severity.value,
                        }
                    tactic_counts[t_id]["techniques"][tech_id]["count"] += 1

        # Remove empty tactics for compact view
        active_tactics = {k: v for k, v in tactic_counts.items() if v["total_findings"] > 0}
        return {
            "total_tactics_hit": len(active_tactics),
            "tactics": active_tactics,
        }

    def generate_navigator_layer(self, findings: List[Finding], campaign_id: str) -> Dict[str, Any]:
        """Generate official MITRE ATT&CK Navigator v4.5 JSON layer."""
        technique_scores: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            for m in self.map_finding(f):
                tid = m["technique_id"]
                if tid not in technique_scores:
                    technique_scores[tid] = {
                        "techniqueID": tid,
                        "tactic": TACTICS_MAP.get(m["tactic_id"], "").lower().replace(" ", "-"),
                        "score": 0,
                        "color": "#f85149" if f.severity == Severity.CRITICAL else "#db61a2",
                        "comment": f"Detected by {f.tool}: {f.title}",
                        "enabled": True,
                    }
                technique_scores[tid]["score"] += 1

        return {
            "name": f"REVENANT Red Team Campaign — {campaign_id}",
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": f"Automated MITRE ATT&CK coverage heatmap generated by REVENANT.",
            "gradient": {
                "colors": ["#1f2937", "#f59e0b", "#f85149"],
                "minValue": 1,
                "maxValue": 5,
            },
            "techniques": list(technique_scores.values()),
        }

    def generate_markdown_heatmap(self, findings: List[Finding]) -> str:
        """Render markdown table summarizing MITRE ATT&CK tactics & techniques."""
        summary = self.generate_matrix_summary(findings)
        lines = [
            f"| MITRE Tactic | Technique ID | Technique Name | Findings | Highest Severity |",
            f"|:---|:---:|:---|:---:|:---:|",
        ]

        if not summary["tactics"]:
            lines.append("| *None* | - | No MITRE techniques mapped | 0 | - |")
            return "\n".join(lines)

        for t_id, t_info in summary["tactics"].items():
            t_name = t_info["tactic_name"]
            for tech_id, tech in t_info["techniques"].items():
                sev_icon = "🔴" if tech["max_severity"] == "CRITICAL" else ("🟠" if tech["max_severity"] == "HIGH" else "🟡")
                lines.append(
                    f"| **{t_name}** (`{t_id}`) | `{tech_id}` | {tech['name']} | {tech['count']} | {sev_icon} {tech['max_severity']} |"
                )

        return "\n".join(lines)

    def generate_html_heatmap(self, findings: List[Finding]) -> str:
        """Render HTML matrix cards for report embedding."""
        summary = self.generate_matrix_summary(findings)
        if not summary["tactics"]:
            return "<p><em>No MITRE ATT&CK techniques mapped.</em></p>"

        cards = []
        for t_id, t_info in summary["tactics"].items():
            tech_items = "".join(
                f'<div style="background:#21262d; border-radius:4px; padding:6px 10px; margin-top:6px; display:flex; justify-content:space-between; align-items:center;">'
                f'<span><code>{tech_id}</code> {t_data["name"]}</span>'
                f'<span style="background:#f85149; color:#fff; border-radius:12px; padding:2px 8px; font-size:11px; font-weight:bold;">{t_data["count"]}</span>'
                f'</div>'
                for tech_id, t_data in t_info["techniques"].items()
            )
            cards.append(f"""
            <div style="background:#161b22; border:1px solid #30363d; border-radius:6px; padding:12px; min-width:260px; flex:1;">
                <h4 style="margin:0 0 8px 0; color:#58a6ff; font-size:14px;">{t_info['tactic_name']} <span style="color:#8b949e; font-size:11px;">({t_id})</span></h4>
                <div style="color:#8b949e; font-size:12px; margin-bottom:8px;">Total Hits: <strong>{t_info['total_findings']}</strong></div>
                {tech_items}
            </div>
            """)

        return f'<div style="display:flex; flex-wrap:wrap; gap:12px; margin-top:12px;">{"".join(cards)}</div>'
