"""
REVENANT — Detection Gap Analysis Engine
Evaluates adversary emulation TTPs against defensive visibility rules (Sigma, Sysmon, Auditd)
to identify blind spots, calculate defensive visibility scores, and generate remediation Sigma rules.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from adapters.purple.telemetry_collector import TelemetryCollector
from control_plane.schemas.models import Finding, Severity

logger = logging.getLogger("revenant.purple.detection_engine")


@dataclass
class DetectionRule:
    """Sigma-style defensive detection rule definition."""
    rule_id: str
    title: str
    technique_id: str
    tactic: str
    logsource: str
    event_ids: List[int]
    detection_logic: str
    sigma_yaml: str
    enabled: bool = True
    level: str = "medium"  # low, medium, high, critical


@dataclass
class DetectionCoverageReport:
    """Comprehensive defensive visibility and detection gap scorecard."""
    total_tested: int
    detected_count: int
    logged_count: int
    blind_spot_count: int
    visibility_score: float  # (detected + logged) / total * 100
    detection_score: float   # detected / total * 100
    evaluations: List[Dict[str, Any]] = field(default_factory=list)
    blind_spot_findings: List[Finding] = field(default_factory=list)


# Curated catalog of standard Sigma rules for MITRE ATT&CK techniques
DEFAULT_SIGMA_CATALOG: Dict[str, DetectionRule] = {
    "T1082": DetectionRule(
        rule_id="sigma_proc_creation_win_sysinfo_discovery",
        title="System Information Discovery Execution",
        technique_id="T1082",
        tactic="TA0007",
        logsource="windows/process_creation",
        event_ids=[1, 4688],
        detection_logic="Image endswith ('systeminfo.exe', 'hostname.exe') or CommandLine contains ('Win32_OperatingSystem', 'uname -a')",
        level="low",
        sigma_yaml="""title: System Information Discovery Execution
id: 56b82596-7b43-41c3-8472-a4f66432e989
status: test
description: Detects execution of system information discovery commands
references:
    - https://attack.mitre.org/techniques/T1082/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'systeminfo'
            - 'Win32_OperatingSystem'
            - 'uname -a'
    condition: selection
falsepositives:
    - Legitimate administrative troubleshooting
level: low
""",
    ),
    "T1087.001": DetectionRule(
        rule_id="sigma_proc_creation_win_local_user_enumeration",
        title="Local User Account Enumeration",
        technique_id="T1087.001",
        tactic="TA0007",
        logsource="windows/process_creation",
        event_ids=[1, 4688],
        detection_logic="Image endswith 'net.exe' and CommandLine contains 'user' or CommandLine contains ('/etc/passwd', 'Get-LocalUser')",
        level="medium",
        sigma_yaml="""title: Local User Account Enumeration
id: e4b2d56a-129b-4ec9-8ea2-b52968603ef8
status: test
description: Detects enumeration of local accounts using net.exe or PowerShell
references:
    - https://attack.mitre.org/techniques/T1087/001/
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        CommandLine|contains:
            - 'net user'
            - 'Get-LocalUser'
            - '/etc/passwd'
    condition: selection_cmd
falsepositives:
    - Administrative account inventory scripts
level: medium
""",
    ),
    "T1057": DetectionRule(
        rule_id="sigma_proc_creation_win_process_discovery",
        title="Active Process Discovery Listing",
        technique_id="T1057",
        tactic="TA0007",
        logsource="windows/process_creation",
        event_ids=[1, 4688],
        detection_logic="Image endswith ('tasklist.exe', 'ps.exe') or CommandLine contains ('Get-Process', 'ps aux')",
        level="low",
        sigma_yaml="""title: Active Process Discovery Listing
id: 9a7860fc-f3e0-4ad1-b219-c0953a96864f
status: test
description: Detects execution of process discovery commands
references:
    - https://attack.mitre.org/techniques/T1057/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'tasklist'
            - 'Get-Process'
            - 'ps aux'
    condition: selection
level: low
""",
    ),
    "T1016": DetectionRule(
        rule_id="sigma_proc_creation_win_network_configuration_discovery",
        title="System Network Configuration Discovery",
        technique_id="T1016",
        tactic="TA0007",
        logsource="windows/process_creation",
        event_ids=[1, 4688],
        detection_logic="Image endswith ('ipconfig.exe', 'ifconfig') or CommandLine contains ('ip addr', 'ipconfig /all')",
        level="low",
        sigma_yaml="""title: System Network Configuration Discovery
id: b32a82d0-6db2-48a5-8178-e04f05f7fa19
status: test
description: Detects network configuration enumeration commands
references:
    - https://attack.mitre.org/techniques/T1016/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'ipconfig'
            - 'ip addr'
            - 'ifconfig'
    condition: selection
level: low
""",
    ),
    "T1049": DetectionRule(
        rule_id="sigma_proc_creation_win_netstat_discovery",
        title="System Network Connections Discovery",
        technique_id="T1049",
        tactic="TA0007",
        logsource="windows/process_creation",
        event_ids=[1, 4688],
        detection_logic="Image endswith ('netstat.exe', 'ss') or CommandLine contains ('netstat -ano', 'ss -tuln')",
        level="medium",
        sigma_yaml="""title: System Network Connections Discovery
id: d76b328a-7e91-4cf1-8302-861c834a34b9
status: test
description: Detects enumeration of active network connections and listening ports
references:
    - https://attack.mitre.org/techniques/T1049/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'netstat -ano'
            - 'ss -tuln'
    condition: selection
level: medium
""",
    ),
    "T1033": DetectionRule(
        rule_id="sigma_proc_creation_win_whoami_execution",
        title="Security Account or Group Discovery via Whoami",
        technique_id="T1033",
        tactic="TA0007",
        logsource="windows/process_creation",
        event_ids=[1, 4688],
        detection_logic="Image endswith 'whoami.exe' or CommandLine contains ('whoami /all', 'id -u')",
        level="medium",
        sigma_yaml="""title: Security Account or Group Discovery via Whoami
id: 61852033-bb9e-4e44-8d99-52d19ec5ff9e
status: test
description: Detects execution of whoami to discover user identity and privileges
references:
    - https://attack.mitre.org/techniques/T1033/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'whoami'
            - 'id -u'
    condition: selection
level: medium
""",
    ),
    "T1059.001": DetectionRule(
        rule_id="sigma_proc_creation_win_powershell_execution",
        title="PowerShell Execution Policy Probe",
        technique_id="T1059.001",
        tactic="TA0002",
        logsource="windows/process_creation",
        event_ids=[1, 4688, 4104],
        detection_logic="Image endswith 'powershell.exe' and CommandLine contains 'Get-ExecutionPolicy'",
        level="medium",
        sigma_yaml="""title: PowerShell Execution Policy Probe
id: 489e2764-a25e-4c74-a6e5-48b2612bbcf3
status: test
description: Detects execution of PowerShell commands probing execution policy
references:
    - https://attack.mitre.org/techniques/T1059/001/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'Get-ExecutionPolicy'
    condition: selection
level: medium
""",
    ),
    "T1518.001": DetectionRule(
        rule_id="sigma_proc_creation_win_security_software_discovery",
        title="Security Software Discovery via WMI/PowerShell",
        technique_id="T1518.001",
        tactic="TA0007",
        logsource="windows/process_creation",
        event_ids=[1, 4688],
        detection_logic="CommandLine contains ('AntiVirusProduct', 'WinDefend', 'Get-MpComputerStatus')",
        level="high",
        sigma_yaml="""title: Security Software Discovery via WMI/PowerShell
id: f38b97d2-9721-4f77-94d8-9c240974e641
status: test
description: Detects queries for installed antivirus products and security agents
references:
    - https://attack.mitre.org/techniques/T1518/001/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'AntiVirusProduct'
            - 'Get-MpComputerStatus'
            - 'WinDefend'
    condition: selection
level: high
""",
    ),
}


class DetectionGapEngine:
    """
    Evaluates adversary emulation actions against defensive rules and telemetry
    to calculate Visibility Scores and generate detection gap findings.
    """

    def __init__(self, rule_catalog: Optional[Dict[str, DetectionRule]] = None):
        self.rules: Dict[str, DetectionRule] = rule_catalog or dict(DEFAULT_SIGMA_CATALOG)

    def register_rule(self, rule: DetectionRule) -> None:
        """Register or override a defensive detection rule."""
        self.rules[rule.technique_id] = rule

    def evaluate_emulation(
        self,
        executed_techniques: List[str],
        active_rules: Optional[Set[str]] = None,
        telemetry_events: Optional[List[Dict[str, Any]]] = None,
        target: str = "localhost",
        collect_live_telemetry: bool = False,
    ) -> DetectionCoverageReport:
        """
        Evaluate executed TTPs against active defensive rules and telemetry.
        If active_rules is None, all enabled rules in self.rules are assumed active.
        If active_rules is provided, only rules in that set are considered active (simulating partial defense).
        If collect_live_telemetry=True, reads real evidence from TelemetryCollector before scoring.
        """
        # Merge live telemetry if requested
        if collect_live_telemetry:
            collector = TelemetryCollector()
            live_events = collector.collect()
            if live_events:
                logger.info("Merged %d live telemetry events into evaluation", len(live_events))
                telemetry_events = list(telemetry_events or []) + live_events
        evaluations: List[Dict[str, Any]] = []
        blind_spot_findings: List[Finding] = []

        detected_count = 0
        logged_count = 0
        blind_spot_count = 0

        # Optional telemetry event search
        telemetry_text = ""
        if telemetry_events:
            telemetry_text = " ".join(str(e) for e in telemetry_events).lower()

        for tid in executed_techniques:
            rule = self.rules.get(tid)
            is_rule_active = False
            if rule and rule.enabled:
                if active_rules is None:
                    is_rule_active = True
                else:
                    is_rule_active = (rule.rule_id in active_rules or tid in active_rules)

            # Check if telemetry matched
            has_telemetry = False
            if telemetry_text:
                if tid.lower() in telemetry_text or (rule and rule.title.lower() in telemetry_text):
                    has_telemetry = True

            if is_rule_active:
                status = "DETECTED"
                detected_count += 1
            elif has_telemetry:
                status = "LOGGED_ONLY"
                logged_count += 1
            else:
                status = "BLIND_SPOT"
                blind_spot_count += 1

                # Generate a Finding for this defensive blind spot
                technique_title = rule.title if rule else f"MITRE Technique {tid}"
                severity = Severity.HIGH if tid in ["T1059.001", "T1518.001", "T1087.001"] else Severity.MEDIUM

                remediation_guide = (
                    f"Deploy SIEM/EDR detection rule for `{tid}`.\n"
                    f"Recommended Sigma rule definition:\n```yaml\n"
                    f"{rule.sigma_yaml if rule else '# Custom Sigma rule needed for ' + tid}\n```"
                )

                finding = Finding(
                    title=f"Defensive Blind Spot: Undetected TTP {tid} ({technique_title})",
                    description=(
                        f"Adversary technique {tid} ({technique_title}) executed successfully against `{target}`, "
                        "but triggered zero defensive alerts and matches no active detection rules."
                    ),
                    severity=severity,
                    target=target,
                    tool="detection_engine",
                    mitre_attack_ids=[tid],
                    remediation=remediation_guide,
                    raw_data={
                        "technique_id": tid,
                        "status": status,
                        "suggested_rule_id": rule.rule_id if rule else None,
                    },
                )
                blind_spot_findings.append(finding)

            evaluations.append({
                "technique_id": tid,
                "title": rule.title if rule else tid,
                "status": status,
                "rule_id": rule.rule_id if rule else None,
                "logsource": rule.logsource if rule else "unknown",
                "level": rule.level if rule else "low",
            })

        total = len(executed_techniques)
        vis_score = round(((detected_count + logged_count) / total * 100), 1) if total > 0 else 0.0
        det_score = round((detected_count / total * 100), 1) if total > 0 else 0.0

        return DetectionCoverageReport(
            total_tested=total,
            detected_count=detected_count,
            logged_count=logged_count,
            blind_spot_count=blind_spot_count,
            visibility_score=vis_score,
            detection_score=det_score,
            evaluations=evaluations,
            blind_spot_findings=blind_spot_findings,
        )

    def generate_markdown_summary(self, report: DetectionCoverageReport) -> str:
        """Render a clean Markdown scorecard table of purple team results."""
        lines = [
            "### Purple Team Adversary Emulation & Detection Matrix",
            "",
            f"- **Total Techniques Emulated:** {report.total_tested}",
            f"- **Techniques Detected (Active Rule):** {report.detected_count}",
            f"- **Techniques Logged (Telemetry Only):** {report.logged_count}",
            f"- **Defensive Blind Spots (Unmonitored):** {report.blind_spot_count}",
            f"- **Defensive Visibility Score:** `{report.visibility_score}%`",
            f"- **Alert Detection Score:** `{report.detection_score}%`",
            "",
            "| Technique ID | Technique Name | Status | Rule ID | Severity |",
            "|:---|:---|:---:|:---|:---:|",
        ]

        for ev in report.evaluations:
            status_badge = (
                "🛡️ DETECTED" if ev["status"] == "DETECTED"
                else ("📝 LOGGED" if ev["status"] == "LOGGED_ONLY" else "⚠️ BLIND SPOT")
            )
            rule_id = ev["rule_id"] or "None"
            lines.append(f"| `{ev['technique_id']}` | {ev['title']} | {status_badge} | `{rule_id}` | {ev['level'].upper()} |")

        return "\n".join(lines)
