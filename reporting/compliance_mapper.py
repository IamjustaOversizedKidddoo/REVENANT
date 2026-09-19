"""
REVENANT — Multi-Framework Compliance & Regulatory Mapper
Maps multi-domain findings to NIST AI RMF 1.0, OWASP Top 10 for LLMs v1.1,
CIS Controls v8, and OWASP Mobile Application Security Verification Standard (MASVS v2.0).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from control_plane.schemas.models import Finding, Severity

logger = logging.getLogger("revenant.reporting.compliance")


@dataclass
class ComplianceControl:
    """Individual compliance framework control or requirement."""
    framework: str        # "NIST_AI_RMF", "OWASP_LLM", "CIS_V8", "OWASP_MASVS"
    control_id: str       # e.g. "MEASURE-2.6", "LLM01", "CIS-16.1", "MASVS-PLATFORM-1"
    name: str
    description: str
    category: str         # e.g. "Govern", "Prompt Injection", "Application Security", "Platform"


# 1. NIST AI Risk Management Framework (AI RMF 1.0)
NIST_AI_RMF_CONTROLS: Dict[str, ComplianceControl] = {
    "GOVERN-1.1": ComplianceControl(
        framework="NIST_AI_RMF",
        control_id="GOVERN-1.1",
        name="AI Risk Governance Structure",
        description="Legal and regulatory requirements and organizational risk tolerances are identified and integrated.",
        category="GOVERN",
    ),
    "MAP-1.5": ComplianceControl(
        framework="NIST_AI_RMF",
        control_id="MAP-1.5",
        name="AI System Classification & Context",
        description="Business requirements, context, and operational deployment scopes of the AI system are documented.",
        category="MAP",
    ),
    "MEASURE-2.6": ComplianceControl(
        framework="NIST_AI_RMF",
        control_id="MEASURE-2.6",
        name="AI Safety & Adversarial Robustness",
        description="The AI system is evaluated for adversarial attacks, prompt injection, jailbreaks, and evasions.",
        category="MEASURE",
    ),
    "MEASURE-2.7": ComplianceControl(
        framework="NIST_AI_RMF",
        control_id="MEASURE-2.7",
        name="AI Residual Risk & Privacy Protection",
        description="Training data leakage, sensitive context extraction, and PII exposure risks are quantified.",
        category="MEASURE",
    ),
    "MANAGE-1.3": ComplianceControl(
        framework="NIST_AI_RMF",
        control_id="MANAGE-1.3",
        name="Adversarial Response & Mitigation",
        description="Incident handling and safety guardrail mitigation mechanisms for model prompt attacks are activated.",
        category="MANAGE",
    ),
    "MANAGE-2.4": ComplianceControl(
        framework="NIST_AI_RMF",
        control_id="MANAGE-2.4",
        name="Autonomous Agent Agency & Tool Authorization",
        description="Excessive agency, unconstrained tool invocation, and downstream arbitrary action risks are monitored.",
        category="MANAGE",
    ),
}

# 2. OWASP Top 10 for LLM Applications v1.1
OWASP_LLM_CONTROLS: Dict[str, ComplianceControl] = {
    "LLM01": ComplianceControl(
        framework="OWASP_LLM",
        control_id="LLM01",
        name="Prompt Injection",
        description="Direct and indirect adversarial manipulation of LLM behavior via untrusted inputs.",
        category="Prompt Injection",
    ),
    "LLM02": ComplianceControl(
        framework="OWASP_LLM",
        control_id="LLM02",
        name="Insecure Output Handling",
        description="Unvalidated or unsanitized model output forwarded to downstream interpreters (XSS, SSRF, RCE).",
        category="Output Handling",
    ),
    "LLM06": ComplianceControl(
        framework="OWASP_LLM",
        control_id="LLM06",
        name="Sensitive Information Disclosure",
        description="Model reveals confidential training data, proprietary system prompts, secrets, or PII.",
        category="Data Disclosure",
    ),
    "LLM08": ComplianceControl(
        framework="OWASP_LLM",
        control_id="LLM08",
        name="Excessive Agency",
        description="Autonomous LLM agents granted disproportionate permissions, tools, or unintended actions.",
        category="Agent Agency",
    ),
    "LLM09": ComplianceControl(
        framework="OWASP_LLM",
        control_id="LLM09",
        name="Overreliance",
        description="Failing to verify model suggestions, resulting in uninspected vulnerable code or hallucinations.",
        category="Overreliance",
    ),
}

# 3. CIS Critical Security Controls v8
CIS_V8_CONTROLS: Dict[str, ComplianceControl] = {
    "CIS-3": ComplianceControl(
        framework="CIS_V8",
        control_id="CIS-3",
        name="Data Protection",
        description="Develop and maintain processes and technical controls to protect data confidentiality and integrity.",
        category="Data Protection",
    ),
    "CIS-4": ComplianceControl(
        framework="CIS_V8",
        control_id="CIS-4",
        name="Secure Configuration of Enterprise Assets and Software",
        description="Establish and maintain the secure configuration of enterprise assets and software.",
        category="Configuration",
    ),
    "CIS-5": ComplianceControl(
        framework="CIS_V8",
        control_id="CIS-5",
        name="Account Management",
        description="Manage the lifecycle of system and user accounts, credentials, and privileged access.",
        category="Identity & Access",
    ),
    "CIS-6": ComplianceControl(
        framework="CIS_V8",
        control_id="CIS-6",
        name="Access Control Management",
        description="Use processes and tools to assign and revoke access credentials and privileges.",
        category="Access Control",
    ),
    "CIS-7": ComplianceControl(
        framework="CIS_V8",
        control_id="CIS-7",
        name="Continuous Vulnerability Management",
        description="Develop a plan to assess and track vulnerabilities on enterprise assets.",
        category="Vulnerability Management",
    ),
    "CIS-8": ComplianceControl(
        framework="CIS_V8",
        control_id="CIS-8",
        name="Audit Log Management",
        description="Collect, alert, review, and retain audit logs of events that could help detect security incidents.",
        category="Logging & Detection",
    ),
    "CIS-16": ComplianceControl(
        framework="CIS_V8",
        control_id="CIS-16",
        name="Application Software Security",
        description="Manage the security life cycle of in-house developed and acquired software.",
        category="Application Security",
    ),
}

# 4. OWASP Mobile Application Security Verification Standard (MASVS v2.0)
OWASP_MASVS_CONTROLS: Dict[str, ComplianceControl] = {
    "MASVS-STORAGE": ComplianceControl(
        framework="OWASP_MASVS",
        control_id="MASVS-STORAGE",
        name="Secure Data Storage",
        description="The app securely stores sensitive data on the device using OS encryption and keystore facilities.",
        category="Storage",
    ),
    "MASVS-CRYPTO": ComplianceControl(
        framework="OWASP_MASVS",
        control_id="MASVS-CRYPTO",
        name="Cryptographic Architecture",
        description="The app employs modern, industry-standard cryptographic algorithms and secure key generation.",
        category="Cryptography",
    ),
    "MASVS-NETWORK": ComplianceControl(
        framework="OWASP_MASVS",
        control_id="MASVS-NETWORK",
        name="Secure Network Communications",
        description="The app encrypts all network traffic via TLS and restricts insecure cleartext HTTP channels.",
        category="Network",
    ),
    "MASVS-PLATFORM": ComplianceControl(
        framework="OWASP_MASVS",
        control_id="MASVS-PLATFORM",
        name="Secure Platform Interaction",
        description="The app securely handles IPC, intent filters, broadcast receivers, and exported Android/iOS components.",
        category="Platform",
    ),
    "MASVS-CODE": ComplianceControl(
        framework="OWASP_MASVS",
        control_id="MASVS-CODE",
        name="Code Quality & Build Settings",
        description="The app is built with production hardening (compiler defenses, debuggable=false, secure webviews).",
        category="Code Quality",
    ),
}


class ComplianceMapper:
    """
    Evaluates findings across multiple compliance frameworks and computes
    audit readiness and control failure distributions.
    """

    def __init__(self):
        self.frameworks = {
            "NIST_AI_RMF": NIST_AI_RMF_CONTROLS,
            "OWASP_LLM": OWASP_LLM_CONTROLS,
            "CIS_V8": CIS_V8_CONTROLS,
            "OWASP_MASVS": OWASP_MASVS_CONTROLS,
        }

    def map_finding_to_controls(self, finding: Finding) -> List[ComplianceControl]:
        """Map a single finding to all relevant compliance controls."""
        matched: List[ComplianceControl] = []
        cwe = (finding.cwe or "").upper()
        title = finding.title.lower()
        tool = finding.tool.lower()
        owasp = (finding.owasp_category or "").upper()
        mitre = [m.upper() for m in finding.mitre_attack_ids]

        # 1. NIST AI RMF & OWASP LLM mappings
        if "LLM" in owasp or "ai" in tool or "garak" in tool or "promptfoo" in tool or "agent" in title:
            if "LLM01" in owasp or "injection" in title or "cwe-77" in cwe:
                matched.append(NIST_AI_RMF_CONTROLS["MEASURE-2.6"])
                matched.append(NIST_AI_RMF_CONTROLS["MANAGE-1.3"])
                matched.append(OWASP_LLM_CONTROLS["LLM01"])
            if "LLM02" in owasp or "output" in title or "cwe-79" in cwe:
                matched.append(OWASP_LLM_CONTROLS["LLM02"])
            if "LLM06" in owasp or "system prompt" in title or "cwe-200" in cwe or "cwe-798" in cwe:
                matched.append(NIST_AI_RMF_CONTROLS["MEASURE-2.7"])
                matched.append(OWASP_LLM_CONTROLS["LLM06"])
            if "LLM08" in owasp or "agency" in title or "cwe-284" in cwe:
                matched.append(NIST_AI_RMF_CONTROLS["MANAGE-2.4"])
                matched.append(OWASP_LLM_CONTROLS["LLM08"])

        # 2. OWASP MASVS mappings
        if "MASVS" in owasp or "mobile" in tool or "mobsf" in tool:
            if "MASVS-PLATFORM" in owasp or "exported" in title or "cwe-926" in cwe:
                matched.append(OWASP_MASVS_CONTROLS["MASVS-PLATFORM"])
            if "MASVS-NETWORK" in owasp or "cleartext" in title or "cwe-319" in cwe:
                matched.append(OWASP_MASVS_CONTROLS["MASVS-NETWORK"])
            if "MASVS-CRYPTO" in owasp or "secret" in title or "cwe-798" in cwe or "random" in title:
                matched.append(OWASP_MASVS_CONTROLS["MASVS-CRYPTO"])
            if "MASVS-CODE" in owasp or "debug" in title or "webview" in title:
                matched.append(OWASP_MASVS_CONTROLS["MASVS-CODE"])
            if "MASVS-STORAGE" in owasp or "storage" in title or "cwe-276" in cwe:
                matched.append(OWASP_MASVS_CONTROLS["MASVS-STORAGE"])

        # 3. CIS Controls v8 mappings (universal)
        if cwe == "CWE-798" or "secret" in title or "credential" in title:
            matched.append(CIS_V8_CONTROLS["CIS-3"])
        if "cloud" in tool or "checkov" in tool or "prowler" in tool or "trivy" in tool:
            matched.append(CIS_V8_CONTROLS["CIS-4"])
        if "bloodhound" in tool or "certipy" in tool or "netexec" in tool or "identity" in tool:
            matched.append(CIS_V8_CONTROLS["CIS-5"])
            matched.append(CIS_V8_CONTROLS["CIS-6"])
        if tool in ["nuclei", "dast", "semgrep", "gitleaks", "trufflehog", "mobsfscan"]:
            matched.append(CIS_V8_CONTROLS["CIS-16"])
        if tool in ["atomic_red_team", "detection_engine", "caldera"] or "blind spot" in title:
            matched.append(CIS_V8_CONTROLS["CIS-8"])

        # Default fallback for general vulnerabilities
        matched.append(CIS_V8_CONTROLS["CIS-7"])

        # De-duplicate
        seen_ids = set()
        unique_matches = []
        for c in matched:
            if (c.framework, c.control_id) not in seen_ids:
                seen_ids.add((c.framework, c.control_id))
                unique_matches.append(c)

        return unique_matches

    def evaluate_compliance(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Evaluate a complete list of findings against all 4 frameworks.
        Calculates affected controls, total violations, and compliance posture.
        """
        framework_summary: Dict[str, Dict[str, Any]] = {
            "NIST_AI_RMF": {"total_controls": len(NIST_AI_RMF_CONTROLS), "failed_controls": {}, "findings_count": 0},
            "OWASP_LLM": {"total_controls": len(OWASP_LLM_CONTROLS), "failed_controls": {}, "findings_count": 0},
            "CIS_V8": {"total_controls": len(CIS_V8_CONTROLS), "failed_controls": {}, "findings_count": 0},
            "OWASP_MASVS": {"total_controls": len(OWASP_MASVS_CONTROLS), "failed_controls": {}, "findings_count": 0},
        }

        for f in findings:
            controls = self.map_finding_to_controls(f)
            for ctrl in controls:
                fw_data = framework_summary[ctrl.framework]
                fw_data["findings_count"] += 1
                if ctrl.control_id not in fw_data["failed_controls"]:
                    fw_data["failed_controls"][ctrl.control_id] = {
                        "control_id": ctrl.control_id,
                        "name": ctrl.name,
                        "category": ctrl.category,
                        "description": ctrl.description,
                        "findings": [],
                    }
                fw_data["failed_controls"][ctrl.control_id]["findings"].append(f.title)

        # Compute posture scores (% of controls without violations)
        for fw_name, data in framework_summary.items():
            total = data["total_controls"]
            failed = len(data["failed_controls"])
            passed = max(0, total - failed)
            posture_pct = round((passed / total * 100), 1) if total > 0 else 100.0
            data["passed_controls_count"] = passed
            data["failed_controls_count"] = failed
            data["posture_percentage"] = posture_pct

        return framework_summary

    def generate_markdown_summary(self, findings: List[Finding]) -> str:
        """Render an executive compliance posture scorecard."""
        eval_data = self.evaluate_compliance(findings)
        lines = [
            "### Enterprise Regulatory & Compliance Posture",
            "",
            "| Framework | Total Controls | Passing | Violations | Posture Score |",
            "|:---|:---:|:---:|:---:|:---:|",
        ]

        fw_titles = {
            "NIST_AI_RMF": "NIST AI RMF 1.0 (AI Risk Management)",
            "OWASP_LLM": "OWASP Top 10 for LLM Applications v1.1",
            "CIS_V8": "CIS Critical Security Controls v8",
            "OWASP_MASVS": "OWASP Mobile Security Verification (MASVS v2.0)",
        }

        for fw_key, title in fw_titles.items():
            data = eval_data[fw_key]
            badge = "🟢" if data["posture_percentage"] >= 80 else ("🟡" if data["posture_percentage"] >= 50 else "🔴")
            lines.append(
                f"| **{title}** | {data['total_controls']} | {data['passed_controls_count']} | {data['failed_controls_count']} | {badge} `{data['posture_percentage']}%` |"
            )

        lines.extend([
            "",
            "#### Control Violation Highlights",
            "",
        ])

        has_any_violations = False
        for fw_key, title in fw_titles.items():
            data = eval_data[fw_key]
            if data["failed_controls"]:
                has_any_violations = True
                lines.append(f"**{title}:**")
                for cid, cinfo in data["failed_controls"].items():
                    count = len(cinfo["findings"])
                    lines.append(f"- `{cid}` ({cinfo['name']}): **{count}** finding(s)")
                lines.append("")

        if not has_any_violations:
            lines.append("*All evaluated compliance framework controls passed without findings.*")

        return "\n".join(lines)
