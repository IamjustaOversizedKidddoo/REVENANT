"""REVENANT — Analyst / Narrator (post-campaign enrichment).

Turns a raw finding set into a structured *intelligence brief* with four sections:

    a) MIF per finding          — Mechanism / Impact / Fix.
    b) Attack-path prediction   — findings chained into likely kill-chains, each with a
                                  confidence and blast-radius note.
    c) Prioritized next steps   — ranked actions with why / expected outcome / risk-noise
                                  / prerequisites.
    d) Executive summary        — CISO business-language, no jargon.

When an LLM is configured (``ANTHROPIC_API_KEY`` + the ``[llm]`` extra) the brief is
produced by the model; otherwise a deterministic, template-based analyzer builds the
same structure from the finding fields (severity, cwe, owasp_category,
mitre_attack_ids). The fallback never raises and never requires a network call, so a
scan always gets a brief.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from intelligence.llm_client import LlmClient, LLMUnavailable

logger = logging.getLogger("revenant.analyst")

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# --------------------------------------------------------------------------- #
# Deterministic knowledge base keyed by CWE / keyword. Accurate, concise MIF   #
# text and kill-chain templates used by the no-LLM fallback path.             #
# --------------------------------------------------------------------------- #

# (matcher substrings, cwe) -> dict(mechanism, impact, fix, chain, blast)
_VULN_KB = [
    {
        "match": ["sql injection", "sqli"],
        "cwe": "CWE-89",
        "mechanism": "User input is concatenated into a SQL query instead of being passed as a bound parameter, so attacker-controlled text is parsed as SQL.",
        "impact": "Authentication bypass and full read/write of the database — dumping every user credential, reading or altering any record.",
        "fix": "Use parameterized queries / prepared statements (bound parameters) everywhere; apply least-privilege DB accounts; never build SQL via string formatting.",
        "chain": "SQL injection -> authentication bypass / full DB dump -> harvested credentials -> lateral movement into other systems",
        "blast": "Entire application database and every user account.",
    },
    {
        "match": ["path traversal", "directory traversal", "lfi", "local file"],
        "cwe": "CWE-22",
        "mechanism": "A file path is built from unsanitized user input, so '../' sequences escape the intended directory and resolve to arbitrary files.",
        "impact": "Arbitrary file read on the server — source code, configuration, and secrets such as /etc/passwd or .env credentials.",
        "fix": "Resolve and canonicalize the path, then verify it stays within an allow-listed base directory; reject '..' and absolute paths; serve files by opaque ID.",
        "chain": "Path traversal -> read config/.env -> recovered DB creds / API keys -> privilege escalation -> deeper compromise",
        "blast": "Any file readable by the web process, including secrets that unlock other systems.",
    },
    {
        "match": ["xss", "cross-site scripting", "cross site scripting"],
        "cwe": "CWE-79",
        "mechanism": "User input is reflected into an HTML response without output encoding, so injected <script> executes in the victim's browser in the site's origin.",
        "impact": "Session and credential theft, request forgery as the victim, and defacement — an admin victim yields admin access.",
        "fix": "Context-aware output encoding on all reflected data; a strict Content-Security-Policy; HttpOnly + SameSite cookies.",
        "chain": "Reflected XSS -> steal session cookie / token -> ride a logged-in (admin) session -> account takeover",
        "blast": "Every user who opens a crafted link, including privileged operators.",
    },
    {
        "match": ["open redirect", "open redirection"],
        "cwe": "CWE-601",
        "mechanism": "A redirect destination is taken from user input and followed without validation, so a trusted link forwards victims to an attacker site.",
        "impact": "Convincing phishing and OAuth token leakage — the link carries the trusted domain but lands on attacker infrastructure.",
        "fix": "Redirect only to an allow-list of internal paths/hosts; never redirect to a raw user-supplied absolute URL.",
        "chain": "Open redirect -> phishing with a trusted domain -> credential harvest / token theft",
        "blast": "Users and brand trust; amplifies any credential-phishing campaign.",
    },
    {
        "match": ["ssrf", "server-side request forgery"],
        "cwe": "CWE-918",
        "mechanism": "The server fetches a URL supplied by the user, letting an attacker pivot requests through the server to internal or cloud-metadata endpoints.",
        "impact": "Access to internal services and cloud instance metadata (IAM credentials) normally unreachable from outside.",
        "fix": "Allow-list outbound hosts, block link-local/metadata ranges, disable unused URL schemes, and require egress proxying.",
        "chain": "SSRF -> cloud metadata endpoint -> temporary IAM keys -> cloud account access -> account takeover",
        "blast": "Internal network and the cloud account hosting the application.",
    },
    {
        "match": ["secret", "api key", "credential", "token exposed", "hardcoded"],
        "cwe": "CWE-798",
        "mechanism": "A live secret (API key, password, token) is committed in code or exposed by an endpoint, so anyone who reads it authenticates as the owner.",
        "impact": "Immediate authenticated access to whatever the secret unlocks — cloud accounts, databases, third-party APIs.",
        "fix": "Rotate the exposed secret now; move secrets to a vault/secret manager; add pre-commit secret scanning; scope keys to least privilege.",
        "chain": "Exposed secret -> authenticated access to a backend service -> data access / privilege escalation",
        "blast": "Every system the leaked credential is authorized to reach.",
    },
    {
        "match": ["misconfig", "public bucket", "s3", "exposed storage", "open port", "default credential"],
        "cwe": "CWE-16",
        "mechanism": "A service is deployed with insecure defaults or overly permissive access, exposing data or management surfaces that should be private.",
        "impact": "Direct data exposure or an easy foothold without any exploit — often the start of a full-account compromise.",
        "fix": "Apply a hardened baseline (CIS benchmark), make storage private by default, and enforce it with IaC policy checks in CI.",
        "chain": "Public storage / misconfig -> exposed .env or data -> IAM keys -> privilege escalation -> account takeover",
        "blast": "Whatever the exposed service holds, and anything its credentials reach.",
    },
]

_GENERIC_KB = {
    "mechanism": "A weakness in input handling or configuration lets an attacker influence behavior the application assumes is trusted.",
    "impact": "Depending on context, loss of confidentiality, integrity, or availability of the affected component.",
    "fix": "Validate and encode untrusted input at the boundary, apply least privilege, and add a regression test for this case.",
    "chain": "Initial access via this weakness -> expanded access to adjacent data or functions",
    "blast": "The affected component and data directly reachable from it.",
}


def _kb_for(view: Dict[str, Any]) -> Dict[str, str]:
    """Pick the best knowledge-base entry for a normalized finding."""
    haystack = " ".join(
        str(view.get(k) or "") for k in ("title", "description", "owasp_category")
    ).lower()
    cwe = (view.get("cwe") or "").upper()
    for entry in _VULN_KB:
        if cwe and cwe == entry["cwe"]:
            return entry
        if any(m in haystack for m in entry["match"]):
            return entry
    return _GENERIC_KB


def _normalize(f: Any) -> Dict[str, Any]:
    """Coerce a Finding model or a report.json dict into a flat field view."""
    def get(name: str, default=None):
        if isinstance(f, dict):
            return f.get(name, default)
        return getattr(f, name, default)

    sev = get("severity", "INFO")
    sev = getattr(sev, "value", sev)  # Severity enum -> str
    return {
        "title": get("title") or "Unnamed finding",
        "description": get("description") or "",
        "severity": str(sev).upper(),
        "target": get("target") or "",
        "tool": get("tool") or "",
        "cve": get("cve"),
        "cwe": get("cwe"),
        "cvss_score": get("cvss_score"),
        "mitre_attack_ids": list(get("mitre_attack_ids", []) or []),
        "owasp_category": get("owasp_category"),
        "endpoint": get("endpoint"),
        "remediation": get("remediation"),
    }


class AnalystNarrator:
    """Produce a structured intelligence brief from a campaign's findings.

    Parameters
    ----------
    findings : list
        ``Finding`` models or report.json finding dicts.
    assets : list, optional
        Discovered assets (models or dicts); used only for context/counts.
    summary : dict, optional
        Blackboard summary (counts). Recomputed from findings if omitted.
    target : str, optional
        The campaign target, for headings.
    llm_client : LlmClient, optional
        Injectable for testing. Defaults to an env-configured client.
    """

    def __init__(
        self,
        findings: List[Any],
        assets: Optional[List[Any]] = None,
        summary: Optional[Dict[str, Any]] = None,
        target: Optional[str] = None,
        llm_client: Optional[LlmClient] = None,
    ) -> None:
        self.findings = [_normalize(f) for f in (findings or [])]
        self.findings.sort(key=lambda v: SEVERITY_RANK.get(v["severity"], 9))
        self.assets = assets or []
        self.target = target or "the assessed target"
        self.summary = summary or self._counts()
        self.llm = llm_client if llm_client is not None else LlmClient()

    # -- public API --------------------------------------------------------

    def build(self) -> Dict[str, Any]:
        """Return the intelligence brief as a dict (LLM path, else deterministic)."""
        brief: Optional[Dict[str, Any]] = None
        if self.llm.available():
            try:
                brief = self._build_llm()
            except LLMUnavailable as exc:
                logger.info("Analyst LLM path unavailable (%s); using fallback.", exc)
            except Exception as exc:  # never let enrichment break a run
                logger.warning("Analyst LLM path errored (%s); using fallback.", exc)
        if not brief:
            brief = self._build_fallback()
        brief["target"] = self.target
        brief["generated_at"] = datetime.now(timezone.utc).isoformat()
        brief["finding_count"] = len(self.findings)
        return brief

    def render_markdown(self, brief: Optional[Dict[str, Any]] = None) -> str:
        """Render a brief (built if not supplied) as an analysis.md document."""
        brief = brief or self.build()
        lines: List[str] = [
            "# REVENANT Intelligence Brief",
            "",
            f"**Target:** `{brief.get('target', self.target)}`  ",
            f"**Findings analyzed:** {brief.get('finding_count', len(self.findings))}  ",
            f"**Generated:** {brief.get('generated_at', '')}  ",
            f"**Analysis mode:** {brief.get('mode', 'fallback')}  ",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            brief.get("executive_summary", ""),
            "",
            "---",
            "",
            "## Finding Analysis — Mechanism / Impact / Fix",
            "",
        ]
        mif = brief.get("mif", [])
        if not mif:
            lines.append("*No findings to analyze.*")
        for i, item in enumerate(mif, 1):
            lines.extend([
                f"### {i}. [{item.get('severity', 'INFO')}] {item.get('title', '')}",
                f"- **Mechanism:** {item.get('mechanism', '')}",
                f"- **Impact:** {item.get('impact', '')}",
                f"- **Fix:** {item.get('fix', '')}",
                "",
            ])

        lines.extend(["---", "", "## Attack-Path Prediction", ""])
        paths = brief.get("attack_paths", [])
        if not paths:
            lines.append("*No multi-step attack paths predicted from the current findings.*")
        for i, p in enumerate(paths, 1):
            lines.extend([
                f"### Chain {i}: {p.get('name', 'Predicted chain')}",
                f"- **Path:** {p.get('chain', '')}",
                f"- **Confidence:** {p.get('confidence', 'n/a')}",
                f"- **Blast radius:** {p.get('blast_radius', '')}",
                "",
            ])

        lines.extend(["---", "", "## Prioritized Next Steps", ""])
        steps = brief.get("next_steps", [])
        if not steps:
            lines.append("*No further actions recommended.*")
        for i, s in enumerate(steps, 1):
            lines.extend([
                f"### {i}. {s.get('action', '')}",
                f"- **Why:** {s.get('why', '')}",
                f"- **Expected outcome:** {s.get('expected_outcome', '')}",
                f"- **Risk / noise:** {s.get('risk', '')}",
                f"- **Prerequisites:** {s.get('prerequisites', '')}",
                "",
            ])
        return "\n".join(lines)

    def run_and_save(self, output_dir: str) -> Dict[str, Any]:
        """Build the brief and write analysis.md + analysis.json into ``output_dir``."""
        brief = self.build()
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "analysis.md").write_text(self.render_markdown(brief), encoding="utf-8")
        (out / "analysis.json").write_text(json.dumps(brief, indent=2), encoding="utf-8")
        return brief

    # -- deterministic fallback -------------------------------------------

    def _counts(self) -> Dict[str, Any]:
        counts = {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        for v in self.findings:
            counts[v["severity"]] = counts.get(v["severity"], 0) + 1
        return {"findings_by_severity": counts, "total_findings": len(self.findings)}

    def _build_fallback(self) -> Dict[str, Any]:
        mif = []
        for v in self.findings:
            kb = _kb_for(v)
            mif.append({
                "title": v["title"],
                "severity": v["severity"],
                "endpoint": v["endpoint"] or v["target"],
                "cwe": v["cwe"],
                "mechanism": kb["mechanism"],
                "impact": kb["impact"],
                # Prefer the tool's own remediation if present, else the KB fix.
                "fix": v["remediation"] or kb["fix"],
            })

        attack_paths = self._fallback_attack_paths()
        next_steps = self._fallback_next_steps()
        exec_summary = self._fallback_exec_summary()
        return {
            "mode": "fallback",
            "executive_summary": exec_summary,
            "mif": mif,
            "attack_paths": attack_paths,
            "next_steps": next_steps,
        }

    def _fallback_attack_paths(self) -> List[Dict[str, Any]]:
        paths: List[Dict[str, Any]] = []
        seen = set()
        for v in self.findings:
            kb = _kb_for(v)
            if kb is _GENERIC_KB:
                continue
            key = kb["chain"]
            if key in seen:
                continue
            seen.add(key)
            # Confidence tracks the severity of the seeding finding.
            conf = {"CRITICAL": "High", "HIGH": "High", "MEDIUM": "Medium"}.get(v["severity"], "Low")
            paths.append({
                "name": v["title"],
                "chain": kb["chain"],
                "confidence": conf,
                "blast_radius": kb["blast"],
                "seed_finding": v["title"],
            })
        # If multiple high/critical findings exist, note a compound compromise.
        highs = [v for v in self.findings if v["severity"] in ("CRITICAL", "HIGH")]
        if len(highs) >= 2:
            paths.append({
                "name": "Compound compromise",
                "chain": " + ".join(sorted({h["title"] for h in highs}))
                + " chained together -> data theft + secret recovery + session hijack -> effective full application and user compromise",
                "confidence": "High",
                "blast_radius": "The application, its data store, and its user base together.",
                "seed_finding": "multiple",
            })
        return paths

    def _fallback_next_steps(self) -> List[Dict[str, Any]]:
        steps: List[Dict[str, Any]] = []
        # One remediation-oriented step per severe finding, highest first.
        for v in self.findings:
            if v["severity"] not in ("CRITICAL", "HIGH"):
                continue
            kb = _kb_for(v)
            where = v["endpoint"] or v["target"]
            steps.append({
                "action": f"Remediate and re-test {v['title']} at {where}",
                "why": f"{v['severity']} severity; {kb['impact']}",
                "expected_outcome": "Vulnerability closed and confirmed fixed on re-scan.",
                "risk": "Low — remediation and a scoped re-test are non-destructive.",
                "prerequisites": "Code/owner access to the affected component; a staging copy to validate the fix.",
            })
        if not steps and self.findings:
            v = self.findings[0]
            steps.append({
                "action": f"Review and triage {v['title']}",
                "why": "Highest-ranked finding in this campaign.",
                "expected_outcome": "Confirmed severity and an owner assigned.",
                "risk": "Low — review only.",
                "prerequisites": "Access to the finding evidence.",
            })
        if not steps:
            steps.append({
                "action": "Broaden coverage with an authorized full-spectrum scan",
                "why": "No findings surfaced; confirm the surface was fully exercised.",
                "expected_outcome": "Either validated clean posture or newly surfaced issues.",
                "risk": "Low — authorized, scoped testing.",
                "prerequisites": "A target you own or are authorized to test.",
            })
        return steps

    def _fallback_exec_summary(self) -> str:
        c = self.summary.get("findings_by_severity", {})
        crit, high = c.get("CRITICAL", 0), c.get("HIGH", 0)
        med, low = c.get("MEDIUM", 0), c.get("LOW", 0)
        total = len(self.findings)
        if total == 0:
            return (
                f"This assessment of {self.target} surfaced no confirmed security issues. "
                "That is a point-in-time result for the tested surface, not a guarantee; "
                "we recommend keeping the assessment cadence and expanding coverage as the "
                "application changes."
            )
        worst = "critical" if crit else ("high-severity" if high else "moderate")
        headline = (
            f"The assessment of {self.target} identified {total} security "
            f"{'issue' if total == 1 else 'issues'} "
            f"({crit} critical, {high} high, {med} medium, {low} low)."
        )
        if crit or high:
            business = (
                " The most serious of these would let an attacker access sensitive data, "
                "impersonate users, or take over accounts without authorization — a direct "
                "risk to customer trust, regulatory standing, and revenue. These should be "
                "scheduled for remediation ahead of lower-severity items."
            )
        else:
            business = (
                " None reach critical or high severity, so the immediate business risk is "
                "limited, but the issues should still be fixed to reduce cumulative exposure."
            )
        return (
            headline + business +
            f" Remediation guidance is provided per finding; the {worst} items are the "
            "priority and can be fixed and re-verified without disruption."
        )

    # -- LLM path ----------------------------------------------------------

    def _llm_findings_payload(self) -> str:
        slim = [
            {
                "title": v["title"],
                "severity": v["severity"],
                "endpoint": v["endpoint"] or v["target"],
                "cwe": v["cwe"],
                "owasp_category": v["owasp_category"],
                "mitre_attack_ids": v["mitre_attack_ids"],
                "description": (v["description"] or "")[:600],
            }
            for v in self.findings
        ]
        return json.dumps({"target": self.target, "findings": slim}, indent=2)

    def _build_llm(self) -> Dict[str, Any]:
        system = (
            "You are a senior offensive-security analyst writing an intelligence brief for an "
            "authorized penetration test. Be accurate and concise. You MUST only reason about "
            "the findings and assets provided — never invent new targets, hosts, or endpoints. "
            "Respond with a SINGLE JSON object and nothing else."
        )
        schema = (
            '{"executive_summary": str (CISO business language, no jargon), '
            '"mif": [{"title": str, "severity": str, "mechanism": str, "impact": str, "fix": str}], '
            '"attack_paths": [{"name": str, "chain": str, "confidence": "High|Medium|Low", "blast_radius": str}], '
            '"next_steps": [{"action": str, "why": str, "expected_outcome": str, "risk": str, "prerequisites": str}]}'
        )
        user = (
            "Produce an intelligence brief for these findings. Return JSON matching exactly "
            f"this schema:\n{schema}\n\nFindings:\n{self._llm_findings_payload()}\n\n"
            "Include one MIF entry per finding. Chain findings into realistic kill-chains in "
            "attack_paths. Rank next_steps most-urgent first. JSON only."
        )
        raw = self.llm.complete(system, user)
        data = _extract_json(raw)
        if not isinstance(data, dict) or "mif" not in data:
            raise LLMUnavailable("LLM response was not valid brief JSON.")
        data.setdefault("executive_summary", "")
        data.setdefault("mif", [])
        data.setdefault("attack_paths", [])
        data.setdefault("next_steps", [])
        data["mode"] = "llm"
        return data


def _extract_json(text: str) -> Any:
    """Best-effort parse of a JSON object out of a model response."""
    text = text.strip()
    # Strip ``` fences if present.
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    return None
