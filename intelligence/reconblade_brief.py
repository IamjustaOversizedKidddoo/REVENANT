"""REVENANT — ReconBLADE-style findings brief (purely additive enrichment).

Re-presents the SAME findings REVENANT already produced in ReconBLADE's detailed,
triaged, "explain like in chat" style: per finding — What it is / Why it matters / Fix /
Next step / If you do it — plus a priority order and a 3-line summary. It never re-scans
and never touches existing reports; it writes a NEW findings_brief.md/json.

Tiers (same philosophy as the Analyst layer):
  1. DEFAULT (offline): build everything from intelligence.triage_kb — deterministic.
  2. OPTIONAL (ANTHROPIC_API_KEY set): ask the LLM to sharpen the narration; any error
     falls back to tier 1.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from intelligence import triage_kb
from intelligence.llm_client import LlmClient, LLMUnavailable

logger = logging.getLogger("revenant.reconblade")

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _normalize(f: Any) -> Dict[str, Any]:
    """Coerce a Finding model or report.json dict into the fields we use."""
    def get(name, default=None):
        if isinstance(f, dict):
            return f.get(name, default)
        return getattr(f, name, default)

    sev = get("severity", "INFO")
    sev = getattr(sev, "value", sev)
    return {
        "title": get("title") or "Unnamed finding",
        "description": get("description") or "",
        "severity": str(sev).upper(),
        "target": get("target") or "",
        "tool": get("tool") or "",
        "cwe": get("cwe"),
        "owasp_category": get("owasp_category"),
        "endpoint": get("endpoint"),
        "remediation": get("remediation"),
    }


class ReconBladeBrief:
    """Build a prioritized, KB-driven brief from existing findings."""

    def __init__(
        self,
        findings: List[Any],
        target: Optional[str] = None,
        llm_client: Optional[LlmClient] = None,
    ) -> None:
        self.findings = [_normalize(f) for f in (findings or [])]
        self.findings.sort(key=lambda v: SEVERITY_RANK.get(v["severity"], 9))
        self.target = target or "the assessed target"
        self.llm = llm_client if llm_client is not None else LlmClient()

    # -- public API --------------------------------------------------------

    def build(self) -> Dict[str, Any]:
        entries = [self._entry(v) for v in self.findings]
        brief: Dict[str, Any] = {
            "target": self.target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "finding_count": len(entries),
            "mode": "fallback",
            "summary": self._summary_lines(),
            "priority_order": [
                {"rank": i, "severity": e["severity"], "title": e["title"]}
                for i, e in enumerate(entries, 1)
            ],
            "entries": entries,
        }
        # Tier 2: optional LLM narration sharpening.
        if self.llm.available():
            try:
                self._enrich_with_llm(brief)
                brief["mode"] = "llm"
            except LLMUnavailable as exc:
                logger.info("ReconBlade LLM enrichment unavailable (%s); using KB only.", exc)
            except Exception as exc:
                logger.warning("ReconBlade LLM enrichment errored (%s); using KB only.", exc)
        return brief

    def render_markdown(self, brief: Optional[Dict[str, Any]] = None) -> str:
        brief = brief or self.build()
        lines: List[str] = [
            "# REVENANT Findings Brief (ReconBLADE style)",
            "",
            f"**Target:** `{brief['target']}`  ",
            f"**Findings:** {brief['finding_count']}  ",
            f"**Generated:** {brief['generated_at']}  ",
            f"**Mode:** {brief['mode']}  ",
            "",
            "## Summary",
            "",
        ]
        lines.extend(brief["summary"])
        lines.extend(["", "## Priority order", ""])
        if brief["priority_order"]:
            for p in brief["priority_order"]:
                lines.append(f"{p['rank']}. [{p['severity']}] {p['title']}")
        else:
            lines.append("*No findings.*")
        lines.extend(["", "---", "", "## Findings", ""])
        if not brief["entries"]:
            lines.append("*No findings to triage.*")
        for e in brief["entries"]:
            lines.extend([
                f"### [{e['severity']}] {e['title']}",
                f"- **What it is**: {e['what_it_is']}",
                f"- **Why it matters**: {e['why_it_matters']}",
                f"- **Fix**: {e['fix']}",
                f"- **Next step**: {e['next_step']}",
                f"- **If you do it**: {e['if_you_do_it']}",
                "",
            ])
        return "\n".join(lines)

    def run_and_save(self, output_dir: str) -> Dict[str, Any]:
        """Build and write findings_brief.md + findings_brief.json into output_dir."""
        brief = self.build()
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "findings_brief.md").write_text(self.render_markdown(brief), encoding="utf-8")
        (out / "findings_brief.json").write_text(json.dumps(brief, indent=2), encoding="utf-8")
        return brief

    # -- deterministic per-finding entry ----------------------------------

    def _entry(self, v: Dict[str, Any]) -> Dict[str, str]:
        text = f"{v['title']} {v['description']}"
        where = v["endpoint"] or v["target"]

        # Port- and header-specific findings get their specialized KB voice.
        port = triage_kb.detect_port(text)
        header = triage_kb.detect_header(text)

        if port is not None and triage_kb.port_info(port):
            kb = triage_kb.port_info(port)
            what = f"Port {port} ({kb['service']}) is exposed. {kb['service']} service detected."
            why = f"{kb['why_it_matters']} Common risks: {kb['common_risks']}"
            fix = v["remediation"] or kb["fix"]
            nxt = kb["next_step"]
            blast = f"{kb['service']} exposure and anything reachable through it"
        elif header is not None:
            kb = triage_kb.header_info(header)
            what = f"The `{header}` security header is missing. {kb['missing_means']}"
            why = kb["risk"]
            fix = v["remediation"] or kb["fix"]
            nxt = f"Add the header and re-check with `revenant {self.target}` or curl -I."
            blast = "users of the site via the weakness this header prevents"
        elif v["severity"] == "INFO":
            # Informational notes (e.g. "Technologies Detected") are context, not a
            # weakness — describe them neutrally instead of using the vuln template.
            what = (v["description"] or v["title"]).strip() or "Informational observation."
            why = ("Informational only — not a vulnerability by itself. Context like "
                   "detected technologies or versions narrows what an attacker would try next.")
            fix = v["remediation"] or ("No fix required. Reduce information disclosure "
                                       "(version banners, verbose headers) if the detail is sensitive.")
            nxt = "Record for context; no remediation needed unless it reveals something sensitive."
            blast = "none on its own; it only informs later steps"
        else:
            kb = triage_kb.finding_info(v["cwe"], v["owasp_category"], text)
            what = kb["plain_explanation"]
            why = kb["why_it_matters"]
            fix = v["remediation"] or kb["typical_fix"]
            nxt = kb["next_step"]
            blast = kb.get("blast", triage_kb._GENERIC_FINDING["blast"])

        if v["severity"] == "INFO":
            causal = f"Informational — no direct exploit; blast radius: {blast}."
        else:
            causal = (
                f"If you exploit this at `{where}` -> {why.rstrip('.').lower()}; "
                f"downstream blast radius: {blast}."
            )
        return {
            "title": v["title"],
            "severity": v["severity"],
            "endpoint": where,
            "cwe": v["cwe"] or "",
            "what_it_is": what,
            "why_it_matters": why,
            "fix": fix,
            "next_step": nxt,
            "if_you_do_it": causal,
        }

    def _summary_lines(self) -> List[str]:
        counts = {k: 0 for k in SEVERITY_RANK}
        for v in self.findings:
            counts[v["severity"]] = counts.get(v["severity"], 0) + 1
        total = len(self.findings)
        if total == 0:
            return [
                f"No findings to triage for {self.target}.",
                "Nothing to prioritize — the tested surface came back clean.",
                "Re-run against a broader scope or an authorized dynamic app to go deeper.",
            ]
        top = self.findings[0]
        return [
            f"{total} finding(s) for {self.target}: "
            f"{counts['CRITICAL']} critical, {counts['HIGH']} high, {counts['MEDIUM']} medium, "
            f"{counts['LOW']} low, {counts['INFO']} info.",
            f"Start with the highest-risk item: [{top['severity']}] {top['title']}.",
            "Each finding below has a plain explanation, a concrete fix, and the likely downstream impact.",
        ]

    # -- optional LLM enrichment (tier 2) ---------------------------------

    def _enrich_with_llm(self, brief: Dict[str, Any]) -> None:
        if not brief["entries"]:
            return
        system = (
            "You are a senior analyst refining a vulnerability brief for an AUTHORIZED test. "
            "Keep it accurate and concise. Do not invent findings or new targets. Return ONE "
            "JSON object: {\"entries\": [{\"title\": str, \"why_it_matters\": str, "
            "\"if_you_do_it\": str}]} refining ONLY those two narration fields for each given "
            "finding, preserving titles and order."
        )
        draft = [
            {"title": e["title"], "severity": e["severity"],
             "why_it_matters": e["why_it_matters"], "if_you_do_it": e["if_you_do_it"]}
            for e in brief["entries"]
        ]
        user = (
            f"Target: {brief['target']}\nSharpen these entries. JSON only.\n"
            + json.dumps({"entries": draft}, indent=2)
        )
        raw = self.llm.complete(system, user)
        data = _extract_json(raw)
        if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
            raise LLMUnavailable("LLM response was not valid brief JSON.")
        by_title = {str(x.get("title", "")): x for x in data["entries"] if isinstance(x, dict)}
        for e in brief["entries"]:
            ref = by_title.get(e["title"])
            if ref:
                if ref.get("why_it_matters"):
                    e["why_it_matters"] = str(ref["why_it_matters"])
                if ref.get("if_you_do_it"):
                    e["if_you_do_it"] = str(ref["if_you_do_it"])


def _extract_json(text: str) -> Any:
    import re

    text = (text or "").strip()
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
