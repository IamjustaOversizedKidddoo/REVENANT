"""Unit tests for the AI Analyst / Narrator (intelligence.analyst).

These exercise the DETERMINISTIC fallback path only: a stub LLM client reports itself
unavailable, so no network call is ever made and the template analyzer runs.
"""
from __future__ import annotations

import json

import pytest

from control_plane.schemas.models import Finding, Severity
from intelligence.analyst import AnalystNarrator


class _OfflineLLM:
    """Stand-in LLM client that forces the deterministic fallback."""

    model = "offline-test"

    def available(self) -> bool:
        return False

    def complete(self, system, user):  # pragma: no cover - must never be called
        raise AssertionError("LLM must not be called in the fallback path")


def _sample_findings():
    return [
        Finding(
            title="Error-Based SQL Injection in Parameter 'username'",
            description="sqlite3.OperationalError raised when injecting into username.",
            severity=Severity.CRITICAL,
            target="http://127.0.0.1:3000",
            tool="dast-fuzzer",
            cwe="CWE-89",
            endpoint="http://127.0.0.1:3000/login",
            owasp_category="A03:2021-Injection",
        ),
        Finding(
            title="Path Traversal in Parameter 'file'",
            description="'root:' detected after ../../etc/passwd payload.",
            severity=Severity.CRITICAL,
            target="http://127.0.0.1:3000",
            tool="dast-fuzzer",
            cwe="CWE-22",
            endpoint="http://127.0.0.1:3000/view",
        ),
        Finding(
            title="Reflected XSS in Parameter 'query'",
            description="Script payload reflected unescaped.",
            severity=Severity.HIGH,
            target="http://127.0.0.1:3000",
            tool="dast-fuzzer",
            cwe="CWE-79",
            endpoint="http://127.0.0.1:3000/search",
        ),
        Finding(
            title="Open Redirection in Parameter 'next'",
            description="302 to attacker-controlled host.",
            severity=Severity.MEDIUM,
            target="http://127.0.0.1:3000",
            tool="dast-fuzzer",
            cwe="CWE-601",
            endpoint="http://127.0.0.1:3000/redirect",
        ),
    ]


def test_fallback_builds_all_four_sections():
    analyst = AnalystNarrator(_sample_findings(), target="http://127.0.0.1:3000", llm_client=_OfflineLLM())
    brief = analyst.build()

    assert brief["mode"] == "fallback"
    # a) MIF per finding
    assert len(brief["mif"]) == 4
    for item in brief["mif"]:
        assert item["mechanism"] and item["impact"] and item["fix"]
    # b) attack-path prediction
    assert brief["attack_paths"], "expected at least one predicted kill-chain"
    for p in brief["attack_paths"]:
        assert p["confidence"] in ("High", "Medium", "Low")
        assert p["blast_radius"]
    # c) prioritized next steps
    assert brief["next_steps"]
    for s in brief["next_steps"]:
        for key in ("action", "why", "expected_outcome", "risk", "prerequisites"):
            assert s[key]
    # d) executive summary (business language, mentions counts)
    assert "critical" in brief["executive_summary"].lower()


def test_mif_uses_cwe_specific_knowledge():
    analyst = AnalystNarrator(_sample_findings(), llm_client=_OfflineLLM())
    brief = analyst.build()
    sqli = next(m for m in brief["mif"] if "SQL Injection" in m["title"])
    assert "parameterized" in sqli["fix"].lower()
    assert "database" in sqli["impact"].lower()


def test_compound_chain_when_multiple_high_severity():
    analyst = AnalystNarrator(_sample_findings(), llm_client=_OfflineLLM())
    brief = analyst.build()
    names = [p["name"] for p in brief["attack_paths"]]
    assert "Compound compromise" in names


def test_markdown_renders_headings():
    analyst = AnalystNarrator(_sample_findings(), target="http://127.0.0.1:3000", llm_client=_OfflineLLM())
    md = analyst.render_markdown()
    for heading in (
        "# REVENANT Intelligence Brief",
        "## Executive Summary",
        "## Finding Analysis",
        "## Attack-Path Prediction",
        "## Prioritized Next Steps",
    ):
        assert heading in md


def test_run_and_save_writes_both_files(tmp_path):
    analyst = AnalystNarrator(_sample_findings(), llm_client=_OfflineLLM())
    brief = analyst.run_and_save(str(tmp_path))
    md = tmp_path / "analysis.md"
    js = tmp_path / "analysis.json"
    assert md.exists() and js.exists()
    loaded = json.loads(js.read_text(encoding="utf-8"))
    assert loaded["mif"] == brief["mif"]
    assert "# REVENANT Intelligence Brief" in md.read_text(encoding="utf-8")


def test_empty_findings_is_safe():
    analyst = AnalystNarrator([], target="http://example.test", llm_client=_OfflineLLM())
    brief = analyst.build()
    assert brief["mif"] == []
    assert brief["next_steps"], "should still recommend broadening coverage"
    assert "no confirmed security issues" in brief["executive_summary"].lower()


def test_accepts_report_json_dicts():
    # Findings coming from report.json are plain dicts, not Finding models.
    dicts = [f.model_dump(mode="json") for f in _sample_findings()]
    analyst = AnalystNarrator(dicts, llm_client=_OfflineLLM())
    brief = analyst.build()
    assert len(brief["mif"]) == 4
