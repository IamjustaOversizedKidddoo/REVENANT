"""Unit tests for the ReconBLADE-style findings brief (offline, no API key).

A stub LLM client forces the deterministic KB path; nothing hits the network.
"""
from __future__ import annotations

import json

import pytest

from control_plane.schemas.models import Finding, Severity
from intelligence import triage_kb
from intelligence.reconblade_brief import ReconBladeBrief


class _OfflineLLM:
    model = "offline-test"

    def available(self) -> bool:
        return False

    def complete(self, system, user):  # pragma: no cover
        raise AssertionError("LLM must not be called in the fallback path")


def _sample_findings():
    return [
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
            title="Error-Based SQL Injection in Parameter 'username'",
            description="sqlite3.OperationalError raised.",
            severity=Severity.CRITICAL,
            target="http://127.0.0.1:3000",
            tool="dast-fuzzer",
            cwe="CWE-89",
            endpoint="http://127.0.0.1:3000/login",
        ),
        Finding(
            title="Open MySQL database on port 3306",
            description="Service detected on port 3306.",
            severity=Severity.MEDIUM,
            target="10.0.0.5",
            tool="nmap",
        ),
        Finding(
            title="Missing Content-Security-Policy header",
            description="Response lacks a content-security-policy header.",
            severity=Severity.LOW,
            target="http://127.0.0.1:3000",
            tool="header-check",
            endpoint="http://127.0.0.1:3000/",
        ),
    ]


def test_brief_contains_every_finding_severity_ordered():
    brief = ReconBladeBrief(_sample_findings(), target="http://127.0.0.1:3000", llm_client=_OfflineLLM()).build()
    assert brief["mode"] == "fallback"
    assert brief["finding_count"] == 4
    sev_seq = [e["severity"] for e in brief["entries"]]
    assert sev_seq == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]  # severity-ordered
    # priority order mirrors the entries
    assert [p["title"] for p in brief["priority_order"]] == [e["title"] for e in brief["entries"]]


def test_every_entry_has_all_five_fields():
    brief = ReconBladeBrief(_sample_findings(), llm_client=_OfflineLLM()).build()
    for e in brief["entries"]:
        for field in ("what_it_is", "why_it_matters", "fix", "next_step", "if_you_do_it"):
            assert e[field], f"{field} missing/empty for {e['title']}"


def test_kb_drives_text_for_known_cwe_port_and_header():
    brief = ReconBladeBrief(_sample_findings(), llm_client=_OfflineLLM()).build()
    by_title = {e["title"]: e for e in brief["entries"]}

    sqli = by_title["Error-Based SQL Injection in Parameter 'username'"]
    assert "parameterized" in sqli["fix"].lower()

    port = by_title["Open MySQL database on port 3306"]
    assert "MySQL" in port["what_it_is"]  # PORT_KB 3306

    header = by_title["Missing Content-Security-Policy header"]
    assert "content-security-policy" in header["what_it_is"].lower()  # HEADER_KB


def test_markdown_renders_all_sections():
    obj = ReconBladeBrief(_sample_findings(), llm_client=_OfflineLLM())
    md = obj.render_markdown()
    for heading in (
        "# REVENANT Findings Brief (ReconBLADE style)",
        "## Summary",
        "## Priority order",
        "## Findings",
        "- **What it is**",
        "- **If you do it**",
    ):
        assert heading in md


def test_run_and_save_writes_both_files(tmp_path):
    obj = ReconBladeBrief(_sample_findings(), llm_client=_OfflineLLM())
    brief = obj.run_and_save(str(tmp_path))
    md = tmp_path / "findings_brief.md"
    js = tmp_path / "findings_brief.json"
    assert md.exists() and js.exists()
    loaded = json.loads(js.read_text(encoding="utf-8"))
    assert loaded["finding_count"] == brief["finding_count"] == 4


def test_no_api_key_never_raises_and_accepts_dicts():
    dicts = [f.model_dump(mode="json") for f in _sample_findings()]
    # No llm_client supplied -> default client, unavailable without a key; must not raise.
    brief = ReconBladeBrief(dicts, target="http://x.test").build()
    assert brief["finding_count"] == 4
    assert brief["mode"] == "fallback"


def test_empty_findings_is_safe():
    brief = ReconBladeBrief([], target="http://x.test", llm_client=_OfflineLLM()).build()
    assert brief["entries"] == []
    assert brief["priority_order"] == []
    assert len(brief["summary"]) == 3


def test_kb_lookup_helpers():
    assert triage_kb.port_info(3306)["service"] == "MySQL"
    assert triage_kb.port_info(99999) is None
    assert triage_kb.header_info("X-Frame-Options")["fix"]
    assert triage_kb.finding_info("CWE-89")["typical_fix"]
    # unknown cwe -> generic, never None
    assert triage_kb.finding_info("CWE-99999")["plain_explanation"]
    assert triage_kb.detect_port("open port 3389 found") == 3389
    assert triage_kb.detect_header("missing strict-transport-security") == "strict-transport-security"
