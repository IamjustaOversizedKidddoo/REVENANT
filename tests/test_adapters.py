"""
Unit tests for REVENANT Tool Adapter Layer (BaseAdapter, HTTPXAdapter, NucleiAdapter).
Verifies Layer 3 Scope Enforcement and correct normalization of tool outputs.
"""

import json
import pytest
from control_plane.schemas.models import Severity
from control_plane.schemas.scope import ScopeManifest, ScopeViolationError
from adapters.recon.httpx_adapter import HTTPXAdapter
from adapters.web.nuclei_adapter import NucleiAdapter


class TestAdapterScopeEnforcement:
    """Ensures BaseAdapter prevents unauthorized executions."""

    def test_adapter_refuses_out_of_scope_target(self):
        adapter = NucleiAdapter()
        manifest = ScopeManifest(allowed_domains=["sanctioned.local"])

        # In-scope doesn't raise scope violation (even if tool binary missing)
        # We test that the scope validator itself passes
        adapter.validate_target_scope("http://sanctioned.local:3000", manifest)

        # Out-of-scope MUST raise ScopeViolationError
        with pytest.raises(ScopeViolationError) as exc_info:
            adapter.run("https://unauthorized-victim.com", manifest)

        assert "SCOPE VIOLATION" in str(exc_info.value)
        assert "unauthorized-victim.com" in str(exc_info.value)


class TestHTTPXAdapterParsing:
    """Tests normalization of httpx output."""

    def test_parse_valid_httpx_json(self):
        adapter = HTTPXAdapter()
        raw_output = json.dumps({
            "timestamp": "2026-09-17T10:00:00.000000Z",
            "url": "http://localhost:3000",
            "input": "localhost:3000",
            "title": "OWASP Juice Shop",
            "webserver": "Express",
            "content_type": "text/html; charset=utf-8",
            "status_code": 200,
            "host": "127.0.0.1",
            "port": "3000",
            "tech": ["Node.js", "Express", "Angular", "OpenSSL"]
        })

        findings, assets = adapter.parse_output(raw_output, "", "http://localhost:3000")

        assert len(assets) == 1
        asset = assets[0]
        assert asset.ip == "127.0.0.1"
        assert len(asset.endpoints) == 1
        assert asset.endpoints[0].status_code == 200
        assert asset.endpoints[0].title == "OWASP Juice Shop"
        assert "Node.js" in asset.endpoints[0].tech_stack

        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "OWASP Juice Shop" in (findings[0].evidence or "")


class TestNucleiAdapterParsing:
    """Tests normalization of Nuclei vulnerability scanner output."""

    def test_parse_nuclei_findings(self):
        adapter = NucleiAdapter()
        raw_nuclei_record = {
            "template-id": "cve-2023-38606",
            "info": {
                "name": "Apache ActiveMQ OpenWire Remote Code Execution",
                "author": ["vuln-team"],
                "tags": ["cve", "cve2023", "rce", "activemq"],
                "description": "Apache ActiveMQ is vulnerable to remote code execution.",
                "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2023-38606"],
                "severity": "critical",
                "classification": {
                    "cve-id": ["CVE-2023-38606"],
                    "cwe-id": ["CWE-502"],
                    "cvss-score": 9.8
                }
            },
            "type": "tcp",
            "host": "http://target.local:61616",
            "matched-at": "http://target.local:61616",
            "curl-command": "curl -X POST http://target.local:61616/api",
            "timestamp": "2026-09-17T11:00:00.000000Z"
        }

        raw_output = json.dumps(raw_nuclei_record)
        findings, assets = adapter.parse_output(raw_output, "", "http://target.local:61616")

        assert len(findings) == 1
        f = findings[0]
        assert f.title == "Apache ActiveMQ OpenWire Remote Code Execution"
        assert f.severity == Severity.CRITICAL
        assert f.cve == "CVE-2023-38606"
        assert f.cwe == "CWE-502"
        assert f.cvss_score == 9.8
        assert f.reproduction_steps == "curl -X POST http://target.local:61616/api"
        assert "Reproduction:" in (f.evidence or "")

    def test_parse_malformed_and_empty_output(self):
        adapter = NucleiAdapter()
        findings, assets = adapter.parse_output("random non json banner output\n", "", "http://localhost")
        assert findings == []
        assert assets == []
