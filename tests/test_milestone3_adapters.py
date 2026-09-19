"""
Unit and integration tests for Milestone 3 Tool Adapters:
Subfinder, Nmap, Ffuf, Schemathesis, and ApiAgent.
"""

import json
import pytest
from unittest.mock import MagicMock

from adapters.api.schemathesis_adapter import SchemathesisAdapter
from adapters.network.nmap_adapter import NmapAdapter
from adapters.recon.subfinder_adapter import SubfinderAdapter
from adapters.web.ffuf_adapter import FfufAdapter
from control_plane.schemas.models import Severity
from control_plane.schemas.scope import ScopeManifest, ScopeViolationError
from orchestrator.agents.api_agent import ApiAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType


class TestSubfinderAdapter:
    """Tests for Subfinder passive subdomain adapter."""

    def test_scope_enforcement(self):
        adapter = SubfinderAdapter()
        manifest = ScopeManifest(allowed_domains=["sanctioned.org"])

        # In-scope
        adapter.validate_target_scope("sanctioned.org", manifest)

        # Out-of-scope
        with pytest.raises(ScopeViolationError):
            adapter.run("unauthorized.com", manifest)

    def test_parse_subfinder_json_output(self):
        adapter = SubfinderAdapter()
        raw_stdout = (
            '{"host":"api.target.com","ip":"192.168.1.10","sources":["crtsh"]}\n'
            '{"host":"auth.target.com","ip":"192.168.1.11","sources":["alienvault"]}\n'
            '{"host":"api.target.com","ip":"192.168.1.10","sources":["virustotal"]}\n'
        )

        findings, assets = adapter.parse_output(raw_stdout, "", "target.com")

        assert len(assets) == 2
        hostnames = {a.hostname for a in assets}
        assert hostnames == {"api.target.com", "auth.target.com"}


class TestNmapAdapter:
    """Tests for Nmap network and port scanner adapter."""

    def test_scope_enforcement(self):
        adapter = NmapAdapter()
        manifest = ScopeManifest(allowed_cidrs=["192.168.1.0/24"])

        # In-scope
        adapter.validate_target_scope("192.168.1.5", manifest)

        # Out-of-scope
        with pytest.raises(ScopeViolationError):
            adapter.run("10.0.0.1", manifest)

    def test_parse_nmap_xml_output(self):
        adapter = NmapAdapter()
        raw_xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -F 192.168.1.50" version="7.94">
<host starttime="1726550000" endtime="1726550010">
    <status state="up" reason="arp-response"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <hostnames>
        <hostname name="lab-target.local" type="user"/>
    </hostnames>
    <ports>
        <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack"/>
            <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu"/>
        </port>
        <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="nginx" version="1.18.0"/>
        </port>
        <port protocol="tcp" portid="3306">
            <state state="closed" reason="reset"/>
        </port>
    </ports>
</host>
</nmaprun>
"""
        findings, assets = adapter.parse_output(raw_xml, "", "192.168.1.50")

        assert len(assets) == 1
        asset = assets[0]
        assert asset.ip == "192.168.1.50"
        assert asset.hostname == "lab-target.local"
        assert len(asset.ports) == 2
        port_map = {p.port: p for p in asset.ports}
        assert 22 in port_map
        assert port_map[22].service == "ssh"
        assert "OpenSSH" in (port_map[22].version or "")
        assert 80 in port_map
        assert port_map[80].service == "http"

        assert len(findings) == 2
        assert any("Open Port 22/tcp" in f.title for f in findings)


class TestFfufAdapter:
    """Tests for Ffuf web directory fuzzer adapter."""

    def test_scope_enforcement(self):
        adapter = FfufAdapter()
        manifest = ScopeManifest(allowed_domains=["lab.local"])

        with pytest.raises(ScopeViolationError):
            adapter.run("https://attacker.org", manifest)

    def test_parse_ffuf_json_output(self):
        adapter = FfufAdapter()
        raw_json = json.dumps({
            "results": [
                {
                    "input": {"FUZZ": "admin"},
                    "position": 1,
                    "status": 200,
                    "length": 1024,
                    "words": 50,
                    "lines": 10,
                    "url": "http://localhost:3000/admin"
                },
                {
                    "input": {"FUZZ": ".env"},
                    "position": 2,
                    "status": 200,
                    "length": 256,
                    "words": 15,
                    "lines": 5,
                    "url": "http://localhost:3000/.env"
                },
                {
                    "input": {"FUZZ": "contact"},
                    "position": 3,
                    "status": 200,
                    "length": 512,
                    "words": 30,
                    "lines": 8,
                    "url": "http://localhost:3000/contact"
                }
            ]
        })

        findings, assets = adapter.parse_output(raw_json, "", "http://localhost:3000")

        assert len(assets) == 1
        assert len(assets[0].endpoints) == 3

        # Both /admin and /.env are in sensitive keywords, but /contact is not
        assert len(findings) == 2
        titles = [f.title for f in findings]
        assert any("/admin" in t for t in titles)
        assert any("/.env" in t for t in titles)
        # .env has Severity.MEDIUM
        env_finding = next(f for f in findings if "/.env" in f.title)
        assert env_finding.severity == Severity.MEDIUM


class TestSchemathesisAdapter:
    """Tests for Schemathesis API fuzzer adapter."""

    def test_scope_enforcement(self):
        adapter = SchemathesisAdapter()
        manifest = ScopeManifest(allowed_hosts=["localhost"])

        with pytest.raises(ScopeViolationError):
            adapter.run("https://google.com/openapi.json", manifest)

    def test_parse_schemathesis_failures(self):
        adapter = SchemathesisAdapter()
        raw_output = json.dumps({
            "failures": [
                {
                    "path": "/api/users/{id}",
                    "method": "GET",
                    "status_code": 500,
                    "title": "Server Error 500: Internal Server Error",
                    "message": "Uncaught NullPointerException on null ID input",
                    "curl": "curl http://localhost:3000/api/users/-1"
                }
            ]
        })

        findings, assets = adapter.parse_output(raw_output, "", "http://localhost:3000/api")

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.HIGH
        assert f.cwe == "CWE-754"
        assert "/api/users/{id}" in f.endpoint
        assert "curl" in (f.reproduction_steps or "")


class TestApiAgent:
    """Tests for ApiAgent event triggering and handling."""

    def test_api_agent_trigger_predicates(self):
        agent = ApiAgent()

        # Should trigger on endpoints containing API indicators
        event_api = BlackboardEvent(
            event_type=EventType.HTTP_ENDPOINT,
            source_agent="recon-agent",
            target="http://localhost:3000/swagger.json",
        )
        assert agent.can_handle(event_api) is True

        event_openapi = BlackboardEvent(
            event_type=EventType.HTTP_ENDPOINT,
            source_agent="recon-agent",
            target="http://localhost:3000/api/v1/users",
        )
        assert agent.can_handle(event_openapi) is True

        # Should NOT trigger on static assets or other event types
        event_img = BlackboardEvent(
            event_type=EventType.HTTP_ENDPOINT,
            source_agent="recon-agent",
            target="http://localhost:3000/static/logo.png",
        )
        assert agent.can_handle(event_img) is False

        event_other = BlackboardEvent(
            event_type=EventType.HOST_DISCOVERED,
            source_agent="recon-agent",
            target="localhost",
        )
        assert agent.can_handle(event_other) is False
