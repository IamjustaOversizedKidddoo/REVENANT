"""
REVENANT — Milestone 2.4 Test Suite: Active Directory & Identity Security Swarm
Tests:
1. Identity schemas and scope allowlists (IDENTITY_ACCOUNT, IDENTITY_DOMAIN, CERT_TEMPLATE, allowed_identity_domains).
2. BloodHoundAdapter (CLI command generation, JSON parsing, Kerberoasting, AS-REP roasting, Unconstrained Delegation).
3. CertipyAdapter (CLI command generation, JSON template parsing, ESC1, ESC4, and ESC8 misconfiguration detection).
4. IdentityAgent specialist agent (event predicate routing, stigmergic dispatch, blackboard updates).
5. End-to-end multi-agent swarm campaign against Active Directory fixtures with MITRE ATT&CK coverage and remediation.
"""

import json
from pathlib import Path
import pytest

from adapters.identity.bloodhound_adapter import BloodHoundAdapter
from adapters.identity.certipy_adapter import CertipyAdapter
from control_plane.schemas.models import (
    AssetType,
    Finding,
    HostAsset,
    Severity,
)
from control_plane.schemas.scope import ScopeEngine, ScopeManifest, ScopeViolationError
from orchestrator.agents.identity_agent import IdentityAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType
from orchestrator.engine import Orchestrator
from reporting.generator import ReportGenerator

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "ad_identity"


# =============================================================================
# 1. Identity Schemas and Scope Enforcement Tests
# =============================================================================

def test_identity_schemas_and_models():
    """Verify AssetType extensions for identity objects and Finding MITRE ATT&CK IDs."""
    assert AssetType.IDENTITY_ACCOUNT == "IDENTITY_ACCOUNT"
    assert AssetType.IDENTITY_DOMAIN == "IDENTITY_DOMAIN"
    assert AssetType.CERT_TEMPLATE == "CERT_TEMPLATE"

    finding = Finding(
        title="Active Directory: Kerberoastable Privileged Account",
        description="SPN configured on Domain Admin account.",
        severity=Severity.CRITICAL,
        target="REVENANT.LOCAL/svc_mssql",
        tool="bloodhound",
        cwe="CWE-521",
        mitre_attack_ids=["T1558.003"],
        remediation="Migrate service to Group Managed Service Account (gMSA) with AES-256.",
    )
    assert "T1558.003" in finding.mitre_attack_ids
    assert finding.remediation is not None

    dumped = finding.model_dump(mode="json")
    assert dumped["mitre_attack_ids"] == ["T1558.003"]
    assert dumped["remediation"] == finding.remediation


def test_identity_scope_engine_allowlists():
    """Verify ScopeEngine allows authorized Active Directory domain names and refuses others."""
    scope = ScopeManifest(
        allowed_hosts=["127.0.0.1"],
        allowed_identity_domains=["REVENANT.LOCAL", "*.CORP.LAN"],
        allowed_repos=[str(FIXTURES_DIR.resolve())],
    )
    engine = ScopeEngine(scope)

    # Authorized identity domains
    assert engine.is_allowed("REVENANT.LOCAL")[0] is True
    assert engine.is_allowed("sub.corp.lan")[0] is True
    assert engine.is_allowed("DC01.REVENANT.LOCAL")[0] is True

    # Unauthorized domain
    assert engine.is_allowed("UNAUTHORIZED.EXTERNAL")[0] is False

    # Validation exception on unauthorized target
    with pytest.raises(ScopeViolationError):
        engine.validate_or_raise("unauthorized.external")


# =============================================================================
# 2. BloodHoundAdapter Tests (Kerberoasting, AS-REP Roasting, Delegation)
# =============================================================================

def test_bloodhound_adapter_command_generation():
    """Verify BloodHound command line synthesis."""
    adapter = BloodHoundAdapter()
    assert adapter.is_installed() is True

    cmd = adapter.build_command("REVENANT.LOCAL", {
        "username": "audit_user",
        "password": "Password123!",
        "dc_ip": "10.0.0.1",
        "collection_method": "all",
    })
    assert "-d" in cmd
    assert "REVENANT.LOCAL" in cmd
    assert "-u" in cmd
    assert "audit_user" in cmd
    assert "-dc" in cmd
    assert "10.0.0.1" in cmd
    assert "--zip" in cmd


def test_bloodhound_builtin_identity_flaw_detection():
    """Verify BloodHound JSON parser detects Kerberoasting, AS-REP Roasting, and Delegation."""
    adapter = BloodHoundAdapter()
    scope = ScopeManifest(allowed_repos=[str(FIXTURES_DIR.resolve())])

    result = adapter.run(str(FIXTURES_DIR), scope)
    assert result.exit_code == 0
    assert len(result.findings) >= 3

    titles = [f.title for f in result.findings]
    cwes = [f.cwe for f in result.findings]
    mitre_ids = [m for f in result.findings for m in f.mitre_attack_ids]

    # Check 1: Kerberoastable Privileged Account (T1558.003 / CWE-521)
    assert any("Kerberoastable Privileged Account" in t for t in titles)
    assert "CWE-521" in cwes
    assert "T1558.003" in mitre_ids

    # Check 2: AS-REP Roastable Account (T1558.004 / CWE-287)
    assert any("AS-REP Roastable Account" in t for t in titles)
    assert "CWE-287" in cwes
    assert "T1558.004" in mitre_ids

    # Check 3: Unconstrained Delegation (T1558.001 / CWE-269)
    assert any("Unconstrained Delegation" in t for t in titles)
    assert "CWE-269" in cwes
    assert "T1558.001" in mitre_ids

    # Check assets indexed
    assert len(result.discovered_assets) >= 3
    asset_names = [a.hostname for a in result.discovered_assets]
    assert any("SVC_MSSQL" in a for a in asset_names)
    assert any("JDOE" in a for a in asset_names)
    assert any("WS-DEV01" in a for a in asset_names)


# =============================================================================
# 3. CertipyAdapter Tests (AD CS ESC1, ESC4, ESC8 Misconfigurations)
# =============================================================================

def test_certipy_adapter_command_generation():
    """Verify Certipy command line synthesis."""
    adapter = CertipyAdapter()
    assert adapter.is_installed() is True

    cmd = adapter.build_command("dc01.revenant.local", {
        "username": "audit_user@revenant.local",
        "password": "Password123!",
    })
    assert "find" in cmd
    assert "-target" in cmd
    assert "dc01.revenant.local" in cmd
    assert "-json" in cmd
    assert "-vulnerable" in cmd


def test_certipy_builtin_adcs_flaw_detection():
    """Verify Certipy analyzer detects ESC1, ESC4, and ESC8 misconfigurations."""
    adapter = CertipyAdapter()
    scope = ScopeManifest(allowed_repos=[str(FIXTURES_DIR.resolve())])

    result = adapter.run(str(FIXTURES_DIR), scope)
    assert result.exit_code == 0
    assert len(result.findings) >= 3

    titles = [f.title for f in result.findings]
    mitre_ids = [m for f in result.findings for m in f.mitre_attack_ids]

    # ESC1: Arbitrary SAN with Client Authentication
    assert any("(ESC1)" in t for t in titles)
    esc1_finding = next(f for f in result.findings if "(ESC1)" in f.title)
    assert esc1_finding.severity == Severity.CRITICAL
    assert esc1_finding.cwe == "CWE-295"
    assert "T1649" in esc1_finding.mitre_attack_ids
    assert "Subject Name" in esc1_finding.remediation

    # ESC4: Insecure Template ACL
    assert any("(ESC4)" in t for t in titles)
    esc4_finding = next(f for f in result.findings if "(ESC4)" in f.title)
    assert esc4_finding.severity == Severity.HIGH
    assert esc4_finding.cwe == "CWE-284"

    # ESC8: NTLM Relayable Web Enrollment without EPA
    assert any("(ESC8)" in t for t in titles)
    esc8_finding = next(f for f in result.findings if "(ESC8)" in f.title)
    assert esc8_finding.severity == Severity.HIGH
    assert "T1187" in esc8_finding.mitre_attack_ids
    assert "Extended Protection" in esc8_finding.remediation


# =============================================================================
# 4. IdentityAgent Specialist Agent Tests
# =============================================================================

def test_identity_agent_can_handle():
    """Verify IdentityAgent event predicate filtering logic."""
    agent = IdentityAgent()

    # Identity asset discovered event
    assert agent.can_handle(BlackboardEvent(
        event_type=EventType.IDENTITY_ASSET_DISCOVERED,
        source_agent="orchestrator",
        target="REVENANT.LOCAL/svc_mssql",
        payload={},
    )) is True

    # Target registered with explicit target_type
    assert agent.can_handle(BlackboardEvent(
        event_type=EventType.TARGET_REGISTERED,
        source_agent="orchestrator",
        target="REVENANT.LOCAL",
        payload={"target_type": "IDENTITY_DOMAIN"},
    )) is True

    # Target registered with domain heuristic
    assert agent.can_handle(BlackboardEvent(
        event_type=EventType.TARGET_REGISTERED,
        source_agent="orchestrator",
        target="CORP.LOCAL",
        payload={},
    )) is True

    # Target registered with fixture path
    assert agent.can_handle(BlackboardEvent(
        event_type=EventType.TARGET_REGISTERED,
        source_agent="orchestrator",
        target=str(FIXTURES_DIR),
        payload={},
    )) is True

    # Unrelated web target
    assert agent.can_handle(BlackboardEvent(
        event_type=EventType.TARGET_REGISTERED,
        source_agent="orchestrator",
        target="http://example.com/api",
        payload={"target_type": "URL"},
    )) is False


def test_identity_agent_handle_execution():
    """Verify IdentityAgent dispatches adapters and generates PRIVILEGE_ESCALATION_PATH_DETECTED events."""
    agent = IdentityAgent()
    blackboard = Blackboard()
    scope = ScopeManifest(allowed_repos=[str(FIXTURES_DIR.resolve())])

    event = BlackboardEvent(
        event_type=EventType.TARGET_REGISTERED,
        source_agent="orchestrator",
        target=str(FIXTURES_DIR),
        payload={"target_type": "AD_IDENTITY"},
    )

    new_events = agent.handle(event, blackboard, scope)
    assert len(new_events) >= 6

    for ev in new_events:
        assert ev.event_type == EventType.PRIVILEGE_ESCALATION_PATH_DETECTED
        assert "finding" in ev.payload

    # Assets indexed on blackboard
    assets = blackboard.get_assets()
    assert len(assets) >= 3


# =============================================================================
# 5. Full Swarm Integration & Report Generation
# =============================================================================

def test_full_identity_campaign_swarm_and_reports():
    """
    Run full Orchestrator swarm against Active Directory fixtures, verifying IdentityAgent -> TriageAgent
    pipeline, deduplication, and multi-format report generator with MITRE ATT&CK technique IDs.
    """
    scope = ScopeManifest(allowed_repos=[str(FIXTURES_DIR.resolve())])
    blackboard = Blackboard()
    orchestrator = Orchestrator(blackboard=blackboard)

    # Confirm IdentityAgent in default swarm
    agent_names = [a.name for a in orchestrator.agents]
    assert "identity-agent" in agent_names
    assert "triage-agent" in agent_names

    # Run the autonomous campaign
    summary = orchestrator.start_campaign(
        target=str(FIXTURES_DIR),
        scope=scope,
        max_iterations=10,
    )

    assert summary["iterations_run"] > 0
    findings = blackboard.get_findings()
    assert len(findings) >= 6

    # Verify triage verified them
    for f in findings:
        assert f.verified is True
        assert f.remediation is not None

    # Generate Reports
    generator = ReportGenerator(
        campaign_id=blackboard.campaign_id,
        target=str(FIXTURES_DIR),
        assets=blackboard.get_assets(),
        findings=findings,
        metadata={"iterations": summary["iterations_run"]},
    )

    # Test Markdown generation
    md_content = generator.generate_markdown()
    assert "Detailed Findings" in md_content
    assert "Kerberoastable" in md_content or "T1558.003" in md_content
    assert "ESC1" in md_content

    # Test SARIF v2.1.0 generation
    sarif = generator.generate_sarif()
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) >= 6

    # Test JSON generation
    json_report = generator.generate_json()
    assert len(json_report["findings"]) >= 6
