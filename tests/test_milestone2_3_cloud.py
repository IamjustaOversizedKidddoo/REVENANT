"""
REVENANT — Milestone 2.3 Test Suite: Cloud Infrastructure & Container Auditing Swarm
Tests:
1. Cloud and container schemas (CONTAINER_IMAGE, IAC_CONFIG, remediation on Finding, cloud scope allowlists).
2. TrivyAdapter (CLI invocation, JSON parsing, native Dockerfile AST misconfiguration & credential analysis).
3. ProwlerAdapter (CLI invocation, JSON parsing, native Terraform CIS benchmarks, Kubernetes privilege checks).
4. CloudAgent specialist agent (event predicate routing, stigmergic dispatch, blackboard updates).
5. End-to-end multi-agent swarm campaign against cloud IaC fixtures with automated SARIF/Markdown report generation.
"""

import json
from pathlib import Path
import pytest

from adapters.cloud.prowler_adapter import ProwlerAdapter
from adapters.cloud.trivy_adapter import TrivyAdapter
from control_plane.schemas.models import (
    AssetType,
    CodeLocation,
    Finding,
    HostAsset,
    Severity,
)
from control_plane.schemas.scope import ScopeEngine, ScopeManifest, ScopeViolationError
from orchestrator.agents.cloud_agent import CloudAgent
from orchestrator.agents.triage_agent import TriageAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType
from orchestrator.engine import Orchestrator
from reporting.generator import ReportGenerator

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "cloud_iac"


# =============================================================================
# 1. Cloud & Container Schemas and Scope Enforcement Tests
# =============================================================================

def test_cloud_schemas_and_models():
    """Verify AssetType extensions and Finding remediation support."""
    assert AssetType.CONTAINER_IMAGE == "CONTAINER_IMAGE"
    assert AssetType.IAC_CONFIG == "IAC_CONFIG"

    finding = Finding(
        title="Insecure Container Base Image",
        description="Container base image uses :latest tag",
        severity=Severity.MEDIUM,
        target="tests/fixtures/cloud_iac/Dockerfile",
        tool="trivy",
        cwe="CWE-1188",
        remediation="Pin base image to immutable SHA256 digest or semantic version tag.",
    )
    assert finding.remediation is not None
    assert "Pin base image" in finding.remediation

    serialized = finding.model_dump(mode="json")
    assert serialized["remediation"] == "Pin base image to immutable SHA256 digest or semantic version tag."
    deserialized = Finding.model_validate(serialized)
    assert deserialized.remediation == finding.remediation


def test_cloud_scope_engine_allowlists():
    """Verify Layer 1-3 scope enforcement handles cloud accounts and container image allowlists."""
    scope = ScopeManifest(
        allowed_hosts=["127.0.0.1"],
        allowed_cloud_accounts=["123456789012", "my-gcp-project"],
        allowed_container_images=["myregistry.azurecr.io/app:*", "node:20-alpine", "corp/*"],
        allowed_repos=[str(FIXTURES_DIR.resolve())],
    )
    engine = ScopeEngine(scope)

    # Authorized cloud account
    assert engine.is_allowed("123456789012")[0] is True
    assert engine.is_allowed("my-gcp-project")[0] is True

    # Unauthorized cloud account
    assert engine.is_allowed("999999999999")[0] is False

    # Authorized container images
    assert engine.is_allowed("node:20-alpine")[0] is True
    assert engine.is_allowed("corp/backend:latest")[0] is True
    assert engine.is_allowed("myregistry.azurecr.io/app:v1.2")[0] is True

    # Unauthorized container image
    assert engine.is_allowed("malicious/rootkit:latest")[0] is False

    # Blocked target raises ScopeViolationError
    with pytest.raises(ScopeViolationError):
        engine.validate_or_raise("unauthorized-account-id")


# =============================================================================
# 2. TrivyAdapter Tests (Container, Dockerfile & SBOM)
# =============================================================================

def test_trivy_adapter_command_generation():
    """Verify Trivy command line composition across scan modes."""
    adapter = TrivyAdapter()
    assert adapter.is_installed() is True

    # Image scan mode
    cmd_image = adapter.build_command("node:20-alpine", {"scan_type": "image", "severity": "HIGH,CRITICAL"})
    assert "image" in cmd_image
    assert "--format" in cmd_image
    assert "json" in cmd_image
    assert "node:20-alpine" in cmd_image
    assert "HIGH,CRITICAL" in cmd_image

    # Config / Dockerfile mode
    cmd_config = adapter.build_command(str(FIXTURES_DIR / "Dockerfile"), {})
    assert "config" in cmd_config or "fs" in cmd_config


def test_trivy_adapter_parse_output():
    """Verify JSON parsing logic of Trivy CLI output."""
    adapter = TrivyAdapter()
    trivy_json = {
        "Results": [
            {
                "Target": "Dockerfile",
                "Class": "config",
                "Misconfigurations": [
                    {
                        "ID": "DS001",
                        "Title": "Process can run with elevated privileges",
                        "Description": "Missing non-root USER instruction.",
                        "Severity": "HIGH",
                        "Resolution": "Add 'USER nonroot' before ENTRYPOINT",
                        "References": ["https://avd.aquasec.com/misconfig/ds001"],
                    }
                ],
            }
        ]
    }

    findings, assets = adapter.parse_output(json.dumps(trivy_json), "", "Dockerfile")
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].tool == "trivy"
    assert "DS001" in findings[0].title or "elevated privileges" in findings[0].title
    assert findings[0].remediation == "Add 'USER nonroot' before ENTRYPOINT"


def test_trivy_builtin_dockerfile_misconfigurations():
    """Verify built-in Dockerfile AST analyzer detects latest tag, embedded secrets, and root user."""
    adapter = TrivyAdapter()
    scope = ScopeManifest(allowed_repos=[str(FIXTURES_DIR.resolve())])

    result = adapter.run(str(FIXTURES_DIR), scope)
    assert result.exit_code == 0
    assert len(result.findings) >= 3

    titles = [f.title for f in result.findings]
    cwes = [f.cwe for f in result.findings]

    # Check 1: Mutable :latest base image (CWE-1188)
    assert any("Mutable Base Image Tag" in t for t in titles)
    assert "CWE-1188" in cwes

    # Check 2: Embedded AWS credentials (CWE-798)
    assert any("Hardcoded Credential" in t for t in titles)
    assert "CWE-798" in cwes
    secret_finding = next(f for f in result.findings if f.cwe == "CWE-798")
    assert secret_finding.severity == Severity.CRITICAL
    assert secret_finding.remediation is not None

    # Check 3: Root execution (CWE-250)
    assert any("Process Runs as Root User" in t for t in titles)
    assert "CWE-250" in cwes


# =============================================================================
# 3. ProwlerAdapter Tests (Cloud Posture & CIS Benchmarks)
# =============================================================================

def test_prowler_adapter_command_generation():
    """Verify Prowler command line builder for AWS / GCP / Azure."""
    adapter = ProwlerAdapter()
    assert adapter.is_installed() is True

    cmd = adapter.build_command("aws", {"provider": "aws", "services": ["s3", "iam"], "compliance": "cis_aws"})
    assert "aws" in cmd
    assert "--output-formats" in cmd
    assert "json" in cmd
    assert "--services" in cmd
    assert "s3,iam" in cmd
    assert "--compliance" in cmd
    assert "cis_aws" in cmd


def test_prowler_adapter_parse_output():
    """Verify JSON parsing logic of Prowler CLI output."""
    adapter = ProwlerAdapter()
    sample_prowler_line = json.dumps({
        "Status": "FAIL",
        "CheckID": "s3_bucket_public_access",
        "CheckTitle": "Ensure S3 buckets do not allow public read access",
        "ServiceName": "s3",
        "Severity": "CRITICAL",
        "StatusExtended": "Bucket 'customer-data' has public read ACL.",
        "Remediation": {
            "Recommendation": {
                "Text": "Enable S3 Block Public Access at bucket level."
            }
        },
        "ResourceId": "arn:aws:s3:::customer-data",
    })

    findings, assets = adapter.parse_output(sample_prowler_line, "", "arn:aws:s3:::customer-data")
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].tool == "prowler"
    assert "CIS Benchmark Failure" in findings[0].title
    assert findings[0].remediation == "Enable S3 Block Public Access at bucket level."
    assert findings[0].owasp_category == "A05:2021 - Security Misconfiguration"


def test_prowler_builtin_iac_cis_benchmarks():
    """Verify built-in CIS benchmark analyzer on Terraform (.tf) and Kubernetes (.yaml)."""
    adapter = ProwlerAdapter()
    scope = ScopeManifest(allowed_repos=[str(FIXTURES_DIR.resolve())])

    result = adapter.run(str(FIXTURES_DIR), scope)
    assert result.exit_code == 0
    assert len(result.findings) >= 5

    titles = [f.title for f in result.findings]

    # Terraform CIS-2.1.5: S3 public read
    assert any("Publicly Readable S3 Bucket (CIS-2.1.5)" in t for t in titles)

    # Terraform CIS-4.1: Open SSH ingress 0.0.0.0/0
    assert any("Ingress Open to Internet (0.0.0.0/0) (CIS-4.1)" in t for t in titles)

    # Terraform CIS-1.16: Overly permissive IAM policy
    assert any("Overly Permissive Wildcard IAM Policy (CIS-1.16)" in t for t in titles)

    # K8s CIS-5.2: Privileged container execution
    assert any("Privileged Container Execution (CIS-5.2)" in t for t in titles)

    # K8s: Host network shared
    assert any("Host Network Namespace Shared" in t for t in titles)

    # Check all findings have remediation advice
    for f in result.findings:
        assert f.remediation is not None
        assert len(f.remediation) > 10


# =============================================================================
# 4. CloudAgent Specialist Agent Tests
# =============================================================================

def test_cloud_agent_can_handle():
    """Verify CloudAgent event predicate filtering logic."""
    agent = CloudAgent()

    # Cloud & container discovered events
    assert agent.can_handle(BlackboardEvent(
        event_type=EventType.CONTAINER_DISCOVERED,
        source_agent="orchestrator",
        target="node:20-alpine",
        payload={},
    )) is True

    assert agent.can_handle(BlackboardEvent(
        event_type=EventType.CLOUD_ASSET_DISCOVERED,
        source_agent="orchestrator",
        target="arn:aws:s3:::test-bucket",
        payload={},
    )) is True

    # Target registered with filesystem path
    assert agent.can_handle(BlackboardEvent(
        event_type=EventType.TARGET_REGISTERED,
        source_agent="orchestrator",
        target=str(FIXTURES_DIR / "terraform_aws.tf"),
        payload={},
    )) is True

    # Target registered with explicit target_type
    assert agent.can_handle(BlackboardEvent(
        event_type=EventType.TARGET_REGISTERED,
        source_agent="orchestrator",
        target="custom-target",
        payload={"target_type": "CONTAINER_IMAGE"},
    )) is True

    # Unrelated web target without cloud payload
    assert agent.can_handle(BlackboardEvent(
        event_type=EventType.TARGET_REGISTERED,
        source_agent="orchestrator",
        target="http://example.com/login",
        payload={"target_type": "URL"},
    )) is False


def test_cloud_agent_handle_execution():
    """Verify CloudAgent execution generates MISCONFIGURATION_DETECTED and SECRET_EXPOSED events."""
    agent = CloudAgent()
    blackboard = Blackboard()
    scope = ScopeManifest(allowed_repos=[str(FIXTURES_DIR.resolve())])

    event = BlackboardEvent(
        event_type=EventType.TARGET_REGISTERED,
        source_agent="orchestrator",
        target=str(FIXTURES_DIR),
        payload={"target_type": "IAC_CONFIG"},
    )

    new_events = agent.handle(event, blackboard, scope)
    assert len(new_events) >= 8

    event_types = [e.event_type for e in new_events]
    assert EventType.MISCONFIGURATION_DETECTED in event_types
    assert EventType.SECRET_EXPOSED in event_types

    # Discovered assets recorded on blackboard
    assets = blackboard.get_assets()
    assert len(assets) >= 1


# =============================================================================
# 5. Full Orchestrator Multi-Agent Swarm Campaign Integration
# =============================================================================

def test_full_cloud_campaign_swarm_and_reports(tmp_path):
    """
    Run full Orchestrator swarm against cloud IaC fixtures, verifying CloudAgent -> TriageAgent
    event pipeline and multi-format report generator with remediation fields.
    """
    scope = ScopeManifest(allowed_repos=[str(FIXTURES_DIR.resolve())])
    blackboard = Blackboard()
    orchestrator = Orchestrator(blackboard=blackboard)

    # CloudAgent should be present in default swarm
    agent_names = [a.name for a in orchestrator.agents]
    assert "cloud-agent" in agent_names
    assert "triage-agent" in agent_names

    # Run the autonomous campaign
    summary = orchestrator.start_campaign(
        target=str(FIXTURES_DIR),
        scope=scope,
        max_iterations=10,
    )

    assert summary["iterations_run"] > 0
    findings = blackboard.get_findings()
    assert len(findings) >= 8

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
    assert "Executive Summary" in md_content
    assert "Remediation" in md_content or "remediation" in md_content.lower()

    # Test SARIF v2.1.0 generation
    sarif = generator.generate_sarif()
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) >= 8

    # Verify SARIF remediation / help markdown is present
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) >= 1
    sample_rule = rules[0]
    assert "help" in sample_rule
    assert "text" in sample_rule["help"]
