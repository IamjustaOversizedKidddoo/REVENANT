"""
REVENANT — Milestone 2.1 SAST, Secrets & Source Code Auditing Test Suite.
Verifies Gitleaks, TruffleHog, Semgrep adapters, CodeAgent lifecycle,
SARIF report code location serialization, and end-to-end swarm integration.
"""

import json
from pathlib import Path
import pytest

from adapters.sast.gitleaks_adapter import GitleaksAdapter
from adapters.sast.semgrep_adapter import SemgrepAdapter
from adapters.sast.trufflehog_adapter import TruffleHogAdapter
from control_plane.schemas.models import Finding, Severity, Target
from control_plane.schemas.scope import ScopeManifest, ScopeViolationError
from orchestrator.agents.code_agent import CodeAgent
from orchestrator.agents.triage_agent import TriageAgent
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType
from orchestrator.engine import Orchestrator
from reporting.generator import ReportGenerator

FIXTURE_REPO = str(Path(__file__).parent / "fixtures" / "vulnerable_repo")


@pytest.fixture
def repo_scope() -> ScopeManifest:
    """Scope manifest permitting the vulnerable fixture repository."""
    return ScopeManifest(
        allowed_repos=[FIXTURE_REPO, "tests/fixtures/vulnerable_repo", "*vulnerable_repo*"],
        allowed_domains=["localhost", "127.0.0.1"],
        allowed_cidrs=["127.0.0.1/32"],
    )


class TestGitleaksAdapter:
    """Verifies Gitleaks command synthesis and report parsing."""

    def test_build_command(self):
        adapter = GitleaksAdapter(binary_override="gitleaks.exe")
        cmd = adapter.build_command("D:/sample_repo", {"no_git": True, "verbose": True})

        assert "gitleaks.exe" in cmd[0]
        assert "detect" in cmd
        assert any("--source=" in arg for arg in cmd)
        assert any("--report-path=" in arg for arg in cmd)
        assert "--report-format=json" in cmd
        assert "--exit-code=0" in cmd
        assert "--no-git" in cmd
        assert "--verbose" in cmd

    def test_parse_output_raw_json(self):
        adapter = GitleaksAdapter()
        mock_findings = [
            {
                "Description": "AWS Access Key",
                "StartLine": 14,
                "EndLine": 14,
                "StartColumn": 1,
                "EndColumn": 20,
                "Match": "AKIAIOSFODNN7EXAMPLE",
                "Secret": "AKIAIOSFODNN7EXAMPLE",
                "File": "config/aws.py",
                "RuleID": "aws-access-token",
                "Entropy": 3.82,
            }
        ]
        raw_json = json.dumps(mock_findings)
        findings, assets = adapter.parse_output(raw_json, "", "D:/sample_repo")

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.CRITICAL
        assert f.cwe == "CWE-798"
        assert f.secret_type == "aws-access-token"
        assert f.code_location is not None
        assert f.code_location.file_path == "config/aws.py"
        assert f.code_location.start_line == 14
        assert "AKI...PLE" in f.code_location.snippet

    def test_live_scan_on_fixture(self, repo_scope: ScopeManifest):
        adapter = GitleaksAdapter()
        if not adapter.is_installed():
            pytest.skip("Gitleaks binary not found on test environment")

        result = adapter.run(FIXTURE_REPO, repo_scope, params={"no_git": True})
        assert result.exit_code == 0
        assert len(result.findings) >= 1
        rule_ids = [f.secret_type for f in result.findings]
        assert any("aws" in (rid or "").lower() or "slack" in (rid or "").lower() for rid in rule_ids)


class TestTruffleHogAdapter:
    """Verifies TruffleHog command synthesis and JSON-lines stream parsing."""

    def test_build_command(self):
        adapter = TruffleHogAdapter(binary_override="trufflehog.exe")
        cmd = adapter.build_command("D:/sample_repo", {"filesystem_only": True, "only_verified": True})

        assert "trufflehog.exe" in cmd[0]
        assert "filesystem" in cmd
        assert "--json" in cmd
        assert "--no-update" in cmd
        assert "--only-verified" in cmd

    def test_parse_output_json_lines(self):
        adapter = TruffleHogAdapter()
        mock_output = "\n".join([
            json.dumps({
                "SourceMetadata": {
                    "Data": {
                        "Filesystem": {
                            "file": "config.py",
                            "line": 42
                        }
                    }
                },
                "DetectorName": "SlackWebhook",
                "Verified": False,
                "Raw": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
                "Redacted": "https://hooks.slack.com/services/T00000000/B00000000/XXXX***XXXX"
            }),
            json.dumps({
                "SourceMetadata": {
                    "Data": {
                        "Filesystem": {
                            "file": "secrets.env",
                            "line": 5
                        }
                    }
                },
                "DetectorName": "AWS",
                "Verified": True,
                "Raw": "AKIAIOSFODNN7EXAMPLE",
                "Redacted": "AKIA***MPLE"
            })
        ])

        findings, assets = adapter.parse_output(mock_output, "", "D:/sample_repo")
        assert len(findings) == 2

        slack_finding = next(f for f in findings if f.secret_type == "SlackWebhook")
        assert slack_finding.severity == Severity.CRITICAL
        assert slack_finding.verified is False
        assert slack_finding.code_location.file_path == "config.py"
        assert slack_finding.code_location.start_line == 42

        aws_finding = next(f for f in findings if f.secret_type == "AWS")
        assert aws_finding.verified is True
        assert aws_finding.verified_valid is True
        assert aws_finding.severity == Severity.CRITICAL

    def test_live_scan_on_fixture(self, repo_scope: ScopeManifest):
        adapter = TruffleHogAdapter()
        if not adapter.is_installed():
            pytest.skip("TruffleHog binary not found on test environment")

        result = adapter.run(FIXTURE_REPO, repo_scope, params={"filesystem_only": True})
        assert result.exit_code == 0
        assert len(result.findings) >= 1


class TestSemgrepAdapter:
    """Verifies Semgrep and native AST / heuristic SAST engine."""

    def test_builtin_sast_rules_detection(self, repo_scope: ScopeManifest):
        adapter = SemgrepAdapter()
        # Ensure target is validated by scope
        result = adapter.run(FIXTURE_REPO, repo_scope)
        assert result.exit_code == 0
        assert len(result.findings) >= 3

        cwes = {f.cwe for f in result.findings}
        assert "CWE-89" in cwes   # SQL Injection in database.py
        assert "CWE-78" in cwes   # Command Injection in server.py
        assert "CWE-502" in cwes  # Insecure Deserialization in server.py

        sqli_finding = next(f for f in result.findings if f.cwe == "CWE-89")
        assert sqli_finding.code_location is not None
        assert "database.py" in sqli_finding.code_location.file_path
        assert sqli_finding.code_location.start_line > 0
        assert "SELECT" in sqli_finding.code_location.snippet

    def test_parse_semgrep_cli_json(self):
        adapter = SemgrepAdapter()
        mock_semgrep_json = json.dumps({
            "results": [
                {
                    "check_id": "python.django.security.injection.sql-injection",
                    "path": "views/profile.py",
                    "start": {"line": 25, "col": 5},
                    "end": {"line": 25, "col": 80},
                    "extra": {
                        "message": "User input directly formatted into raw SQL query",
                        "severity": "ERROR",
                        "metadata": {
                            "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"],
                            "owasp": ["A03:2021 - Injection"]
                        },
                        "lines": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"
                    }
                }
            ]
        })

        findings, assets = adapter.parse_output(mock_semgrep_json, "", "D:/app")
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.CRITICAL
        assert f.cwe.startswith("CWE-89")
        assert f.code_location.file_path == "views/profile.py"
        assert f.code_location.start_line == 25
        assert "SELECT" in f.code_location.snippet


class TestCodeAgent:
    """Verifies CodeAgent triggering predicates, lifecycle, and event publishing."""

    def test_can_handle_predicate(self):
        agent = CodeAgent()

        # REPO_DISCOVERED event
        repo_event = BlackboardEvent(
            event_type=EventType.REPO_DISCOVERED,
            source_agent="recon-agent",
            target="https://github.com/org/repo.git",
        )
        assert agent.can_handle(repo_event) is True

        # TARGET_REGISTERED with directory/repo path
        local_dir_event = BlackboardEvent(
            event_type=EventType.TARGET_REGISTERED,
            source_agent="orchestrator",
            target=FIXTURE_REPO,
            payload={"target_type": "REPO"},
        )
        assert agent.can_handle(local_dir_event) is True

        # TARGET_REGISTERED with standard Web URL (not a repo)
        web_event = BlackboardEvent(
            event_type=EventType.TARGET_REGISTERED,
            source_agent="orchestrator",
            target="https://example.com",
            payload={"target_type": "DOMAIN"},
        )
        assert agent.can_handle(web_event) is False

    def test_handle_dispatches_events(self, repo_scope: ScopeManifest):
        agent = CodeAgent()
        bb = Blackboard()

        event = BlackboardEvent(
            event_type=EventType.TARGET_REGISTERED,
            source_agent="orchestrator",
            target=FIXTURE_REPO,
            payload={"target_type": "REPO"},
        )

        new_events = agent.handle(event, bb, repo_scope)
        assert len(new_events) > 0

        event_types = {e.event_type for e in new_events}
        assert EventType.VULNERABILITY_CANDIDATE in event_types or EventType.SECRET_EXPOSED in event_types

        # Check that assets were posted to the blackboard
        assert len(bb.get_assets()) > 0


class TestEndToEndSastCascade:
    """Verifies complete Stigmergic cascade with CodeAgent and TriageAgent."""

    def test_e2e_code_audit_and_report_generation(self, repo_scope: ScopeManifest):
        bb = Blackboard()
        code_agent = CodeAgent()
        triage_agent = TriageAgent()

        swarm = Orchestrator(
            blackboard=bb,
            agents=[code_agent, triage_agent],
        )

        swarm.start_campaign(FIXTURE_REPO, repo_scope, max_iterations=5)
        findings = bb.get_findings()

        # Confirm findings were detected and triaged
        assert len(findings) >= 3
        cwes = {f.cwe for f in findings}
        assert "CWE-89" in cwes or "CWE-798" in cwes

        # Generate SARIF report and verify CodeLocation schema serialization
        generator = ReportGenerator(
            campaign_id="test-sast-campaign",
            target=FIXTURE_REPO,
            assets=bb.get_assets(),
            findings=findings,
        )
        sarif_data = generator.generate_sarif()
        assert isinstance(sarif_data, dict)

        runs = sarif_data.get("runs", [])
        assert len(runs) == 1
        results = runs[0].get("results", [])
        assert len(results) >= 3

        # Check that physicalLocation contains valid regions with startLine
        locations_with_regions = [
            r for r in results
            if r.get("locations", [{}])[0].get("physicalLocation", {}).get("region", {}).get("startLine") is not None
        ]
        assert len(locations_with_regions) >= 3

        # Generate Markdown report and verify CodeLocation table
        md_report = generator.generate_markdown()
        assert "Code Location" in md_report
        assert "database.py" in md_report or "server.py" in md_report or "config.py" in md_report

    def test_scope_refusal_for_unauthorized_repo(self):
        # A scope that strictly denies or does not allow /secret/unauthorized/repo
        strict_scope = ScopeManifest(allowed_repos=["D:/authorized/repo"])
        adapter = SemgrepAdapter()

        with pytest.raises(ScopeViolationError) as exc_info:
            adapter.run("D:/unauthorized/repo", strict_scope)

        assert "SCOPE VIOLATION" in str(exc_info.value)
