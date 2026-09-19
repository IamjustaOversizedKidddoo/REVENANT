"""
REVENANT — Milestone 5 Test Suite: Production Hardening, Appliance Packaging & Full-Spectrum Simulation
Tests:
- Docker appliance configuration & Compose orchestration
- Mission profile registry & CLI subcommand routing
- Master Full-Spectrum Autonomous Mission Simulation connecting:
  Recon -> Web -> Cloud -> Identity -> Forensics -> Attack Graph -> Autonomous Remediation -> SOAR -> Enterprise Reports
"""

import http.server
import json
import os
import socketserver
import threading
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from adapters.malware.yara_adapter import YaraAdapter
from adapters.soar.webhook_adapter import SOARPlatform, SOARWebhookAdapter
from adapters.web.dast_adapter import DastAdapter
from control_plane.cli import build_parser
from control_plane.profiles import (
    PROFILES,
    MissionProfile,
    get_profile,
    list_profiles,
    validate_profile_target,
)
from control_plane.schemas.models import EndpointInfo, Finding, HostAsset, Severity
from control_plane.schemas.scope import ScopeManifest
from orchestrator.blackboard import Blackboard, BlackboardEvent, EventType
from orchestrator.correlation.attack_graph_engine import AttackGraphEngine
from orchestrator.engine import Orchestrator
from orchestrator.remediation.remediation_engine import RemediationEngine
from reporting.enterprise_exporters import DradisExporter, FaradayExporter
from reporting.generator import ReportGenerator


# ==============================================================================
# 1. DOCKER APPLIANCE PACKAGING TESTS
# ==============================================================================
class TestDockerAppliancePackaging:
    """Verifies production Docker and Compose appliance configuration files."""

    @pytest.fixture
    def repo_root(self) -> Path:
        return Path(__file__).resolve().parent.parent

    def test_dockerfile_control_plane_spec(self, repo_root):
        dockerfile = repo_root / "docker" / "Dockerfile.control-plane"
        assert dockerfile.exists(), "Dockerfile.control-plane must exist"
        content = dockerfile.read_text(encoding="utf-8")

        assert "FROM python:3.11-slim" in content
        assert "USER revenant" in content, "Control plane container must run as non-root user"
        assert "EXPOSE 8000" in content
        assert "HEALTHCHECK" in content
        assert "/api/v1/health" in content
        assert "uvicorn" in content

    def test_dockerfile_worker_spec(self, repo_root):
        dockerfile = repo_root / "docker" / "Dockerfile.worker"
        assert dockerfile.exists(), "Dockerfile.worker must exist"
        content = dockerfile.read_text(encoding="utf-8")

        assert "FROM python:3.11-slim" in content
        assert "USER revenant" in content, "Worker container must run as non-root user"
        assert "nmap" in content
        assert "VOLUME" in content
        assert "revenant.py" in content

    def test_docker_compose_orchestration_spec(self, repo_root):
        compose_file = repo_root / "deployments" / "docker-compose.yml"
        assert compose_file.exists(), "docker-compose.yml must exist"
        data = yaml.safe_load(compose_file.read_text(encoding="utf-8"))

        assert "services" in data
        services = data["services"]

        # 4 Core Appliance Services
        assert "postgres" in services
        assert "redis" in services
        assert "control-plane" in services
        assert "worker" in services

        # Verify Postgres has pgvector and healthcheck
        assert "pgvector" in services["postgres"]["image"]
        assert "healthcheck" in services["postgres"]

        # Verify Control Plane depends on healthy databases
        cp = services["control-plane"]
        assert "postgres" in cp["depends_on"]
        assert "redis" in cp["depends_on"]
        assert "8000" in str(cp.get("ports", []))

        # Verify Network Isolation
        assert "revenant-internal" in data.get("networks", {})

    def test_env_example_spec(self, repo_root):
        env_file = repo_root / "deployments" / ".env.example"
        assert env_file.exists(), ".env.example template must exist"
        content = env_file.read_text(encoding="utf-8")

        assert "REVENANT_ENV=production" in content
        assert "POSTGRES_USER=" in content
        assert "POSTGRES_PASSWORD=" in content
        assert "SOAR_WEBHOOK_URL=" in content


# ==============================================================================
# 2. MISSION PROFILES & CLI SUBCOMMAND TESTS
# ==============================================================================
class TestMissionProfilesArchitecture:
    """Verifies pre-configured mission profiles and CLI subcommand routing."""

    def test_profile_registry_integrity(self):
        profiles = list_profiles()
        assert len(profiles) >= 5

        names = [p.name for p in profiles]
        assert "recon" in names
        assert "web-dast" in names
        assert "cloud-native" in names
        assert "ad-identity" in names
        assert "full-spectrum" in names

    def test_profile_attributes(self):
        fs = get_profile("full-spectrum")
        assert fs is not None
        assert fs.max_iterations >= 25
        assert len(fs.active_agents) >= 8
        assert "dast" in fs.active_agents
        assert "cloud" in fs.active_agents
        assert "identity" in fs.active_agents
        assert "forensics" in fs.active_agents

        web = get_profile("web-dast")
        assert web is not None
        assert web.target_type == "url"
        assert "dast" in web.active_agents

    def test_profile_target_validation(self):
        web = get_profile("web-dast")
        valid, msg = validate_profile_target(web, "http://target.corp.local")
        assert valid is True

        invalid, msg = validate_profile_target(web, "192.168.1.1")
        assert invalid is False
        assert "URL target" in msg

    def test_cli_subcommands_parser(self):
        parser = build_parser()

        # Test scan command parsing
        args_scan = parser.parse_args(["scan", "http://target.local", "--profile", "web-dast", "--max-iterations", "15"])
        assert args_scan.subcommand == "scan"
        assert args_scan.target == "http://target.local"
        assert args_scan.profile == "web-dast"
        assert args_scan.max_iterations == 15

        # Test profiles command
        args_prof = parser.parse_args(["profiles"])
        assert args_prof.subcommand == "profiles"

        # Test remediate command
        args_rem = parser.parse_args(["remediate", "findings.json", "--output-dir", "custom_fixes"])
        assert args_rem.subcommand == "remediate"
        assert args_rem.findings_file == "findings.json"
        assert args_rem.output_dir == "custom_fixes"

        # Test asm command
        args_asm = parser.parse_args(["asm", "daemon", "--interval", "120"])
        assert args_asm.subcommand == "asm"
        assert args_asm.interval == 120


# ==============================================================================
# 3. MASTER FULL-SPECTRUM AUTONOMOUS MISSION SIMULATION
# ==============================================================================
class LiveWebhookReceiver(http.server.BaseHTTPRequestHandler):
    """Captures dispatched incident notifications during full mission."""
    dispatched_events: List[Dict[str, Any]] = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.__class__.dispatched_events.append({
            "headers": dict(self.headers),
            "body": body,
            "json": json.loads(body.decode("utf-8")),
        })
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format, *args):
        pass


@pytest.fixture(scope="module")
def live_soar_endpoint():
    LiveWebhookReceiver.dispatched_events = []
    server = socketserver.TCPServer(("127.0.0.1", 0), LiveWebhookReceiver)
    host, port = server.server_address
    url = f"http://127.0.0.1:{port}/soar-intake"

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield url
    server.shutdown()
    server.server_close()


class VulnerableLabServerHandler(http.server.BaseHTTPRequestHandler):
    """Minimal local HTTP server exposing a reflected XSS parameter for live DAST testing."""

    def do_GET(self):
        import urllib.parse
        self.close_connection = True
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        if "/search" in parsed.path:
            query_val = qs.get("query", [""])[0]
            # Deliberately unescaped reflected parameter to trigger live DastAdapter verification
            body = f"<html><body><h1>Search Results</h1><p>Results for: {query_val}</p></body></html>".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress console clutter during test run


class TestCrossDomainCorrelationPipeline:
    """
    Cross-domain correlation and remediation pipeline test.
    Verification provenance:
    - 2 of 6 stages use LIVE tool execution against real local targets:
      1. Web Stage: Real DastAdapter fuzzing local HTTP lab server (verified reflected XSS finding).
      2. Malware Stage: Real YaraAdapter scanning genuine PHP webshell fixture (verified webshell finding).
    - 4 of 6 stages use CALIBRATED SEEDED findings for stages requiring infrastructure not provisioned in CI:
      3. Cloud Infrastructure: Seeded Prowler S3 public access finding (no live AWS account in CI).
      4. Active Directory: Seeded Certipy ESC1 template takeover finding (no Windows Server DC in CI).
      5. Host Network: Seeded NetExec SMBv1 protocol finding (no unpatched SMB host in CI).
      6. Memory Forensics: Seeded Volatility 3 process injection finding (no multi-GB raw RAM image in CI).
    """

    def test_cross_domain_correlation_and_remediation_pipeline(self, tmp_path, live_soar_endpoint):
        out_dir = tmp_path / "master_mission_evidence"
        out_dir.mkdir(parents=True, exist_ok=True)

        # 1. Mission Intake & Scope Boundaries
        target = "http://enterprise-core.corp.local"
        scope = ScopeManifest(
            allowed_hosts=["enterprise-core.corp.local", "127.0.0.1", "localhost", "sample_webshell.php"],
            allowed_domains=["corp.local", "localhost"],
            allowed_cidrs=["10.0.0.0/8", "127.0.0.1/32"],
            allowed_cloud_accounts=["aws-prod-123456789012"],
            allowed_identity_domains=["CORP.LOCAL"],
            allowed_repos=[str((Path(__file__).parent / "fixtures" / "malware").resolve())],
        )

        blackboard = Blackboard(campaign_id="mission-alpha-v2")
        orchestrator = Orchestrator(blackboard=blackboard)

        # ----------------------------------------------------------------------
        # STAGE 1 (LIVE): Web Application DAST Fuzzing (DastAdapter -> Local Server)
        # ----------------------------------------------------------------------
        httpd = http.server.HTTPServer(("127.0.0.1", 0), VulnerableLabServerHandler)
        lab_port = httpd.server_address[1]
        server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        server_thread.start()

        try:
            dast_adapter = DastAdapter()
            ep = EndpointInfo(url=f"http://127.0.0.1:{lab_port}/search", method="GET", parameters=["query"])
            dast_res = dast_adapter.run(
                f"http://127.0.0.1:{lab_port}/search?query=test",
                scope=scope,
                params={"endpoints": [ep]},
            )
        finally:
            httpd.shutdown()

        assert dast_res.exit_code == 0
        assert len(dast_res.findings) >= 1
        f_web = dast_res.findings[0]
        assert f_web.tool == "dast-fuzzer"
        assert f_web.verified is True
        print(f"\n[LIVE STAGE 1: WEB DAST] Verified Finding: '{f_web.title}' | CWE: {f_web.cwe} | Tool: {f_web.tool}")

        # ----------------------------------------------------------------------
        # STAGE 2 (LIVE): Malware / Binary Triage (YaraAdapter -> sample_webshell.php)
        # ----------------------------------------------------------------------
        fixtures_dir = (Path(__file__).parent / "fixtures" / "malware").resolve()
        rules_path = str((fixtures_dir / "rules.yar").resolve())
        webshell_path = str((fixtures_dir / "sample_webshell.php").resolve())

        yara_adapter = YaraAdapter(use_wsl=True)
        yara_res = yara_adapter.run(webshell_path, scope=scope, params={"rules": rules_path})
        assert yara_res.exit_code == 0
        assert len(yara_res.findings) >= 1
        f_malware = yara_res.findings[0]
        assert f_malware.tool == "yara"
        assert f_malware.severity == Severity.CRITICAL
        print(f"[LIVE STAGE 2: MALWARE YARA] Verified Finding: '{f_malware.title}' | Tool: {f_malware.tool}")

        # ----------------------------------------------------------------------
        # STAGES 3-6 (CALIBRATED SEEDED FINDINGS for unavailable infrastructure)
        # ----------------------------------------------------------------------
        print("[SEEDED STAGE 3: CLOUD INFRA] Calibrated Prowler S3 Finding (no live AWS account in CI)")
        f_cloud = Finding(
            id="find-cloud-s3-01",
            title="Exposed S3 Customer Data Bucket",
            description="AWS S3 bucket 'enterprise-pii-records' allows unauthenticated public read/write.",
            severity=Severity.CRITICAL,
            target="s3://enterprise-pii-records",
            tool="prowler",
            cwe="CWE-284",
            mitre_attack_ids=["T1530"],
            remediation="Enable S3 PublicAccessBlock.",
        )

        print("[SEEDED STAGE 4: IDENTITY AD] Calibrated Certipy ESC1 Finding (no live Windows DC in CI)")
        f_identity = Finding(
            id="find-ad-esc1-01",
            title="Vulnerable Active Directory Certificate Template ESC1 Privilege Escalation",
            description="AD CS certificate template 'SmartCardClient' allows SAN specification leading to full Domain Admin takeover.",
            severity=Severity.CRITICAL,
            target="CORP.LOCAL:CA01",
            tool="certipy",
            cwe="CWE-269",
            mitre_attack_ids=["T1649"],
            remediation="Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag from template.",
        )

        print("[SEEDED STAGE 5: HOST SMB] Calibrated NetExec SMBv1 Finding (no live unpatched SMB host in CI)")
        f_host = Finding(
            id="find-host-smb-01",
            title="SMBv1 Active and Missing SMB Signing",
            description="Deprecated SMBv1 protocol active and packet signing not required on domain controller.",
            severity=Severity.HIGH,
            target="WIN-DC01:445",
            tool="nxc",
            cwe="CWE-319",
            mitre_attack_ids=["T1021.002"],
            remediation="Enforce SMB signing and disable SMBv1 via GPO.",
        )

        print("[SEEDED STAGE 6: FORENSICS] Calibrated Volatility 3 Finding (no multi-GB live RAM dump in CI)")
        f_forensics = Finding(
            id="find-mem-inject-01",
            title="Memory Injection & Process Tampering Detected",
            description="Host svchost.exe PID 1420 contains injected MZ executable header with PAGE_EXECUTE_READWRITE permissions.",
            severity=Severity.CRITICAL,
            target="WIN-DC01:1420",
            tool="volatility",
            cwe="CWE-119",
            mitre_attack_ids=["T1055.001"],
            remediation="Terminate infected process, isolate endpoint, and dump memory for forensic capture.",
        )

        # ----------------------------------------------------------------------
        # Blackboard Ingestion (Combining Live & Calibrated Seeded Findings)
        # ----------------------------------------------------------------------
        all_findings = [f_web, f_cloud, f_identity, f_host, f_malware, f_forensics]
        for f in all_findings:
            blackboard.post_event(
                BlackboardEvent(
                    event_type=EventType.VULNERABILITY_CONFIRMED,
                    source_agent="orchestration_test",
                    target=f.target,
                    payload={"finding": f.model_dump()},
                )
            )

        # 3. Attack Graph Synthesis & Choke Point Detection
        graph_engine = AttackGraphEngine()
        assets = [
            HostAsset(hostname="enterprise-core.corp.local", ip="10.0.1.10"),
            HostAsset(hostname="WIN-DC01", ip="10.0.1.5"),
        ]
        graph = graph_engine.build_graph(assets=assets, findings=all_findings)
        assert len(graph.nodes) >= 4
        assert len(graph.edges) >= 2

        # 4. Autonomous Remediation Generation (IaC + Ansible + Rules)
        remed_engine = RemediationEngine(output_dir=str(out_dir / "remediation"))
        artifacts = remed_engine.remediate_campaign(all_findings)
        exported_files = remed_engine.export_artifacts(artifacts)
        assert len(exported_files) >= 5

        # Verify Terraform, Ansible, YARA/Sigma code exists on disk
        assert (out_dir / "remediation" / "terraform").exists()
        assert (out_dir / "remediation" / "ansible").exists()
        assert (out_dir / "remediation" / "yara").exists()
        assert (out_dir / "remediation" / "sigma").exists()

        # 5. Live SOAR Incident Alert Dispatch
        soar_adapter = SOARWebhookAdapter()
        secret = "full-spectrum-hmac-secret"
        soar_res = soar_adapter.dispatch(
            endpoint_url=live_soar_endpoint,
            platform=SOARPlatform.GENERIC,
            event_title="Full-Spectrum Autonomous Red Team Mission Alert",
            findings=all_findings,
            secret=secret,
            metadata={"mission_id": blackboard.campaign_id, "profile": "full-spectrum"},
        )
        assert soar_res["success"] is True
        assert soar_res["status_code"] == 200

        # Verify HMAC signature received at server
        captured = LiveWebhookReceiver.dispatched_events[-1]
        sig_header = next((v for k, v in captured["headers"].items() if k.lower() == "x-revenant-signature"), None)
        assert sig_header is not None
        assert sig_header.startswith("sha256=")

        # 6. Multi-Format Enterprise Reporting Generation
        generator = ReportGenerator(
            campaign_id=blackboard.campaign_id,
            target=target,
            assets=assets,
            findings=all_findings,
            metadata={"profile": "full-spectrum"},
        )

        # Markdown
        md_text = generator.generate_markdown()
        (out_dir / "report.md").write_text(md_text, encoding="utf-8")
        assert "Reflected Cross-Site Scripting" in md_text
        assert "Exposed S3" in md_text
        assert "Detect_Webshell_PHP" in md_text

        # SARIF v2.1.0
        sarif_data = generator.generate_sarif()
        (out_dir / "report.sarif").write_text(json.dumps(sarif_data), encoding="utf-8")
        assert sarif_data["version"] == "2.1.0"

        # MITRE ATT&CK Navigator Layer
        nav_data = generator.generate_attack_navigator()
        (out_dir / "report.attack_nav.json").write_text(json.dumps(nav_data), encoding="utf-8")
        assert "REVENANT" in nav_data["name"]

        # Faraday Vulnerability Management JSON
        faraday_data = FaradayExporter().export(
            campaign_id=blackboard.campaign_id,
            target=target,
            assets=assets,
            findings=all_findings,
        )
        (out_dir / "faraday.json").write_text(json.dumps(faraday_data), encoding="utf-8")
        assert faraday_data["faraday_schema_version"] == "3.0"
        assert len(faraday_data["vulnerabilities"]) == len(all_findings)

        # Dradis Project Template JSON
        dradis_data = DradisExporter().export(
            campaign_id=blackboard.campaign_id,
            target=target,
            assets=assets,
            findings=all_findings,
        )
        (out_dir / "dradis.json").write_text(json.dumps(dradis_data), encoding="utf-8")
        assert dradis_data["dradis_template_version"] == "4.0"
        assert len(dradis_data["issues"]) == len(all_findings)

        # Confirm all 5 report files exist and are populated
        for fname in ["report.md", "report.sarif", "report.attack_nav.json", "faraday.json", "dradis.json"]:
            p = out_dir / fname
            assert p.exists()
            assert p.stat().st_size > 0
