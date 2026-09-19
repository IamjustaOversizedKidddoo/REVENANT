"""
REVENANT — Milestone 2.5 Test Suite: Attack Graph Engine & MITRE ATT&CK Matrix Correlation
Tests:
1. AttackGraph data structure: node/edge management, traversal, choke point identification, Mermaid.js synthesis.
2. AttackGraphEngine cross-domain synthesis: correlates Recon, Web, Code Secrets, Cloud, and Identity into exploit chains.
3. MitreMapper: maps findings to MITRE ATT&CK Enterprise Matrix v14 tactics & techniques, validates Navigator v4.5 layer schema.
4. Multi-format reporting engine integration: Markdown with Mermaid, HTML with interactive heatmaps, SARIF with taxonomies, JSON graph dumps.
"""

from pathlib import Path
import pytest

from control_plane.schemas.attack_graph import (
    AttackGraph,
    EdgeRelationship,
    GraphEdge,
    GraphNode,
    NodeType,
)
from control_plane.schemas.models import (
    CodeLocation,
    Finding,
    HostAsset,
    Severity,
)
from orchestrator.correlation.attack_graph_engine import AttackGraphEngine
from reporting.generator import ReportGenerator
from reporting.mitre_mapper import MitreMapper


# =============================================================================
# 1. AttackGraph Model Unit Tests
# =============================================================================

def test_attack_graph_node_and_edge_management():
    """Verify node and edge addition, deduplication, and adjacency calculation."""
    graph = AttackGraph()

    node1 = GraphNode(id="host_1", label="192.168.1.10", node_type=NodeType.ASSET)
    node2 = GraphNode(id="vuln_1", label="SQL Injection in /login", node_type=NodeType.VULNERABILITY, severity=Severity.CRITICAL)
    node3 = GraphNode(id="obj_db", label="Customer DB", node_type=NodeType.OBJECTIVE, severity=Severity.CRITICAL)

    graph.add_node(node1)
    graph.add_node(node2)
    graph.add_node(node3)

    # Add edges
    graph.add_edge(GraphEdge(source="host_1", target="vuln_1", relationship=EdgeRelationship.AFFECTS))
    graph.add_edge(GraphEdge(source="vuln_1", target="obj_db", relationship=EdgeRelationship.LEADS_TO))
    # Test deduplication
    graph.add_edge(GraphEdge(source="host_1", target="vuln_1", relationship=EdgeRelationship.AFFECTS))

    assert len(graph.nodes) == 3
    assert len(graph.edges) == 2

    adj = graph.get_adjacency()
    assert adj["host_1"] == ["vuln_1"]
    assert adj["vuln_1"] == ["obj_db"]
    assert adj["obj_db"] == []


def test_attack_graph_paths_and_choke_points():
    """Verify critical path traversal and choke point frequency ranking."""
    graph = AttackGraph()

    # Create two converging entry paths meeting at a choke point
    graph.add_node(GraphNode(id="entry_web", label="Public Web App", node_type=NodeType.ASSET))
    graph.add_node(GraphNode(id="entry_api", label="Public API Gateway", node_type=NodeType.ASSET))
    graph.add_node(GraphNode(id="vuln_auth", label="Broken Authentication Token", node_type=NodeType.CREDENTIAL, severity=Severity.HIGH))
    graph.add_node(GraphNode(id="obj_admin", label="Domain Administrator", node_type=NodeType.OBJECTIVE, severity=Severity.CRITICAL))

    graph.add_edge(GraphEdge(source="entry_web", target="vuln_auth", relationship=EdgeRelationship.EXPOSES))
    graph.add_edge(GraphEdge(source="entry_api", target="vuln_auth", relationship=EdgeRelationship.EXPOSES))
    graph.add_edge(GraphEdge(source="vuln_auth", target="obj_admin", relationship=EdgeRelationship.ESCALATES_TO))

    paths = graph.find_attack_paths()
    assert len(paths) >= 2

    choke_points = graph.find_choke_points()
    assert len(choke_points) >= 1
    # vuln_auth should be the top choke point because both web and api pass through it
    top_choke = choke_points[0]
    assert top_choke["node_id"] == "vuln_auth"
    assert top_choke["attack_paths_affected"] >= 2
    assert top_choke["remediation_priority"] in ["CRITICAL", "HIGH"]


def test_attack_graph_mermaid_generation():
    """Verify Mermaid.js flowchart syntax generation."""
    graph = AttackGraph()
    graph.add_node(GraphNode(id="srv", label="Database Server", node_type=NodeType.ASSET))
    graph.add_node(GraphNode(id="cred", label="Leaked Root Password", node_type=NodeType.CREDENTIAL, severity=Severity.CRITICAL))
    graph.add_edge(GraphEdge(source="srv", target="cred", relationship=EdgeRelationship.EXPOSES))

    mermaid_str = graph.to_mermaid()
    assert mermaid_str.startswith("```mermaid")
    assert "flowchart LR" in mermaid_str
    assert "classDef" in mermaid_str
    assert "Database Server" in mermaid_str
    assert "Leaked Root Password" in mermaid_str
    assert "EXPOSES" in mermaid_str
    assert mermaid_str.endswith("```")


# =============================================================================
# 2. AttackGraphEngine Cross-Domain Correlation Tests
# =============================================================================

def test_attack_graph_engine_cross_domain_synthesis():
    """Verify synthesis of multi-domain assets and findings into connected exploit chains."""
    engine = AttackGraphEngine()

    assets = [
        HostAsset(hostname="app.corp.local", ip="10.0.0.50"),
        HostAsset(hostname="WS-DEV01.CORP.LOCAL"),
    ]

    findings = [
        # Domain 1: Code Secret (SAST)
        Finding(
            title="Hardcoded AWS Secret Key",
            description="Leaked AWS credentials in source code",
            severity=Severity.CRITICAL,
            target="app.corp.local",
            tool="gitleaks",
            cwe="CWE-798",
        ),
        # Domain 2: Web DAST
        Finding(
            title="SQL Injection in Search Form",
            description="Exploitable SQL injection vulnerability",
            severity=Severity.CRITICAL,
            target="app.corp.local",
            tool="dast",
            cwe="CWE-89",
        ),
        # Domain 3: Active Directory Identity
        Finding(
            title="Active Directory: Kerberoastable Privileged Account",
            description="SPN on Domain Admin",
            severity=Severity.CRITICAL,
            target="WS-DEV01.CORP.LOCAL",
            tool="bloodhound",
            cwe="CWE-521",
            mitre_attack_ids=["T1558.003"],
        ),
    ]

    graph = engine.build_graph(assets, findings, "corp.local")
    assert len(graph.nodes) >= 5
    assert len(graph.edges) >= 4

    # Verify synthesized objective nodes
    labels = [n.label for n in graph.nodes.values()]
    assert any("AWS" in l or "Cloud" in l for l in labels)
    assert any("Database" in l for l in labels)
    assert any("Domain Admin" in l for l in labels)

    # Verify choke points calculated
    choke_points = graph.find_choke_points()
    assert len(choke_points) >= 1


# =============================================================================
# 3. MitreMapper Unit Tests
# =============================================================================

def test_mitre_mapper_cwe_resolution():
    """Verify resolution of CWEs and tools to MITRE ATT&CK techniques and tactics."""
    mapper = MitreMapper()

    # SAST Credential
    f_cred = Finding(
        title="Hardcoded API Secret",
        description="Leaked token",
        severity=Severity.HIGH,
        target="repo",
        tool="gitleaks",
        cwe="CWE-798",
    )
    mapped_cred = mapper.map_finding(f_cred)
    assert len(mapped_cred) >= 1
    assert any(m["technique_id"] == "T1552.001" for m in mapped_cred)
    assert any(m["tactic_id"] == "TA0006" for m in mapped_cred)

    # Web SQLi
    f_sqli = Finding(
        title="SQL Injection",
        description="SQL flaw",
        severity=Severity.CRITICAL,
        target="http://example.com",
        tool="dast",
        cwe="CWE-89",
    )
    mapped_sqli = mapper.map_finding(f_sqli)
    assert any(m["technique_id"] == "T1190" for m in mapped_sqli)
    assert any(m["tactic_id"] == "TA0001" for m in mapped_sqli)

    # Active Directory ESC1
    f_esc1 = Finding(
        title="AD CS ESC1 Misconfiguration",
        description="Arbitrary SAN",
        severity=Severity.CRITICAL,
        target="ADCS/ESC1",
        tool="certipy",
        cwe="CWE-295",
        mitre_attack_ids=["T1649"],
    )
    mapped_esc1 = mapper.map_finding(f_esc1)
    assert any(m["technique_id"] == "T1649" for m in mapped_esc1)
    assert any(m["tactic_id"] == "TA0004" for m in mapped_esc1)


def test_mitre_mapper_navigator_layer_generation():
    """Verify compliance of generated JSON with MITRE ATT&CK Navigator v4.5 specification."""
    mapper = MitreMapper()
    findings = [
        Finding(
            title="Kerberoasting",
            description="Service ticket crack",
            severity=Severity.CRITICAL,
            target="dc.local",
            tool="bloodhound",
            mitre_attack_ids=["T1558.003"],
        ),
        Finding(
            title="S3 Public Access",
            description="Open cloud storage",
            severity=Severity.HIGH,
            target="s3://bucket",
            tool="prowler",
            cwe="CWE-732",
        ),
    ]

    layer = mapper.generate_navigator_layer(findings, "test-campaign-001")
    assert layer["name"] == "REVENANT Red Team Campaign — test-campaign-001"
    assert layer["versions"]["layer"] == "4.5"
    assert layer["versions"]["navigator"] == "4.9.1"
    assert len(layer["techniques"]) >= 2

    # Check technique entry fields
    tech = layer["techniques"][0]
    assert "techniqueID" in tech
    assert "score" in tech
    assert "color" in tech
    assert "comment" in tech
    assert tech["enabled"] is True


def test_mitre_markdown_and_html_heatmaps():
    """Verify rendering of Markdown and HTML MITRE heatmaps."""
    mapper = MitreMapper()
    findings = [
        Finding(
            title="Unconstrained Delegation",
            description="TGT harvesting",
            severity=Severity.CRITICAL,
            target="ws01",
            tool="bloodhound",
            mitre_attack_ids=["T1558.001"],
        )
    ]

    md_table = mapper.generate_markdown_heatmap(findings)
    assert "| MITRE Tactic | Technique ID | Technique Name |" in md_table
    assert "T1558.001" in md_table
    assert "Privilege Escalation" in md_table

    html_heatmap = mapper.generate_html_heatmap(findings)
    assert "T1558.001" in html_heatmap
    assert "Privilege Escalation" in html_heatmap


# =============================================================================
# 4. Multi-Format Reporting Integration Tests
# =============================================================================

def test_full_report_generator_with_attack_graph_and_mitre():
    """
    Verify that ReportGenerator seamlessly synthesizes the attack graph,
    Mermaid diagrams, choke points, and MITRE taxonomies across MD, HTML, SARIF, and JSON.
    """
    assets = [
        HostAsset(hostname="portal.revenant.lab", ip="10.0.0.100"),
        HostAsset(hostname="DC01.REVENANT.LOCAL"),
    ]

    findings = [
        Finding(
            title="Hardcoded Production Secret",
            description="API key in settings.py",
            severity=Severity.CRITICAL,
            target="portal.revenant.lab",
            tool="trufflehog",
            cwe="CWE-798",
            remediation="Use environment variables or Vault.",
        ),
        Finding(
            title="Reflected XSS in Search Query",
            description="XSS on /search",
            severity=Severity.HIGH,
            target="portal.revenant.lab/search",
            tool="dast",
            cwe="CWE-79",
            remediation="Encode user input in HTML output context.",
        ),
        Finding(
            title="Active Directory: Kerberoastable Account",
            description="Admin SPN ticket crackable",
            severity=Severity.CRITICAL,
            target="DC01.REVENANT.LOCAL/svc_sql",
            tool="bloodhound",
            cwe="CWE-521",
            mitre_attack_ids=["T1558.003"],
            remediation="Migrate service to gMSA.",
        ),
    ]

    generator = ReportGenerator(
        campaign_id="camp-graph-001",
        target="revenant.lab",
        assets=assets,
        findings=findings,
    )

    # 1. Markdown Verification
    md = generator.generate_markdown()
    assert "## Attack Graph & Exploit Chains" in md
    assert "```mermaid" in md
    assert "flowchart" in md
    assert "Strategic Remediation Choke Points" in md
    assert "## MITRE ATT&CK Enterprise Matrix Coverage" in md
    assert "T1558.003" in md

    # 2. HTML Verification
    html = generator.generate_html()
    assert "mermaid" in html
    assert "Strategic Remediation Choke Points" in html
    assert "MITRE ATT&CK Enterprise Matrix Coverage" in html

    # 3. SARIF v2.1.0 Verification
    sarif = generator.generate_sarif()
    assert sarif["version"] == "2.1.0"
    taxonomies = sarif["runs"][0].get("taxonomies", [])
    assert len(taxonomies) >= 1
    assert taxonomies[0]["name"] == "MITRE ATT&CK"
    assert any(t["id"] == "T1558.003" for t in taxonomies[0]["taxa"])

    # 4. JSON Verification
    raw_json = generator.generate_json()
    assert "attack_graph" in raw_json
    assert "nodes" in raw_json["attack_graph"]
    assert "edges" in raw_json["attack_graph"]
    assert "choke_points" in raw_json["attack_graph"]
    assert "mitre_matrix" in raw_json

    # 5. MITRE Navigator Layer Verification
    nav = generator.generate_attack_navigator()
    assert nav["versions"]["navigator"] == "4.9.1"
    assert nav["versions"]["layer"] == "4.5"
    assert len(nav["techniques"]) >= 2
