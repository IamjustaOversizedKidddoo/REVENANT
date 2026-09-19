"""
REVENANT — Attack Graph Correlation Engine
Synthesizes multi-domain findings (Network, Web, Code Secrets, Cloud, Identity)
into a unified directed attack graph, linking exploit chains and identifying choke points.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from control_plane.schemas.attack_graph import (
    AttackGraph,
    EdgeRelationship,
    GraphEdge,
    GraphNode,
    NodeType,
)
from control_plane.schemas.models import Finding, HostAsset, Severity


class AttackGraphEngine:
    """Correlates disparate findings and assets across security domains into an attack graph."""

    def build_graph(
        self,
        assets: List[HostAsset],
        findings: List[Finding],
        target_name: Optional[str] = None,
    ) -> AttackGraph:
        """Construct the complete multi-domain attack graph from discovered assets and findings."""
        graph = AttackGraph()

        # 1. Map Discovered Assets into Nodes
        asset_node_ids: Dict[str, str] = {}
        for asset in assets:
            raw_id = asset.hostname or asset.ip or asset.id
            node_id = f"asset_{re.sub(r'[^a-zA-Z0-9_]', '_', raw_id)}"

            # Classify node type
            node_type = NodeType.ASSET
            meta = asset.metadata or {}
            source = meta.get("source", "")
            if "bloodhound" in source or "identity" in meta:
                node_type = NodeType.IDENTITY
            elif "prowler" in source or "certipy" in source:
                node_type = NodeType.CLOUD_RESOURCE if "prowler" in source else NodeType.IDENTITY

            graph.add_node(
                GraphNode(
                    id=node_id,
                    label=raw_id,
                    node_type=node_type,
                    metadata=meta,
                )
            )
            asset_node_ids[raw_id] = node_id
            if asset.ip:
                asset_node_ids[asset.ip] = node_id
            if asset.hostname:
                asset_node_ids[asset.hostname] = node_id

        # 2. Map Findings into Vulnerability & Credential Nodes
        finding_node_ids: Dict[str, str] = {}
        for idx, finding in enumerate(findings):
            f_node_id = f"vuln_{idx}_{re.sub(r'[^a-zA-Z0-9_]', '_', finding.tool)}_{finding.cwe or 'flaw'}"
            node_type = NodeType.CREDENTIAL if finding.cwe == "CWE-798" or finding.secret_type else NodeType.VULNERABILITY

            graph.add_node(
                GraphNode(
                    id=f_node_id,
                    label=finding.title,
                    node_type=node_type,
                    severity=finding.severity,
                    metadata={
                        "cwe": finding.cwe,
                        "mitre_attack_ids": finding.mitre_attack_ids,
                        "tool": finding.tool,
                        "remediation": finding.remediation,
                    },
                )
            )
            finding_node_ids[finding.id] = f_node_id

            # Link finding to target asset if matched
            matched_asset_id = None
            for raw_name, a_node_id in asset_node_ids.items():
                if raw_name in (finding.endpoint or "") or raw_name in finding.target:
                    matched_asset_id = a_node_id
                    break

            if matched_asset_id:
                graph.add_edge(
                    GraphEdge(
                        source=matched_asset_id,
                        target=f_node_id,
                        relationship=EdgeRelationship.EXPOSES if node_type == NodeType.CREDENTIAL else EdgeRelationship.AFFECTS,
                        label=finding.severity.value,
                    )
                )
            else:
                # Create a target anchor node
                t_anchor = f"target_{re.sub(r'[^a-zA-Z0-9_]', '_', finding.target)}"
                if t_anchor not in graph.nodes:
                    graph.add_node(
                        GraphNode(
                            id=t_anchor,
                            label=finding.target,
                            node_type=NodeType.ASSET,
                        )
                    )
                graph.add_edge(
                    GraphEdge(
                        source=t_anchor,
                        target=f_node_id,
                        relationship=EdgeRelationship.AFFECTS,
                        label=finding.severity.value,
                    )
                )

        # 3. Synthesize Cross-Domain Exploit Chains
        for finding in findings:
            f_node_id = finding_node_ids.get(finding.id)
            if not f_node_id:
                continue

            # Chain A: Leaked Credentials / Secrets (CWE-798) -> Cloud Infrastructure
            if finding.cwe == "CWE-798" or "credential" in finding.title.lower() or "secret" in finding.title.lower():
                cloud_dest = "obj_cloud_iam"
                if cloud_dest not in graph.nodes:
                    graph.add_node(
                        GraphNode(
                            id=cloud_dest,
                            label="AWS / Cloud Control Plane Access",
                            node_type=NodeType.OBJECTIVE,
                            severity=Severity.CRITICAL,
                        )
                    )
                graph.add_edge(
                    GraphEdge(
                        source=f_node_id,
                        target=cloud_dest,
                        relationship=EdgeRelationship.AUTHENTICATES_TO,
                        label="Privileged Auth",
                    )
                )

            # Chain B: Web DAST Flaws (SQLi / XSS / LFI) -> Backend Data / Host Access
            if finding.cwe == "CWE-89":  # SQL Injection
                db_dest = "obj_database_access"
                if db_dest not in graph.nodes:
                    graph.add_node(
                        GraphNode(
                            id=db_dest,
                            label="Database Exfiltration & Tampering",
                            node_type=NodeType.OBJECTIVE,
                            severity=Severity.CRITICAL,
                        )
                    )
                graph.add_edge(
                    GraphEdge(
                        source=f_node_id,
                        target=db_dest,
                        relationship=EdgeRelationship.LEADS_TO,
                        label="Data Leakage",
                    )
                )

            # Chain C: Active Directory Kerberoasting & AS-REP Roasting -> Domain Compromise
            if "T1558.003" in finding.mitre_attack_ids or "kerberoast" in finding.title.lower():
                da_dest = "obj_domain_admin"
                if da_dest not in graph.nodes:
                    graph.add_node(
                        GraphNode(
                            id=da_dest,
                            label="Active Directory Domain Admin Privileges",
                            node_type=NodeType.OBJECTIVE,
                            severity=Severity.CRITICAL,
                        )
                    )
                graph.add_edge(
                    GraphEdge(
                        source=f_node_id,
                        target=da_dest,
                        relationship=EdgeRelationship.ESCALATES_TO,
                        label="Offline Crack",
                    )
                )

            if "T1558.001" in finding.mitre_attack_ids or "unconstrained delegation" in finding.title.lower():
                dc_dest = "obj_domain_controller"
                if dc_dest not in graph.nodes:
                    graph.add_node(
                        GraphNode(
                            id=dc_dest,
                            label="Domain Controller TGT Impersonation",
                            node_type=NodeType.OBJECTIVE,
                            severity=Severity.CRITICAL,
                        )
                    )
                graph.add_edge(
                    GraphEdge(
                        source=f_node_id,
                        target=dc_dest,
                        relationship=EdgeRelationship.ESCALATES_TO,
                        label="TGT Harvesting",
                    )
                )

            # Chain D: AD CS ESC1 / ESC4 / ESC8 -> Enterprise CA Elevation
            if "T1649" in finding.mitre_attack_ids or "ESC1" in finding.title:
                ca_dest = "obj_pki_admin"
                if ca_dest not in graph.nodes:
                    graph.add_node(
                        GraphNode(
                            id=ca_dest,
                            label="Forest-Wide Domain Admin via PKINIT",
                            node_type=NodeType.OBJECTIVE,
                            severity=Severity.CRITICAL,
                        )
                    )
                graph.add_edge(
                    GraphEdge(
                        source=f_node_id,
                        target=ca_dest,
                        relationship=EdgeRelationship.ESCALATES_TO,
                        label="Arbitrary SAN",
                    )
                )

            # Chain E: Container Escape / Host Breakout
            if (
                ("CWE-250" in (finding.cwe or "") and ("privileged" in finding.title.lower() or "root" in finding.title.lower()))
                or "T1611" in finding.mitre_attack_ids
                or any(k in finding.title.lower() for k in ["escape", "hostpath", "hostpid", "docker.sock"])
            ):
                host_dest = "obj_host_kernel"
                if host_dest not in graph.nodes:
                    graph.add_node(
                        GraphNode(
                            id=host_dest,
                            label="Host Node Root Execution",
                            node_type=NodeType.OBJECTIVE,
                            severity=Severity.HIGH,
                        )
                    )
                graph.add_edge(
                    GraphEdge(
                        source=f_node_id,
                        target=host_dest,
                        relationship=EdgeRelationship.ESCALATES_TO,
                        label="Container Breakout",
                    )
                )

            # Chain E2: Kubernetes Dangerous RBAC / Cluster-Admin Takeover
            if any(k in finding.title.lower() for k in ["cluster-admin", "clusterrole", "dangerous rbac", "serviceaccount"]):
                k8s_dest = "obj_k8s_cluster_admin"
                if k8s_dest not in graph.nodes:
                    graph.add_node(
                        GraphNode(
                            id=k8s_dest,
                            label="Kubernetes Cluster-Admin Takeover",
                            node_type=NodeType.OBJECTIVE,
                            severity=Severity.CRITICAL,
                        )
                    )
                graph.add_edge(
                    GraphEdge(
                        source=f_node_id,
                        target=k8s_dest,
                        relationship=EdgeRelationship.AUTHENTICATES_TO,
                        label="Privileged ServiceAccount",
                    )
                )

            # Chain F: AI / LLM Excessive Agency & Prompt Injection -> Autonomous Agent Control
            if (finding.owasp_category and "LLM" in finding.owasp_category) or "AI/LLM" in finding.title:
                if "LLM06" in (finding.owasp_category or "") or "agency" in finding.title.lower() or "injection" in finding.title.lower():
                    ai_dest = "obj_agent_hijack"
                    if ai_dest not in graph.nodes:
                        graph.add_node(
                            GraphNode(
                                id=ai_dest,
                                label="Autonomous Agent Hijack & Arbitrary Tool Invocation",
                                node_type=NodeType.OBJECTIVE,
                                severity=Severity.CRITICAL,
                            )
                        )
                    graph.add_edge(
                        GraphEdge(
                            source=f_node_id,
                            target=ai_dest,
                            relationship=EdgeRelationship.ESCALATES_TO,
                            label="Agent Control",
                        )
                    )

            # Chain G: Mobile Application Vulnerabilities -> Backend API Breach & Local Compromise
            if (finding.owasp_category and "MASVS" in finding.owasp_category) or "Mobile:" in finding.title:
                if "MASVS-PLATFORM" in (finding.owasp_category or "") or "exported" in finding.title.lower() or "CWE-926" in (finding.cwe or ""):
                    mobile_dest = "obj_mobile_ipc_takeover"
                    if mobile_dest not in graph.nodes:
                        graph.add_node(
                            GraphNode(
                                id=mobile_dest,
                                label="Mobile Application Component Hijack & Data Theft",
                                node_type=NodeType.OBJECTIVE,
                                severity=Severity.HIGH,
                            )
                        )
                    graph.add_edge(
                        GraphEdge(
                            source=f_node_id,
                            target=mobile_dest,
                            relationship=EdgeRelationship.ESCALATES_TO,
                            label="IPC Abuse",
                        )
                    )

            # Chain H: Purple Team Adversary Emulation & Detection Blind Spots -> Unmonitored Lateral Movement
            if finding.tool in ["atomic_red_team", "detection_engine", "caldera"] or "Blind Spot" in finding.title or "Emulated TTP" in finding.title:
                purple_dest = "obj_unmonitored_adversary_path"
                if purple_dest not in graph.nodes:
                    graph.add_node(
                        GraphNode(
                            id=purple_dest,
                            label="Unmonitored Adversary Attack Path & Lateral Move",
                            node_type=NodeType.OBJECTIVE,
                            severity=Severity.HIGH,
                        )
                    )
                graph.add_edge(
                    GraphEdge(
                        source=f_node_id,
                        target=purple_dest,
                        relationship=EdgeRelationship.ESCALATES_TO,
                        label="Evasion / Blind Spot",
                    )
                )

            # Chain I: Endpoint Forensics — Process Injection, Memory Implants & Persistence
            if finding.tool in ["volatility3", "velociraptor"] or any(t in finding.mitre_attack_ids for t in ["T1055", "T1055.001", "T1547.001", "T1071"]):
                # I1: In-Memory Stealth Process Injection
                if any(t in finding.mitre_attack_ids for t in ["T1055", "T1055.001"]) or "injection" in finding.title.lower():
                    implant_dest = "obj_in_memory_implant"
                    if implant_dest not in graph.nodes:
                        graph.add_node(
                            GraphNode(
                                id=implant_dest,
                                label="In-Memory Process Injection & Code Execution",
                                node_type=NodeType.OBJECTIVE,
                                severity=Severity.CRITICAL,
                            )
                        )
                    graph.add_edge(
                        GraphEdge(
                            source=f_node_id,
                            target=implant_dest,
                            relationship=EdgeRelationship.ESCALATES_TO,
                            label="Process Hollow / Injection",
                        )
                    )

                # I2: Autostart Host Persistence
                if any(t in finding.mitre_attack_ids for t in ["T1547", "T1547.001"]) or "persistence" in finding.title.lower():
                    persist_dest = "obj_endpoint_persistence"
                    if persist_dest not in graph.nodes:
                        graph.add_node(
                            GraphNode(
                                id=persist_dest,
                                label="Reboot-Resistant Host Endpoint Persistence",
                                node_type=NodeType.OBJECTIVE,
                                severity=Severity.HIGH,
                            )
                        )
                    graph.add_edge(
                        GraphEdge(
                            source=f_node_id,
                            target=persist_dest,
                            relationship=EdgeRelationship.LEADS_TO,
                            label="Autostart Registry / Service",
                        )
                    )

                # I3: Active C2 Beaconing
                if any(t in finding.mitre_attack_ids for t in ["T1071", "T1071.001"]) or "c2" in finding.title.lower() or "socket" in finding.title.lower():
                    c2_dest = "obj_c2_channel"
                    if c2_dest not in graph.nodes:
                        graph.add_node(
                            GraphNode(
                                id=c2_dest,
                                label="Active C2 Beaconing & External Exfiltration Channel",
                                node_type=NodeType.OBJECTIVE,
                                severity=Severity.CRITICAL,
                            )
                        )
                    graph.add_edge(
                        GraphEdge(
                            source=f_node_id,
                            target=c2_dest,
                            relationship=EdgeRelationship.LEADS_TO,
                            label="Outbound C2",
                        )
                    )

            # Chain J: Malware Analysis — Webshells, Packed Implants & C2 Exfiltration
            if finding.tool in ["yara", "capev2_sandbox", "binary_triage"] or any(t in finding.mitre_attack_ids for t in ["T1505.003", "T1027.002", "T1105"]):
                # J1: Persistent Webshell Access
                if any(t in finding.mitre_attack_ids for t in ["T1505", "T1505.003"]) or "webshell" in finding.title.lower():
                    ws_dest = "obj_webshell_access"
                    if ws_dest not in graph.nodes:
                        graph.add_node(
                            GraphNode(
                                id=ws_dest,
                                label="Persistent Web Shell & Arbitrary Command Execution",
                                node_type=NodeType.OBJECTIVE,
                                severity=Severity.CRITICAL,
                            )
                        )
                    graph.add_edge(
                        GraphEdge(
                            source=f_node_id,
                            target=ws_dest,
                            relationship=EdgeRelationship.ESCALATES_TO,
                            label="Webshell Command Exec",
                        )
                    )

                # J2: Packed / Obfuscated Evasion
                if any(t in finding.mitre_attack_ids for t in ["T1027", "T1027.002"]) or "entropy" in finding.title.lower() or "packed" in finding.title.lower():
                    pack_dest = "obj_packed_evasion"
                    if pack_dest not in graph.nodes:
                        graph.add_node(
                            GraphNode(
                                id=pack_dest,
                                label="Packed Binary Defeating Static Signatures & AV Evasion",
                                node_type=NodeType.OBJECTIVE,
                                severity=Severity.HIGH,
                            )
                        )
                    graph.add_edge(
                        GraphEdge(
                            source=f_node_id,
                            target=pack_dest,
                            relationship=EdgeRelationship.ESCALATES_TO,
                            label="AV Evasion",
                        )
                    )

                # J3: Malware C2 Channel
                if any(t in finding.mitre_attack_ids for t in ["T1071.001", "T1041"]) or "c2" in finding.title.lower() or "beacon" in finding.title.lower():
                    c2_dest = "obj_c2_channel"
                    if c2_dest not in graph.nodes:
                        graph.add_node(
                            GraphNode(
                                id=c2_dest,
                                label="Active C2 Beaconing & External Exfiltration Channel",
                                node_type=NodeType.OBJECTIVE,
                                severity=Severity.CRITICAL,
                            )
                        )
                    graph.add_edge(
                        GraphEdge(
                            source=f_node_id,
                            target=c2_dest,
                            relationship=EdgeRelationship.LEADS_TO,
                            label="Malware Beaconing",
                        )
                    )

            # Chain K: Firmware, Embedded Devices & Binary Fuzzing Exploitation
            if finding.tool in ["binwalk", "afl_fuzzer"] or any(t in finding.mitre_attack_ids for t in ["T1552.004", "T1190"]) or "firmware" in finding.title.lower():
                # K1: Hardcoded Embedded Key / Backdoor Access
                if any(t in finding.mitre_attack_ids for t in ["T1552.004", "T1552"]) or "key" in finding.title.lower() or "credential" in finding.title.lower():
                    fw_dest = "obj_firmware_backdoor"
                    if fw_dest not in graph.nodes:
                        graph.add_node(
                            GraphNode(
                                id=fw_dest,
                                label="Hardcoded Firmware Key & Root Device Access",
                                node_type=NodeType.OBJECTIVE,
                                severity=Severity.CRITICAL,
                            )
                        )
                    graph.add_edge(
                        GraphEdge(
                            source=f_node_id,
                            target=fw_dest,
                            relationship=EdgeRelationship.AUTHENTICATES_TO,
                            label="Firmware Key Exploit",
                        )
                    )

                # K2: Memory Corruption / Fuzzing Zero-Day RCE
                if finding.tool == "afl_fuzzer" or any(k in finding.title.lower() for k in ["buffer overflow", "use-after-free", "stack overflow", "memory sanitizer"]):
                    rce_dest = "obj_zero_day_rce"
                    if rce_dest not in graph.nodes:
                        graph.add_node(
                            GraphNode(
                                id=rce_dest,
                                label="Zero-Day Native Remote Code Execution via Memory Corruption",
                                node_type=NodeType.OBJECTIVE,
                                severity=Severity.CRITICAL,
                            )
                        )
                    graph.add_edge(
                        GraphEdge(
                            source=f_node_id,
                            target=rce_dest,
                            relationship=EdgeRelationship.ESCALATES_TO,
                            label="Memory Corruption RCE",
                        )
                    )

        return graph

