"""
REVENANT — Mission Profile Registry
Pre-configured assessment templates mapping operational objectives to specialized agent swarms,
iteration caps, timeouts, and execution parameters.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple
from pydantic import BaseModel, Field


class MissionProfile(BaseModel):
    """Configuration template defining agent engagement rules and scope focus."""
    name: str
    description: str
    target_type: str
    active_agents: List[str]
    max_iterations: int = 25
    timeout_seconds: int = 300
    safe_mode_default: bool = True
    capabilities: List[str] = Field(default_factory=list)


# Standard Built-In Mission Profiles
PROFILES: Dict[str, MissionProfile] = {
    "recon": MissionProfile(
        name="recon",
        description="Perimeter discovery, subdomain mapping, DNS enumeration, and open port fingerprinting.",
        target_type="domain_or_ip",
        active_agents=["recon", "crawl"],
        max_iterations=10,
        timeout_seconds=180,
        safe_mode_default=True,
        capabilities=[
            "Subdomain discovery via Subfinder",
            "Port discovery & service fingerprinting via Nmap / HTTPX",
            "Perimeter attack surface baseline",
        ],
    ),
    "web-dast": MissionProfile(
        name="web-dast",
        description="Deep application crawling, API parameter discovery, and dynamic injection vulnerability testing.",
        target_type="url",
        active_agents=["crawl", "dast", "triage"],
        max_iterations=20,
        timeout_seconds=300,
        safe_mode_default=True,
        capabilities=[
            "Recursive link & form extraction via Katana",
            "OpenAPI / Swagger schema fuzzing via Schemathesis",
            "Dynamic injection sweeps: Reflected XSS, Open Redirect, Path Traversal",
        ],
    ),
    "cloud-native": MissionProfile(
        name="cloud-native",
        description="AWS / multi-cloud posture audit, Terraform misconfiguration detection, and Kubernetes cluster security.",
        target_type="cloud_or_manifest",
        active_agents=["cloud", "kubernetes", "triage"],
        max_iterations=25,
        timeout_seconds=360,
        safe_mode_default=True,
        capabilities=[
            "AWS CIS Benchmarks via Prowler",
            "Infrastructure-as-Code scanning via Checkov",
            "Kubernetes PodSecurity & RBAC audit via Kubescape & Kube-bench",
        ],
    ),
    "ad-identity": MissionProfile(
        name="ad-identity",
        description="Active Directory privilege escalation, BloodHound OpenCypher attack path analysis, and AD CS audit.",
        target_type="ip_or_domain",
        active_agents=["identity", "triage"],
        max_iterations=25,
        timeout_seconds=360,
        safe_mode_default=True,
        capabilities=[
            "BloodHound Kerberoasting & ACL path discovery",
            "Active Directory Certificate Services (AD CS) escalation via Certipy",
            "SMB session & authentication validation via NetExec (NXC)",
        ],
    ),
    "full-spectrum": MissionProfile(
        name="full-spectrum",
        description="Complete autonomous cyber warfare assessment engaging all 20+ specialized agents with cross-domain attack graph synthesis.",
        target_type="any",
        active_agents=[
            "recon",
            "crawl",
            "dast",
            "code",
            "cloud",
            "identity",
            "kubernetes",
            "forensics",
            "malware",
            "firmware",
            "purple",
            "triage",
        ],
        max_iterations=50,
        timeout_seconds=600,
        safe_mode_default=True,
        capabilities=[
            "Multi-domain assessment across Web, Cloud, Network, AD, Code, and DFIR",
            "Living Attack Graph correlation & choke point identification",
            "Automated IaC & Ansible remediation code generation",
            "Real-time SOAR webhook alert dispatching",
        ],
    ),
}


def get_profile(name: str) -> Optional[MissionProfile]:
    """Retrieve mission profile by name (case-insensitive)."""
    return PROFILES.get(name.lower().strip())


def list_profiles() -> List[MissionProfile]:
    """Return all registered mission profiles."""
    return list(PROFILES.values())


def validate_profile_target(profile: MissionProfile, target: str) -> Tuple[bool, str]:
    """Validate target format compatibility with the selected profile."""
    if not target or not target.strip():
        return False, "Target cannot be empty"

    target_clean = target.strip()
    if profile.target_type == "url":
        if not (target_clean.startswith("http://") or target_clean.startswith("https://")):
            return False, f"Profile '{profile.name}' requires a full HTTP/HTTPS URL target (e.g. http://127.0.0.1:3000)"

    return True, "Target format valid"
