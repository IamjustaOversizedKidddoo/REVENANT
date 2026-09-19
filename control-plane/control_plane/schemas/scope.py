"""
REVENANT — Scope Boundary Enforcement Engine
Strict, defense-in-depth validation ensuring no tool, agent, or command touches
an unauthorized target. Evaluates domains, wildcards, CIDRs, IPs, and cloud metadata.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse
from pydantic import BaseModel, Field


class ScopeViolationError(PermissionError):
    """Raised when an operation targets an asset outside the authorized scope manifest."""
    def __init__(self, target: str, reason: str):
        super().__init__(f"SCOPE VIOLATION: Target '{target}' is unauthorized. Reason: {reason}")
        self.target = target
        self.reason = reason


# Link-local / Cloud Metadata IPs (AWS, GCP, Azure, OpenStack)
CLOUD_METADATA_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
]

# Multicast & Broadcast
MULTICAST_NETWORKS = [
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
]


class ScopeManifest(BaseModel):
    """Authorization manifest defining allowed and strictly forbidden targets."""
    name: str = "default-scope"
    allowed_cidrs: List[str] = Field(default_factory=list)
    allowed_domains: List[str] = Field(default_factory=list)
    allowed_wildcards: List[str] = Field(default_factory=list)  # e.g. ["*.example.com"]
    allowed_hosts: List[str] = Field(default_factory=list)      # e.g. ["localhost", "127.0.0.1"]
    allowed_repos: List[str] = Field(default_factory=list)      # e.g. ["/path/to/repo", "github.com/org/*"]
    allowed_cloud_accounts: List[str] = Field(default_factory=list) # e.g. ["123456789012", "my-gcp-project"]
    allowed_container_images: List[str] = Field(default_factory=list) # e.g. ["myregistry/app:*", "alpine:3.18"]
    allowed_identity_domains: List[str] = Field(default_factory=list) # e.g. ["CORP.LOCAL", "LAB.REVENANT"]
    denied_cidrs: List[str] = Field(default_factory=list)
    denied_domains: List[str] = Field(default_factory=list)
    allow_cloud_metadata: bool = False
    require_explicit_scope: bool = True
    max_parallel_active: int = 20


class ScopeEngine:
    """Core scope validator and gatekeeper."""

    def __init__(self, manifest: Optional[ScopeManifest] = None):
        self.manifest = manifest or ScopeManifest()
        self._parsed_allowed_cidrs = self._parse_cidrs(self.manifest.allowed_cidrs)
        self._parsed_denied_cidrs = self._parse_cidrs(self.manifest.denied_cidrs)

    @staticmethod
    def _parse_cidrs(cidrs: List[str]) -> List[ipaddress._BaseNetwork]:
        parsed = []
        for c in cidrs:
            try:
                parsed.append(ipaddress.ip_network(c.strip(), strict=False))
            except ValueError:
                continue
        return parsed

    @staticmethod
    def extract_host(target: str) -> str:
        """
        Extract raw hostname, IP, or path from target string, stripping protocols,
        ports, credentials, and query strings.
        """
        cleaned = target.strip()
        if not cleaned:
            return ""

        import os
        from pathlib import Path
        # If target is an existing filesystem path or repo directory, return as-is
        if os.path.exists(cleaned) or cleaned.endswith(".git"):
            return cleaned

        # Prepend scheme if missing so urlparse handles authority/port cleanly
        if "://" not in cleaned:
            test_url = "http://" + cleaned
        else:
            test_url = cleaned

        parsed = urlparse(test_url)
        host = parsed.hostname or ""

        # Fallback if urlparse struggled with bare host:port or IP:port
        if not host:
            # Strip port if present (e.g. localhost:3000 -> localhost)
            host = cleaned.split("/")[0].split(":")[0]

        # Lowercase and strip bracket encapsulation for IPv6 (e.g. [::1] -> ::1)
        return host.lower().strip("[]")

    def is_allowed(self, target: str) -> Tuple[bool, str]:
        """
        Check if target is authorized under the active scope manifest.
        Returns: (is_allowed: bool, reason: str)
        """
        import os
        from pathlib import Path

        cleaned_target = target.strip()
        if not cleaned_target:
            return False, "Target resolved to an empty host."

        # Check if target is a local filesystem path or repo directory
        if os.path.exists(cleaned_target):
            target_resolved = str(Path(cleaned_target).resolve()).lower()
            for allowed_repo in self.manifest.allowed_repos:
                if allowed_repo == "*" or allowed_repo.lower() in target_resolved or target_resolved.startswith(str(Path(allowed_repo).resolve()).lower()):
                    return True, f"Target path matches authorized repository manifest '{allowed_repo}'."
            if any(h in ["localhost", "127.0.0.1"] for h in self.manifest.allowed_hosts):
                return True, "Target is a local filesystem path authorized under localhost/127.0.0.1 scope."

        # Check container image authorization
        for img in self.manifest.allowed_container_images:
            pattern = img.lower()
            if img == "*" or fnmatch.fnmatch(cleaned_target.lower(), pattern) or cleaned_target.lower().startswith(pattern.rstrip("*")):
                return True, f"Target matches authorized container image '{img}'."

        # Check cloud account authorization
        for acc in self.manifest.allowed_cloud_accounts:
            pattern = acc.lower()
            if acc == "*" or fnmatch.fnmatch(cleaned_target.lower(), pattern) or pattern in cleaned_target.lower():
                return True, f"Target matches authorized cloud account '{acc}'."

        # Check identity domain authorization
        for dom in self.manifest.allowed_identity_domains:
            pattern = dom.lower()
            if dom == "*" or fnmatch.fnmatch(cleaned_target.lower(), pattern) or cleaned_target.lower().endswith(pattern) or pattern in cleaned_target.lower():
                return True, f"Target matches authorized identity domain '{dom}'."

        host = self.extract_host(cleaned_target)
        if not host:
            return False, "Target resolved to an empty host."

        # Check if manifest has any rules declared
        has_allowed_rules = bool(
            self.manifest.allowed_cidrs
            or self.manifest.allowed_domains
            or self.manifest.allowed_wildcards
            or self.manifest.allowed_hosts
            or self.manifest.allowed_repos
            or self.manifest.allowed_cloud_accounts
            or self.manifest.allowed_container_images
            or self.manifest.allowed_identity_domains
        )

        if not has_allowed_rules and self.manifest.require_explicit_scope:
            return False, "Scope manifest is empty. Explicit authorization is mandatory."

        # 1. Parse target as IP if possible
        target_ip: Optional[ipaddress._BaseAddress] = None
        try:
            target_ip = ipaddress.ip_address(host)
        except ValueError:
            target_ip = None

        # 2. Hard block link-local / cloud metadata (169.254.169.254, etc.)
        if target_ip and not self.manifest.allow_cloud_metadata:
            for meta_net in CLOUD_METADATA_NETWORKS:
                if target_ip in meta_net:
                    return False, f"Target IP '{host}' is a cloud metadata / link-local address (strictly blocked)."

        # 3. Hard block multicast
        if target_ip:
            for multi_net in MULTICAST_NETWORKS:
                if target_ip in multi_net:
                    return False, f"Target IP '{host}' is multicast (strictly blocked)."

        # 4. Check Denied CIDRs
        if target_ip:
            for denied_net in self._parsed_denied_cidrs:
                if target_ip in denied_net:
                    return False, f"Target IP '{host}' is in denied CIDR '{denied_net}'."

        # 5. Check Denied Domains / Wildcards
        for denied_domain in self.manifest.denied_domains:
            pattern = denied_domain.lower()
            if fnmatch.fnmatch(host, pattern) or host == pattern.lstrip("*."):
                return False, f"Target host '{host}' matches denied domain pattern '{denied_domain}'."

        # 6. Check Allowed Hosts (Direct match for localhost, IPs, or specific hostnames)
        for allowed_host in self.manifest.allowed_hosts:
            if host == allowed_host.lower().strip("[]"):
                return True, f"Target host '{host}' matches explicitly allowed host '{allowed_host}'."

        # 7. Check Allowed IP in Allowed CIDRs
        if target_ip:
            for allowed_net in self._parsed_allowed_cidrs:
                if target_ip in allowed_net:
                    return True, f"Target IP '{host}' is in allowed CIDR '{allowed_net}'."

        # 8. Check Allowed Domains and Wildcards
        for allowed_domain in self.manifest.allowed_domains:
            norm_dom = allowed_domain.lower()
            if host == norm_dom:
                return True, f"Target host '{host}' matches allowed domain '{norm_dom}'."

        for wildcard in self.manifest.allowed_wildcards:
            pattern = wildcard.lower()
            root_domain = pattern.lstrip("*.")
            # Matches subdomains (e.g. api.example.com matches *.example.com)
            # and root domain (e.g. example.com matches *.example.com)
            if fnmatch.fnmatch(host, pattern) or host == root_domain:
                return True, f"Target host '{host}' matches allowed wildcard '{wildcard}'."

        return False, f"Target host '{host}' is outside all authorized domains, CIDRs, and host manifests."

    def validate_or_raise(self, target: str) -> None:
        """Enforces scope; raises ScopeViolationError if unauthorized."""
        allowed, reason = self.is_allowed(target)
        if not allowed:
            raise ScopeViolationError(target, reason)
