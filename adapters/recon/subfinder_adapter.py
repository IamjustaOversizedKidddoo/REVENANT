"""
REVENANT — ProjectDiscovery Subfinder Tool Adapter
Passive subdomain discovery and attack-surface mapping.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple
from adapters.base import BaseAdapter
from control_plane.schemas.models import Finding, HostAsset


class SubfinderAdapter(BaseAdapter):
    """Adapter for ProjectDiscovery Subfinder."""

    def __init__(self, binary_override: str | None = None):
        super().__init__(
            name="subfinder",
            category="recon",
            version="2.6.0+",
            binary_override=binary_override,
        )

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        # Extract host to pass clean domain to -d
        from control_plane.schemas.scope import ScopeEngine
        domain = ScopeEngine.extract_host(target)

        cmd = [
            self.binary_path or "subfinder",
            "-d", domain,
            "-silent",
            "-oJ",  # JSON lines output
        ]
        if params.get("all_sources", False):
            cmd.append("-all")
        if params.get("timeout"):
            cmd.extend(["-timeout", str(params["timeout"])])
        return cmd

    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        discovered_assets: List[HostAsset] = []
        seen_hosts = set()

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            subdomain = None
            try:
                data = json.loads(line)
                subdomain = data.get("host")
            except json.JSONDecodeError:
                # Subfinder standard output fallback if not JSON
                if "." in line and " " not in line:
                    subdomain = line

            if subdomain and subdomain not in seen_hosts:
                seen_hosts.add(subdomain)
                discovered_assets.append(
                    HostAsset(
                        hostname=subdomain,
                        metadata={"source": "subfinder", "root_domain": target},
                    )
                )

        return [], discovered_assets
