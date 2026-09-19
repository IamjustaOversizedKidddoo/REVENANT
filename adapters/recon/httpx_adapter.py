"""
REVENANT — ProjectDiscovery httpx Tool Adapter
Performs fast HTTP probing, technology detection, title extraction, and endpoint mapping.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple
from control_plane.schemas.models import EndpointInfo, Finding, HostAsset, PortInfo, Severity
from adapters.base import BaseAdapter


class HTTPXAdapter(BaseAdapter):
    """Adapter for ProjectDiscovery httpx."""

    def __init__(self, binary_override: str | None = None):
        super().__init__(
            name="httpx",
            category="recon",
            version="1.6.0+",
            binary_override=binary_override,
        )

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [
            self.binary_path or "httpx",
            "-u", target,
            "-silent",
            "-json",
            "-tech-detect",
            "-status-code",
            "-title",
            "-content-type",
            "-web-server",
        ]
        if params.get("follow_redirects", True):
            cmd.append("-follow-redirects")
        if params.get("timeout"):
            cmd.extend(["-timeout", str(params["timeout"])])
        if params.get("rate_limit"):
            cmd.extend(["-rate-limit", str(params["rate_limit"])])
        return cmd

    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        findings: List[Finding] = []
        endpoints: List[EndpointInfo] = []
        host_ip: str | None = None
        hostname: str | None = None
        ports: List[PortInfo] = []

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

                # Extract endpoint metadata
            url = data.get("url") or target
            status_code = data.get("status_code")
            title = data.get("title")
            tech_stack = data.get("tech") or []
            content_type = data.get("content_type")
            web_server = data.get("webserver")
            if web_server and web_server not in tech_stack:
                tech_stack.append(web_server)

            endpoints.append(
                EndpointInfo(
                    url=url,
                    method="GET",
                    status_code=status_code,
                    content_type=content_type,
                    title=title,
                    tech_stack=tech_stack,
                )
            )

            # Extract host / port
            host_ip = host_ip or data.get("host")
            if "port" in data:
                try:
                    port_num = int(data["port"])
                    ports.append(
                        PortInfo(
                            port=port_num,
                            protocol="tcp",
                            state="open",
                            service="http" if "http" in url else "https",
                        )
                    )
                except (ValueError, TypeError):
                    pass

            # Informational finding if technology stack is fingerprinted
            if tech_stack:
                findings.append(
                    Finding(
                        title=f"Technologies Detected on {url}",
                        description=f"HTTP probing fingerprinted technologies: {', '.join(tech_stack)}",
                        severity=Severity.INFO,
                        target=target,
                        tool=self.name,
                        endpoint=url,
                        evidence=f"Status: {status_code}, Title: '{title}', Tech: {tech_stack}",
                        raw_data=data,
                    )
                )

        discovered_assets: List[HostAsset] = []
        if endpoints or ports or host_ip:
            discovered_assets.append(
                HostAsset(
                    ip=host_ip,
                    hostname=target,
                    ports=ports,
                    endpoints=endpoints,
                )
            )

        return findings, discovered_assets
