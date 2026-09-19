"""
REVENANT — Nmap Tool Adapter
Network discovery, port scanning, and service version fingerprinting.
Parses Nmap XML output (-oX -) into structured PortInfo and HostAsset records.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Tuple
from adapters.base import BaseAdapter
from control_plane.schemas.models import Finding, HostAsset, PortInfo, Severity
from control_plane.schemas.scope import ScopeEngine


class NmapAdapter(BaseAdapter):
    """Adapter for Nmap network port and service scanner."""

    def __init__(
        self,
        binary_override: str | None = None,
        use_wsl: bool = False,
        wsl_distro: str = "Ubuntu",
    ):
        super().__init__(
            name="nmap",
            category="network",
            version="7.90+",
            binary_override=binary_override,
            use_wsl=use_wsl,
            wsl_distro=wsl_distro,
        )

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        host = ScopeEngine.extract_host(target)
        cmd = [
            self.binary_path or "nmap",
            "-sT",
            "-sV",
            "-T4",
            "-oX", "-",
        ]
        if params.get("ports"):
            cmd.extend(["-p", str(params["ports"])])
        elif params.get("fast_mode", True):
            cmd.append("-F")

        cmd.append(host)
        return cmd

    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        findings: List[Finding] = []
        discovered_assets: List[HostAsset] = []

        cleaned_stdout = stdout.strip()
        if not cleaned_stdout or not cleaned_stdout.startswith("<?xml") and "<nmaprun" not in cleaned_stdout:
            return [], []

        try:
            root = ET.fromstring(cleaned_stdout)
        except ET.ParseError:
            return [], []

        for host_elem in root.findall("host"):
            # Check host state
            status = host_elem.find("status")
            if status is not None and status.get("state") != "up":
                continue

            # Extract IP / Hostname
            host_ip = None
            for addr in host_elem.findall("address"):
                if addr.get("addrtype") in ["ipv4", "ipv6"]:
                    host_ip = addr.get("addr")
                    break

            hostnames = []
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                for hn in hostnames_elem.findall("hostname"):
                    name = hn.get("name")
                    if name:
                        hostnames.append(name)

            hostname = hostnames[0] if hostnames else ScopeEngine.extract_host(target)

            # Extract Ports
            ports_elem = host_elem.find("ports")
            discovered_ports: List[PortInfo] = []

            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    state_elem = port_elem.find("state")
                    if state_elem is None or state_elem.get("state") != "open":
                        continue

                    try:
                        port_num = int(port_elem.get("portid", 0))
                    except ValueError:
                        continue

                    protocol = port_elem.get("protocol", "tcp")

                    service_name = None
                    version_info = None
                    service_elem = port_elem.find("service")
                    if service_elem is not None:
                        service_name = service_elem.get("name")
                        product = service_elem.get("product")
                        version = service_elem.get("version")
                        extrainfo = service_elem.get("extrainfo")
                        parts = [p for p in [product, version, extrainfo] if p]
                        if parts:
                            version_info = " ".join(parts)

                    discovered_ports.append(
                        PortInfo(
                            port=port_num,
                            protocol=protocol,
                            state="open",
                            service=service_name,
                            version=version_info,
                        )
                    )

                    # Informational finding for exposed service
                    service_desc = f"{service_name or 'unknown service'} {version_info or ''}".strip()
                    findings.append(
                        Finding(
                            title=f"Open Port {port_num}/{protocol} ({service_name or 'unknown'})",
                            description=f"Nmap discovered open port {port_num}/{protocol} running {service_desc}.",
                            severity=Severity.INFO,
                            target=target,
                            tool=self.name,
                            evidence=f"Port: {port_num}, Protocol: {protocol}, Service: {service_desc}",
                        )
                    )

            if discovered_ports or host_ip:
                discovered_assets.append(
                    HostAsset(
                        ip=host_ip,
                        hostname=hostname,
                        ports=discovered_ports,
                    )
                )

        return findings, discovered_assets
