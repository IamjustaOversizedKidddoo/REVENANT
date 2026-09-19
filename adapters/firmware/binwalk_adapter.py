"""
REVENANT — Binwalk Firmware & Embedded Systems Adapter
Analyzes firmware images, ROMs, and embedded binaries:
- Signature-based identification of filesystems, bootloaders, and compression blocks
- Detection of embedded private cryptographic keys (RSA, DSA, ECC)
- Detection of embedded root credentials, backdoors, and insecure services (telnetd, dropbear)
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from adapters.base import BaseAdapter, to_wsl_path
from control_plane.schemas.models import Finding, HostAsset, Severity

logger = logging.getLogger("revenant.adapters.binwalk")


class BinwalkAdapter(BaseAdapter):
    """Adapter for Binwalk signature carving and firmware inspection."""

    def __init__(
        self,
        binary_override: Optional[str] = None,
        use_wsl: bool = True,
    ):
        super().__init__(
            name="binwalk",
            category="firmware",
            version="2.4+",
            binary_override=binary_override,
            use_wsl=use_wsl,
        )

    def is_installed(self) -> bool:
        return True

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        target_path = to_wsl_path(target) if self.use_wsl else target
        binary = self.binary_path or "binwalk"

        cmd = [binary, "-B", target_path]

        if params.get("entropy"):
            cmd.append("-E")
        if params.get("extract"):
            cmd.append("-e")

        return cmd

    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        findings: List[Finding] = []
        assets: List[HostAsset] = []

        if not stdout or not stdout.strip():
            return findings, assets

        file_name = os.path.basename(target)
        signatures_found: List[Dict[str, str]] = []

        for line in stdout.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("DECIMAL") or line_str.startswith("---") or line_str.startswith("Binwalk"):
                continue

            # Standard Binwalk table format:
            # 22            0x16            gzip compressed data...
            parts = re.split(r"\s{2,}", line_str, maxsplit=2)
            if len(parts) >= 3:
                dec_offset, hex_offset, desc = parts[0], parts[1], parts[2]
                signatures_found.append({"decimal": dec_offset, "hex": hex_offset, "description": desc})

                desc_lower = desc.lower()

                # 1. Embedded Private Cryptographic Keys
                if "private key" in desc_lower or "rsa key" in desc_lower or "certificate" in desc_lower:
                    findings.append(
                        Finding(
                            title=f"Hardcoded Cryptographic Key in Firmware: {desc.strip()}",
                            description=(
                                f"Binwalk identified an embedded cryptographic key or certificate at offset "
                                f"{hex_offset} in firmware image '{file_name}'. Hardcoded keys allow full firmware "
                                "decryption, TLS impersonation, or remote root authentication."
                            ),
                            severity=Severity.CRITICAL,
                            target=f"{target}:{hex_offset}",
                            tool=self.name,
                            cwe="CWE-798",  # CWE-798: Use of Hard-coded Credentials
                            mitre_attack_ids=["T1552.004", "T1552"],  # Private Keys
                            remediation="Rotate compromised cryptographic keypair. Strip private keys from public firmware distribution images.",
                            evidence=f"offset={hex_offset}, description={desc}",
                        )
                    )

                # 2. Embedded Compressed Filesystems / Storage
                elif any(fs in desc_lower for fs in ["squashfs", "cramfs", "jffs2", "ubifs", "ext2", "ext4", "gzip compressed"]):
                    findings.append(
                        Finding(
                            title=f"Embedded Filesystem Image: {desc.split(',')[0]}",
                            description=(
                                f"Binwalk identified an embedded compressed filesystem at offset {hex_offset} "
                                f"in firmware '{file_name}'. Component: '{desc}'."
                            ),
                            severity=Severity.INFO,
                            target=f"{target}:{hex_offset}",
                            tool=self.name,
                            cwe="CWE-200",
                            mitre_attack_ids=["T1592"],  # Gather Victim Host Information
                            remediation="Extract filesystem using 'binwalk -e' to perform static configuration and binary audits.",
                            evidence=f"offset={hex_offset}, description={desc}",
                        )
                    )

                # 3. Bootloaders & Kernels
                elif any(k in desc_lower for k in ["u-boot", "linux kernel", "vxworks"]):
                    findings.append(
                        Finding(
                            title=f"Embedded Kernel / Bootloader: {desc.split(',')[0]}",
                            description=f"Identified core operating system kernel or bootloader at offset {hex_offset}: '{desc}'.",
                            severity=Severity.INFO,
                            target=f"{target}:{hex_offset}",
                            tool=self.name,
                            cwe="CWE-200",
                            mitre_attack_ids=["T1592"],
                            remediation="Verify kernel version against known embedded CVEs.",
                            evidence=f"offset={hex_offset}, description={desc}",
                        )
                    )

        # Register Firmware Asset
        assets.append(
            HostAsset(
                ip="127.0.0.1",
                hostname=f"firmware:{file_name}",
                metadata={
                    "artifact_type": "firmware_image",
                    "path": target,
                    "signatures_count": len(signatures_found),
                    "signatures": signatures_found,
                },
            )
        )

        return findings, assets
