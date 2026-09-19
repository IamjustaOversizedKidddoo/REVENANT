"""
REVENANT — AFL++ & libFuzzer Crash Triage Adapter
Analyzes binary fuzzing campaigns, crash dumps, and sanitizer reports:
- Parses AddressSanitizer (ASan) & UndefinedBehaviorSanitizer (UBSan) traces
- Identifies root cause: Heap Buffer Overflow (CWE-122), Use-After-Free (CWE-416),
  Stack Overflow (CWE-121), NULL Pointer Dereference (CWE-476)
- Maps actionable crash findings to MITRE ATT&CK T1190 / T1499.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from adapters.base import BaseAdapter
from control_plane.schemas.models import Finding, HostAsset, Severity

logger = logging.getLogger("revenant.adapters.fuzzing")


class AFLFuzzingAdapter(BaseAdapter):
    """Adapter for AFL++ and Sanitizer crash triage."""

    def __init__(
        self,
        binary_override: Optional[str] = None,
        use_wsl: bool = False,
    ):
        super().__init__(
            name="afl_fuzzer",
            category="fuzzing",
            version="4.0+",
            binary_override=binary_override,
            use_wsl=use_wsl,
        )

    def is_installed(self) -> bool:
        return True

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        # For offline log triage
        return ["cat", target]

    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        findings: List[Finding] = []
        assets: List[HostAsset] = []

        combined = (stdout + "\n" + stderr).strip()
        if not combined:
            return findings, assets

        file_name = os.path.basename(target)

        # 1. AddressSanitizer Crash Pattern Matching
        # e.g.: ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
        asan_match = re.search(r"ERROR:\s*AddressSanitizer:\s*([a-zA-Z0-9_-]+)\s+on\s+address\s+(0x[0-9a-fA-F]+)", combined)
        if asan_match:
            crash_type = asan_match.group(1).lower()
            fault_addr = asan_match.group(2)

            # Stack frame #0
            frame_match = re.search(r"#0\s+(0x[0-9a-fA-F]+)\s+in\s+([a-zA-Z0-9_:]+)\s+([^\n\r]+)", combined)
            offending_func = frame_match.group(2) if frame_match else "unknown_function"
            offending_loc = frame_match.group(3) if frame_match else "unknown_location"

            if "heap-buffer-overflow" in crash_type:
                title = f"Heap Buffer Overflow in {offending_func} ({os.path.basename(offending_loc)})"
                severity = Severity.CRITICAL
                cwe = 122
                mitre_ids = ["T1190"]
            elif "use-after-free" in crash_type or "heap-use-after-free" in crash_type:
                title = f"Use-After-Free Vulnerability in {offending_func} ({os.path.basename(offending_loc)})"
                severity = Severity.CRITICAL
                cwe = 416
                mitre_ids = ["T1190"]
            elif "stack-buffer-overflow" in crash_type:
                title = f"Stack Buffer Overflow in {offending_func} ({os.path.basename(offending_loc)})"
                severity = Severity.CRITICAL
                cwe = 121
                mitre_ids = ["T1190"]
            elif "null-dereference" in crash_type:
                title = f"Null Pointer Dereference Crash in {offending_func}"
                severity = Severity.MEDIUM
                cwe = 476
                mitre_ids = ["T1499"]
            else:
                title = f"Memory Sanitizer Crash ({crash_type}) in {offending_func}"
                severity = Severity.HIGH
                cwe = 119
                mitre_ids = ["T1190"]

            desc = (
                f"Coverage-guided binary fuzzing triggered reproducible AddressSanitizer crash: '{crash_type}' "
                f"at fault address {fault_addr}. Offending stack frame: {offending_func}() at {offending_loc}."
            )

            findings.append(
                Finding(
                    title=title,
                    description=desc,
                    severity=severity,
                    target=f"{target}:{offending_func}",
                    tool=self.name,
                    cwe=f"CWE-{cwe}",
                    mitre_attack_ids=mitre_ids,
                    remediation=f"Patch memory bounds checks in {offending_loc} and recompile with ASan verification.",
                    evidence=combined[:1000],
                )
            )

        assets.append(
            HostAsset(
                ip="127.0.0.1",
                hostname=f"fuzz-target:{file_name}",
                metadata={
                    "artifact_type": "fuzz_crash_report",
                    "path": target,
                    "finding_count": len(findings),
                },
            )
        )

        return findings, assets
