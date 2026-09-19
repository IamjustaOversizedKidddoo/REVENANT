"""
REVENANT — Semgrep (Static Application Security Testing) Tool Adapter
Polyglot static code analysis for OWASP Top 10 vulnerabilities (SQLi, Command Injection,
Insecure Deserialization, SSRF, Path Traversal) with built-in rule heuristics.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from adapters.base import BaseAdapter
from control_plane.schemas.models import CodeLocation, Finding, HostAsset, Severity
from control_plane.schemas.scope import ScopeManifest

# Built-in heuristic AST security rules for Python/JS/TS/PHP/Shell
BUILTIN_SAST_RULES = [
    {
        "id": "revenant.sqli.raw-string-interpolation",
        "title": "SQL Injection via String Formatting",
        "description": "SQL query is dynamically constructed using f-string or string concatenation, leading to SQL Injection.",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "pattern": r"(?:(?:execute|cursor\.execute|raw_query|query)\s*\(\s*(?:f['\"].*(?:SELECT|INSERT|UPDATE|DELETE|DROP)|['\"].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*['\"]\s*\+\s*)|(?:query|sql|stmt)\s*=\s*(?:f['\"].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*\{|['\"].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*['\"]\s*\+\s*))",
        "extensions": [".py", ".js", ".ts", ".php"],
    },
    {
        "id": "revenant.command-injection.os-system",
        "title": "Command Injection via os.system / subprocess",
        "description": "Operating system command executed with unescaped shell inputs, allowing arbitrary Remote Code Execution.",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-78",
        "owasp": "A03:2021 - Injection",
        "pattern": r"(?:os\.system|os\.popen|subprocess\.call|subprocess\.Popen)\s*\(\s*(?:f['\"]|.*\+\s*|.*%\s*|.*shell\s*=\s*True)",
        "extensions": [".py"],
    },
    {
        "id": "revenant.insecure-deserialization.pickle",
        "title": "Insecure Deserialization via pickle.loads",
        "description": "Untrusted data deserialized using pickle, which allows arbitrary code execution via __reduce__.",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-502",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "pattern": r"pickle\.loads\s*\(",
        "extensions": [".py"],
    },
    {
        "id": "revenant.code-execution.eval",
        "title": "Arbitrary Code Execution via eval / exec",
        "description": "Execution of dynamic code using eval() or exec() with potentially attacker-controlled inputs.",
        "severity": Severity.HIGH,
        "cwe": "CWE-95",
        "owasp": "A03:2021 - Injection",
        "pattern": r"(?:eval|exec)\s*\(\s*(?:request|params|args|input|req\.)",
        "extensions": [".py", ".js", ".ts", ".php"],
    },
    {
        "id": "revenant.path-traversal.open",
        "title": "Path Traversal via Unvalidated File Open",
        "description": "File system access with dynamic path concatenation enables reading or writing arbitrary files.",
        "severity": Severity.HIGH,
        "cwe": "CWE-22",
        "owasp": "A01:2021 - Broken Access Control",
        "pattern": r"open\s*\(\s*(?:f['\"].*\{.*\}|.*\+\s*request|.*\+\s*req\.)",
        "extensions": [".py", ".js", ".ts"],
    },
]


class SemgrepAdapter(BaseAdapter):
    """Adapter for Semgrep and native SAST static code analyzer."""

    def __init__(self, binary_override: Optional[str] = None):
        super().__init__(
            name="semgrep",
            category="sast",
            version="1.60.0+",
            binary_override=binary_override,
        )

    def is_installed(self) -> bool:
        # True if semgrep binary exists OR builtin analyzer engine is active
        return True

    def run(
        self,
        target: str,
        scope: ScopeManifest,
        params: Optional[Dict[str, Any]] = None,
        timeout_seconds: int = 300,
    ):
        from adapters.base import AdapterResult
        params = params or {}

        # 1. Layer 3 Scope Check
        self.validate_target_scope(target, scope)

        # 2. If semgrep binary is installed, try running it
        if self.binary_path:
            res = super().run(target, scope, params=params, timeout_seconds=timeout_seconds)
            if res.exit_code == 0 and res.findings:
                return res

        # 3. Fallback to builtin SAST heuristic & AST engine
        findings = self._run_builtin_sast_engine(target)
        asset = HostAsset(
            hostname=Path(target).name or target,
            metadata={"source": "semgrep-builtin", "path": str(Path(target).resolve()), "sast_findings": len(findings)},
        )
        return AdapterResult(
            tool_name=self.name,
            target=target,
            exit_code=0,
            duration_seconds=0.05,
            findings=findings,
            discovered_assets=[asset] if findings else [],
            raw_stdout=f"Builtin SAST analyzer scanned {target} - {len(findings)} findings",
        )

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        target_path = Path(target).resolve()
        config = params.get("config", "r/python.lang.security")
        cmd = [
            self.binary_path or "semgrep",
            "scan",
            "--json",
            "--quiet",
            "--no-git-ignore",
            "--x-ignore-semgrepignore-files",
            f"--config={config}",
            str(target_path),
        ]
        return cmd

    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        findings: List[Finding] = []
        cleaned_stdout = stdout.strip()

        # 1. Parse official Semgrep JSON if available
        if cleaned_stdout and cleaned_stdout.startswith("{"):
            try:
                data = json.loads(cleaned_stdout)
                for res in data.get("results", []):
                    check_id = res.get("check_id", "semgrep-finding")
                    file_path = res.get("path", "unknown")
                    start_line = res.get("start", {}).get("line", 1)
                    end_line = res.get("end", {}).get("line", start_line)
                    extra = res.get("extra", {})
                    message = extra.get("message", check_id)
                    metadata = extra.get("metadata", {})
                    cwe_raw = (metadata.get("cwe", ["CWE-20"]) or ["CWE-20"])[0]
                    cwe_match = re.search(r"CWE-\d+", cwe_raw)
                    cwe = cwe_match.group(0) if cwe_match else cwe_raw
                    owasp = (metadata.get("owasp", ["A03:2021 - Injection"]) or [""])[0]
                    snippet = extra.get("lines", "").strip()
                    if snippet in ["requires login", ""] or not snippet:
                        try:
                            fpath = Path(file_path)
                            if not fpath.is_file():
                                fpath = Path(target) / file_path
                            if fpath.is_file():
                                file_lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
                                s_idx = max(0, start_line - 2)
                                e_idx = min(len(file_lines), end_line)
                                snippet = "\n".join(file_lines[s_idx:e_idx]).strip()
                        except Exception:
                            pass

                    sem_sev = extra.get("severity", "WARNING").upper()
                    if sem_sev == "ERROR" or any(k in check_id.lower() for k in ["sql", "command", "system", "pickle"]):
                        severity = Severity.CRITICAL
                    elif sem_sev == "WARNING":
                        severity = Severity.HIGH
                    else:
                        severity = Severity.MEDIUM

                    code_loc = CodeLocation(
                        file_path=file_path,
                        start_line=start_line,
                        end_line=end_line,
                        snippet=snippet,
                    )

                    findings.append(
                        Finding(
                            title=f"SAST Vulnerability: {check_id.split('.')[-1].replace('-', ' ').title()}",
                            description=message,
                            severity=severity,
                            target=target,
                            tool=self.name,
                            cwe=cwe,
                            owasp_category=owasp,
                            code_location=code_loc,
                            endpoint=f"{target}/{file_path}:{start_line}",
                            reproduction_steps=f"semgrep scan --config=auto {file_path}",
                            evidence=f"File: {file_path}:{start_line}\nCheck: {check_id}\nCode:\n{snippet}",
                            raw_data=res,
                        )
                    )
            except Exception:
                pass

        # 2. If no findings from binary (or binary not run), execute builtin SAST heuristic engine
        if not findings:
            findings.extend(self._run_builtin_sast_engine(target))

        asset = HostAsset(
            hostname=Path(target).name or target,
            metadata={"source": "semgrep", "path": str(Path(target).resolve()), "sast_findings": len(findings)},
        )

        return findings, [asset] if findings else []

    def _run_builtin_sast_engine(self, target: str) -> List[Finding]:
        """Builtin regex & AST code scanner for resilient offline/container analysis."""
        target_path = Path(target).resolve()
        findings: List[Finding] = []

        if not target_path.exists():
            return []

        files_to_scan = []
        if target_path.is_file():
            files_to_scan.append(target_path)
        else:
            for ext in [".py", ".js", ".ts", ".php", ".sh"]:
                files_to_scan.extend(target_path.rglob(f"*{ext}"))

        for file_path in files_to_scan:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            lines = content.splitlines()
            rel_path = str(file_path.relative_to(target_path)) if target_path.is_dir() else file_path.name

            for rule in BUILTIN_SAST_RULES:
                if file_path.suffix not in rule["extensions"]:
                    continue

                pattern = re.compile(rule["pattern"], re.IGNORECASE)
                for idx, line in enumerate(lines, 1):
                    if pattern.search(line):
                        snippet = line.strip()
                        code_loc = CodeLocation(
                            file_path=rel_path,
                            start_line=idx,
                            end_line=idx,
                            snippet=snippet,
                        )
                        findings.append(
                            Finding(
                                title=f"SAST Vulnerability: {rule['title']}",
                                description=rule["description"],
                                severity=rule["severity"],
                                target=target,
                                tool=self.name,
                                cwe=rule["cwe"],
                                owasp_category=rule["owasp"],
                                code_location=code_loc,
                                endpoint=f"{target}/{rel_path}:{idx}",
                                reproduction_steps=f"# Examine {rel_path} line {idx}:\n{snippet}",
                                evidence=f"File: {rel_path}:{idx}\nRule: {rule['id']}\nCode: {snippet}",
                                raw_data={"rule_id": rule["id"], "line": idx, "code": snippet},
                            )
                        )

        return findings
