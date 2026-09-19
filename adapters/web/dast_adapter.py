"""
REVENANT — DAST (Dynamic Application Security Testing) Adapter
Active HTTP vulnerability fuzzer targeting discovered endpoints, query parameters,
and HTML form inputs. Verifies live exploitable vulnerabilities:
- Reflected Cross-Site Scripting (CWE-79 / OWASP A03)
- Open Redirect (CWE-601 / OWASP A01)
- Path Traversal & LFI (CWE-22 / OWASP A01)
- SQL Injection via error-based reflection (CWE-89 / OWASP A03)
"""

from __future__ import annotations

import logging
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import requests

from adapters.base import AdapterResult, BaseAdapter
from control_plane.schemas.models import EndpointInfo, Finding, HostAsset, Severity
from control_plane.schemas.scope import ScopeManifest

logger = logging.getLogger("revenant.adapters.dast")

SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query(): query failed",
    "sqlite3.operationalerror",
    "syntax error at or near",
    "ora-00933: sql command not properly ended",
    "microsoft ole db provider for sql server",
]

COMMON_REDIRECT_PARAMS = {
    "next", "redirect", "url", "return", "return_to", "r", "dest", "destination", "goto", "out"
}

COMMON_TRAVERSAL_PARAMS = {
    "file", "path", "doc", "document", "page", "filename", "read", "view", "include", "dir"
}


class DastAdapter(BaseAdapter):
    """Active DAST injection tester for web endpoints, query strings, and forms."""

    def __init__(self, binary_override: Optional[str] = None):
        super().__init__(
            name="dast-fuzzer",
            category="dast",
            version="1.0.0",
            binary_override=binary_override,
        )

    def is_installed(self) -> bool:
        return True

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        # DAST adapter is an active Python protocol fuzzer
        return ["python", "-m", "revenant.adapters.dast", target]

    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        return [], []

    def run(
        self,
        target: str,
        scope: ScopeManifest,
        params: Optional[Dict[str, Any]] = None,
        timeout_seconds: int = 300,
    ) -> AdapterResult:
        params = params or {}

        # 1. Layer 3 Scope Enforcement
        self.validate_target_scope(target, scope)

        endpoints: List[EndpointInfo] = params.get("endpoints", [])
        findings: List[Finding] = []

        # If no explicit endpoints passed, probe the target URL itself
        if not endpoints:
            parsed = urllib.parse.urlparse(target)
            p_names = list(urllib.parse.parse_qs(parsed.query).keys())
            endpoints = [EndpointInfo(url=target, method="GET", parameters=p_names)]

        for ep in endpoints:
            findings.extend(self._fuzz_endpoint(ep, target, scope))

        asset = HostAsset(
            hostname=urllib.parse.urlparse(target).hostname or target,
            metadata={"source": "dast-fuzzer", "dast_findings": len(findings)},
        )

        return AdapterResult(
            tool_name=self.name,
            target=target,
            exit_code=0,
            duration_seconds=0.1,
            findings=findings,
            discovered_assets=[asset] if findings else [],
            raw_stdout=f"DAST fuzzer completed testing on {len(endpoints)} endpoints — {len(findings)} confirmed flaws",
        )

    def _fuzz_endpoint(
        self,
        endpoint: EndpointInfo,
        target: str,
        scope: ScopeManifest,
    ) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urllib.parse.urlparse(endpoint.url)
        query_dict = urllib.parse.parse_qs(parsed.query)

        # Collect parameter names from URL and from endpoint.parameters
        all_param_names = set(query_dict.keys()).union(set(endpoint.parameters))

        # 1. Probe Form inputs if present
        for form in endpoint.forms:
            action = form.get("action", endpoint.url)
            method = form.get("method", "POST").upper()
            form_inputs = [i["name"] for i in form.get("inputs", []) if i.get("name")]
            for param_name in form_inputs:
                findings.extend(self._test_xss(action, param_name, method=method, is_form=True))
                findings.extend(self._test_sqli(action, param_name, method=method, is_form=True))

        # 2. Probe Query parameters
        for param_name in all_param_names:
            # A. Test Reflected XSS
            findings.extend(self._test_xss(endpoint.url, param_name, method="GET"))

            # B. Test Open Redirect
            if param_name.lower() in COMMON_REDIRECT_PARAMS or "url" in param_name.lower() or "redirect" in param_name.lower():
                findings.extend(self._test_open_redirect(endpoint.url, param_name))

            # C. Test Path Traversal
            if param_name.lower() in COMMON_TRAVERSAL_PARAMS or "file" in param_name.lower() or "path" in param_name.lower():
                findings.extend(self._test_path_traversal(endpoint.url, param_name))

            # D. Test SQL Injection Error Reflection
            findings.extend(self._test_sqli(endpoint.url, param_name, method="GET"))

        return findings

    def _test_xss(
        self,
        base_url: str,
        param_name: str,
        method: str = "GET",
        is_form: bool = False,
    ) -> List[Finding]:
        """Probes for Reflected Cross-Site Scripting (XSS)."""
        canary = f"rev<script>alert('xss_{param_name}')</script>rev"
        try:
            if method == "GET":
                parsed = urllib.parse.urlparse(base_url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[param_name] = [canary]
                new_query = urllib.parse.urlencode(qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                req_proof = f"GET {test_url} HTTP/1.1\nUser-Agent: REVENANT-DAST"
                resp = requests.get(test_url, timeout=4)
            else:
                data = {param_name: canary}
                req_proof = f"POST {base_url} HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\n{param_name}={canary}"
                resp = requests.post(base_url, data=data, timeout=4)

            # Verification: canary must reflect unescaped inside HTML response
            if canary in resp.text:
                return [
                    Finding(
                        title=f"Reflected Cross-Site Scripting (XSS) in Parameter '{param_name}'",
                        description=f"Active DAST injection identified unescaped reflection of script payload in parameter '{param_name}' on endpoint '{base_url}'.",
                        severity=Severity.HIGH,
                        target=base_url,
                        tool=self.name,
                        cwe="CWE-79",
                        owasp_category="A03:2021 - Injection",
                        cvss_score=7.1,
                        endpoint=f"{base_url}?{param_name}=",
                        reproduction_steps=f"curl -s \"{base_url}?{param_name}={urllib.parse.quote(canary)}\"",
                        evidence=f"Reflected payload detected in HTTP response body:\n{canary}",
                        request_proof=req_proof,
                        response_proof=f"HTTP/1.1 {resp.status_code}\nContent-Type: {resp.headers.get('Content-Type')}\n\n...{canary}...",
                        verified=True,
                        verified_valid=True,
                    )
                ]
        except Exception:
            pass
        return []

    def _test_open_redirect(self, base_url: str, param_name: str) -> List[Finding]:
        """Probes for Open Redirection."""
        canary_redirect = "https://revenant.security.test"
        try:
            parsed = urllib.parse.urlparse(base_url)
            qs = urllib.parse.parse_qs(parsed.query)
            qs[param_name] = [canary_redirect]
            new_query = urllib.parse.urlencode(qs, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

            req_proof = f"GET {test_url} HTTP/1.1\nUser-Agent: REVENANT-DAST"
            resp = requests.get(test_url, allow_redirects=False, timeout=4)

            location = resp.headers.get("Location", "")
            if resp.status_code in [301, 302, 303, 307, 308] and canary_redirect in location:
                return [
                    Finding(
                        title=f"Open Redirection in Parameter '{param_name}'",
                        description=f"Active DAST probe confirmed unvalidated redirect to external arbitrary domain via parameter '{param_name}'.",
                        severity=Severity.MEDIUM,
                        target=base_url,
                        tool=self.name,
                        cwe="CWE-601",
                        owasp_category="A01:2021 - Broken Access Control",
                        cvss_score=6.1,
                        endpoint=f"{base_url}?{param_name}=",
                        reproduction_steps=f"curl -i -s \"{test_url}\"",
                        evidence=f"HTTP {resp.status_code} Redirect with Location: {location}",
                        request_proof=req_proof,
                        response_proof=f"HTTP/1.1 {resp.status_code} Found\nLocation: {location}",
                        verified=True,
                        verified_valid=True,
                    )
                ]
        except Exception:
            pass
        return []

    def _test_path_traversal(self, base_url: str, param_name: str) -> List[Finding]:
        """Probes for Path Traversal / Local File Inclusion."""
        traversal_payloads = [
            ("../../../../etc/passwd", "root:"),
            ("..\\..\\..\\windows\\win.ini", "[extensions]"),
            ("..\\..\\..\\..\\windows\\win.ini", "[fonts]"),
        ]

        for payload, marker in traversal_payloads:
            try:
                parsed = urllib.parse.urlparse(base_url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[param_name] = [payload]
                new_query = urllib.parse.urlencode(qs, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

                req_proof = f"GET {test_url} HTTP/1.1\nUser-Agent: REVENANT-DAST"
                resp = requests.get(test_url, timeout=4)

                if marker.lower() in resp.text.lower():
                    return [
                        Finding(
                            title=f"Path Traversal in Parameter '{param_name}'",
                            description=f"Active DAST probe read arbitrary system files via directory traversal in parameter '{param_name}'.",
                            severity=Severity.CRITICAL,
                            target=base_url,
                            tool=self.name,
                            cwe="CWE-22",
                            owasp_category="A01:2021 - Broken Access Control",
                            cvss_score=8.6,
                            endpoint=f"{base_url}?{param_name}=",
                            reproduction_steps=f"curl -s \"{test_url}\"",
                            evidence=f"System file signature '{marker}' detected in response body.",
                            request_proof=req_proof,
                            response_proof=f"HTTP/1.1 {resp.status_code}\n\n{resp.text[:200]}...",
                            verified=True,
                            verified_valid=True,
                        )
                    ]
            except Exception:
                continue
        return []

    def _test_sqli(
        self,
        base_url: str,
        param_name: str,
        method: str = "GET",
        is_form: bool = False,
    ) -> List[Finding]:
        """Probes for SQL Injection error reflections."""
        sqli_probes = ["' OR '1'='1", "''", "') OR ('1'='1"]

        for probe in sqli_probes:
            try:
                if method == "GET":
                    parsed = urllib.parse.urlparse(base_url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[param_name] = [probe]
                    new_query = urllib.parse.urlencode(qs, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                    req_proof = f"GET {test_url} HTTP/1.1"
                    resp = requests.get(test_url, timeout=4)
                else:
                    data = {param_name: probe}
                    req_proof = f"POST {base_url} HTTP/1.1\n\n{param_name}={probe}"
                    resp = requests.post(base_url, data=data, timeout=4)

                resp_lower = resp.text.lower()
                for err in SQL_ERROR_PATTERNS:
                    if err in resp_lower:
                        return [
                            Finding(
                                title=f"Error-Based SQL Injection in Parameter '{param_name}'",
                                description=f"Active DAST probe provoked database error message '{err}' using SQL quote injection on parameter '{param_name}'.",
                                severity=Severity.CRITICAL,
                                target=base_url,
                                tool=self.name,
                                cwe="CWE-89",
                                owasp_category="A03:2021 - Injection",
                                cvss_score=9.3,
                                endpoint=f"{base_url}?{param_name}=",
                                reproduction_steps=f"curl -s \"{base_url}?{param_name}={urllib.parse.quote(probe)}\"",
                                evidence=f"Database syntax error detected: '{err}'",
                                request_proof=req_proof,
                                response_proof=f"HTTP/1.1 {resp.status_code}\n\n{resp.text[:250]}...",
                                verified=True,
                                verified_valid=True,
                            )
                        ]
            except Exception:
                continue
        return []
