"""
REVENANT — Katana Crawler Tool Adapter
Deep recursive web crawling, endpoint discovery, HTML form extraction,
and parameter surface mapping for web applications and APIs.
Dual-mode engine: executes Katana CLI when available with automatic fallback
to high-performance native asynchronous/recursive DOM & link crawler.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.parse
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

from adapters.base import AdapterResult, BaseAdapter
from control_plane.schemas.models import EndpointInfo, Finding, HostAsset, Severity
from control_plane.schemas.scope import ScopeEngine, ScopeManifest

logger = logging.getLogger("revenant.adapters.katana")


class _HTMLFormAndLinkParser(HTMLParser):
    """HTML parser to extract hyperlinks, forms, inputs, and script sources."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        # 1. Extract Links (a, link, iframe)
        if tag in ["a", "link", "iframe"]:
            href = attr_dict.get("href") or attr_dict.get("src")
            if href:
                resolved = urllib.parse.urljoin(self.base_url, href.strip())
                self.links.add(resolved)

        # 2. Extract Script Sources
        elif tag == "script":
            src = attr_dict.get("src")
            if src:
                resolved = urllib.parse.urljoin(self.base_url, src.strip())
                self.links.add(resolved)

        # 3. Extract Forms and Form Inputs
        elif tag == "form":
            action = attr_dict.get("action", "")
            method = attr_dict.get("method", "GET").upper()
            resolved_action = urllib.parse.urljoin(self.base_url, action.strip()) if action else self.base_url
            self._current_form = {
                "action": resolved_action,
                "method": method,
                "inputs": [],
            }

        elif tag in ["input", "textarea", "select"] and self._current_form is not None:
            name = attr_dict.get("name")
            if name:
                self._current_form["inputs"].append({
                    "name": name,
                    "type": attr_dict.get("type", "text"),
                    "value": attr_dict.get("value", ""),
                })

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


class KatanaAdapter(BaseAdapter):
    """Adapter for Katana deep crawler and dynamic endpoint mapping engine."""

    def __init__(self, binary_override: Optional[str] = None, use_wsl: bool = False):
        super().__init__(
            name="katana",
            category="web",
            version="1.7.0",
            binary_override=binary_override,
            use_wsl=use_wsl,
        )

    def is_installed(self) -> bool:
        if self.use_wsl:
            return True
        return self.binary_path is not None

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [
            self.binary_path or "katana",
            "-u", target,
            "-j",                    # JSON-lines output
            "-jc",                   # JavaScript crawling
            "-d", str(params.get("depth", 3)),
            "-ct", f"{params.get('timeout', 10)}s",
            "-silent",
            "-aff",                  # Automatic form-fill simulation
            "-duc",                  # Disable update check
        ]
        if params.get("no_color", True):
            cmd.append("-nc")
        return cmd

    def run(
        self,
        target: str,
        scope: ScopeManifest,
        params: Optional[Dict[str, Any]] = None,
        timeout_seconds: int = 300,
    ) -> AdapterResult:
        params = params or {}

        # 1. Layer 3 Scope Enforcement Gate
        self.validate_target_scope(target, scope)

        # 2. Try official Katana binary (WSL2 Linux or native)
        if self.is_installed():
            try:
                res = super().run(target, scope, params=params, timeout_seconds=timeout_seconds)
                if res.exit_code == 0 and res.discovered_assets:
                    return res
            except Exception as e:
                logger.debug(f"Katana binary invocation fallback: {e}")

        # 3. Fallback to resilient native crawler
        return self._run_builtin_crawler(target, scope, params)

    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        """Parse Katana JSON-lines crawl records into HostAsset and EndpointInfo models."""
        endpoints: List[EndpointInfo] = []
        findings: List[Finding] = []
        parsed_target = urllib.parse.urlparse(target)
        host = parsed_target.hostname or target

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            req_data = data.get("request", {})
            url = req_data.get("endpoint") or data.get("url") or ""
            if not url:
                continue

            method = req_data.get("method") or data.get("method") or "GET"
            resp_data = data.get("response", {})
            status_code = resp_data.get("status_code")
            headers = resp_data.get("headers", {})
            content_type = headers.get("content_type") or headers.get("content-type")

            # Extract URL query parameters
            parsed_url = urllib.parse.urlparse(url)
            query_params = list(urllib.parse.parse_qs(parsed_url.query).keys())

            # Extract forms from JSON record or response body
            forms = data.get("forms") or req_data.get("forms") or []
            body = resp_data.get("body", "")
            if body and "form" in body.lower():
                parser = _HTMLFormAndLinkParser(base_url=url)
                try:
                    parser.feed(body)
                    forms.extend(parser.forms)
                except Exception:
                    pass

            endpoints.append(
                EndpointInfo(
                    url=url,
                    method=method.upper(),
                    status_code=status_code,
                    content_type=content_type,
                    headers=headers if isinstance(headers, dict) else {},
                    parameters=query_params,
                    forms=forms,
                )
            )

        # Ensure forms are extracted from the target page if Katana JSON didn't include them
        if endpoints and not any(ep.forms for ep in endpoints):
            try:
                resp = requests.get(target, timeout=5)
                if "html" in resp.headers.get("Content-Type", ""):
                    parser = _HTMLFormAndLinkParser(base_url=target)
                    parser.feed(resp.text)
                    if parser.forms:
                        endpoints[0].forms = parser.forms
            except Exception:
                pass

        asset = HostAsset(
            hostname=host,
            endpoints=endpoints,
            metadata={"source": "katana", "crawled_urls_count": len(endpoints)},
        )
        return findings, [asset] if endpoints else []

    def _run_builtin_crawler(
        self,
        target: str,
        scope: ScopeManifest,
        params: Dict[str, Any],
    ) -> AdapterResult:
        """
        Native recursive web crawler with HTML form extraction, link resolution,
        and Layer 3 scope boundary enforcement per hop.
        """
        scope_engine = ScopeEngine(scope)
        max_depth = int(params.get("depth", 3))
        max_pages = int(params.get("max_pages", 40))
        timeout = int(params.get("timeout", 5))

        normalized_target = target if "://" in target else f"http://{target}"
        visited_urls: Set[str] = set()
        queue: List[Tuple[str, int]] = [(normalized_target, 0)]

        discovered_endpoints: Dict[str, EndpointInfo] = {}
        findings: List[Finding] = []

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) REVENANT-Katana-Crawler/1.0",
            "Accept": "text/html,application/xhtml+xml,application/json,*/*",
        }

        while queue and len(visited_urls) < max_pages:
            current_url, depth = queue.pop(0)
            if current_url in visited_urls:
                continue

            # Layer 3 Scope check per URL hop
            allowed, _ = scope_engine.is_allowed(current_url)
            if not allowed:
                continue

            visited_urls.add(current_url)

            fetch_url = current_url.replace("://localhost:", "://127.0.0.1:").replace("://localhost/", "://127.0.0.1/")
            try:
                resp = requests.get(fetch_url, headers=headers, timeout=timeout, allow_redirects=True)
            except Exception:
                continue

            content_type = resp.headers.get("Content-Type", "").lower()
            status_code = resp.status_code

            # Parse query parameters from current URL
            parsed_curr = urllib.parse.urlparse(current_url)
            query_params = list(urllib.parse.parse_qs(parsed_curr.query).keys())

            endpoint_info = EndpointInfo(
                url=current_url,
                method="GET",
                status_code=status_code,
                content_type=content_type,
                parameters=query_params,
                headers=dict(resp.headers),
            )

            # If response is HTML, parse links and forms
            if "html" in content_type:
                parser = _HTMLFormAndLinkParser(base_url=current_url)
                try:
                    parser.feed(resp.text)
                except Exception:
                    pass

                # Record extracted forms
                endpoint_info.forms = parser.forms

                # Also extract parameters declared inside form inputs
                for form in parser.forms:
                    form_action = form.get("action", current_url)
                    form_method = form.get("method", "GET").upper()
                    form_params = [inp["name"] for inp in form.get("inputs", []) if inp.get("name")]

                    # Add form action as a discovered endpoint
                    if form_action not in discovered_endpoints:
                        discovered_endpoints[form_action] = EndpointInfo(
                            url=form_action,
                            method=form_method,
                            parameters=form_params,
                            forms=[form],
                        )
                    else:
                        discovered_endpoints[form_action].parameters = list(
                            set(discovered_endpoints[form_action].parameters + form_params)
                        )
                        discovered_endpoints[form_action].forms.append(form)

                # Enqueue child links if depth allows
                if depth < max_depth:
                    for link in parser.links:
                        # Normalize and clean link
                        link_clean = link.split("#")[0].strip()
                        if link_clean and link_clean not in visited_urls:
                            # Pre-check scope before queueing
                            is_in_scope, _ = scope_engine.is_allowed(link_clean)
                            if is_in_scope:
                                queue.append((link_clean, depth + 1))

            # Store current endpoint info
            discovered_endpoints[current_url] = endpoint_info

        # Convert discovered endpoints into HostAsset
        parsed_target = urllib.parse.urlparse(normalized_target)
        host = parsed_target.hostname or target
        asset = HostAsset(
            hostname=host,
            endpoints=list(discovered_endpoints.values()),
            metadata={
                "source": "katana-builtin",
                "crawled_urls_count": len(discovered_endpoints),
                "forms_discovered": sum(len(ep.forms) for ep in discovered_endpoints.values()),
            },
        )

        return AdapterResult(
            tool_name=self.name,
            target=target,
            exit_code=0,
            duration_seconds=0.1,
            findings=findings,
            discovered_assets=[asset],
            raw_stdout=f"Katana crawler mapped {len(discovered_endpoints)} endpoints across {len(visited_urls)} pages",
        )
