"""REVENANT — ReconBLADE-style triage knowledge base (rule-based, offline).

Plain, extensible dictionaries that explain findings "like in chat": what a port /
missing header / vulnerability class means, why it matters, how to fix it, and the next
step. Ported from the ReconBLADE standalone-triage idea
(github.com/IamjustaOversizedKidddoo/reconBLADE) so REVENANT can re-present the SAME
findings in a detailed, triaged, prioritized style with zero network calls.

Everything here is a plain dict — add entries freely. Lookups are tolerant: unknown
ports/headers/CWEs fall back to a generic explanation rather than failing.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

# --------------------------------------------------------------------------- #
# PORT_KB — common service ports                                              #
# --------------------------------------------------------------------------- #
PORT_KB: Dict[int, Dict[str, str]] = {
    21: {
        "service": "FTP",
        "why_it_matters": "File Transfer Protocol often allows anonymous login and sends credentials in cleartext.",
        "common_risks": "Credential sniffing, anonymous file read/write, bounce attacks.",
        "fix": "Disable FTP; use SFTP/FTPS. If required, disable anonymous access and enforce TLS.",
        "next_step": "Attempt anonymous login and check for writable directories.",
    },
    22: {
        "service": "SSH",
        "why_it_matters": "Remote shell access. A weak/reused password or key is a direct foothold.",
        "common_risks": "Credential brute force, key reuse, outdated ciphers.",
        "fix": "Key-only auth, disable root login, rate-limit, keep OpenSSH patched.",
        "next_step": "Check the banner/version for known CVEs and confirm password auth is off.",
    },
    23: {
        "service": "Telnet",
        "why_it_matters": "Unencrypted remote shell — credentials travel in cleartext.",
        "common_risks": "Full credential capture by any on-path attacker.",
        "fix": "Disable Telnet entirely; replace with SSH.",
        "next_step": "Confirm the service is decommissioned, not just firewalled.",
    },
    25: {
        "service": "SMTP",
        "why_it_matters": "Mail transfer. Open relays and VRFY/EXPN leak users and enable spam/phishing.",
        "common_risks": "Open relay abuse, user enumeration.",
        "fix": "Require auth, disable open relay, restrict VRFY/EXPN.",
        "next_step": "Test for open relay and user enumeration.",
    },
    53: {
        "service": "DNS",
        "why_it_matters": "Name resolution. Zone transfers and recursion expose internal records.",
        "common_risks": "AXFR zone transfer, cache poisoning, subdomain mapping.",
        "fix": "Restrict zone transfers to secondaries; disable open recursion.",
        "next_step": "Attempt an AXFR zone transfer for internal hostnames.",
    },
    80: {
        "service": "HTTP",
        "why_it_matters": "Unencrypted web traffic — anything sent is readable on the wire.",
        "common_risks": "Credential/session interception, content injection, no transport integrity.",
        "fix": "Redirect to HTTPS and enable HSTS; serve nothing sensitive over plain HTTP.",
        "next_step": "Confirm a 301 to HTTPS and crawl the app surface for parameters.",
    },
    443: {
        "service": "HTTPS",
        "why_it_matters": "Encrypted web. Weak TLS config or app-layer bugs are the real surface here.",
        "common_risks": "Outdated TLS/ciphers, expired certs, app vulns behind TLS.",
        "fix": "TLS 1.2+ only, strong ciphers, valid cert, HSTS; fix app-layer issues.",
        "next_step": "Grade the TLS config and crawl the app for injectable parameters.",
    },
    445: {
        "service": "SMB",
        "why_it_matters": "Windows file sharing — a classic lateral-movement and ransomware vector.",
        "common_risks": "Null sessions, SMBv1, EternalBlue-class RCE, share enumeration.",
        "fix": "Disable SMBv1, require signing, restrict exposure, patch promptly.",
        "next_step": "Enumerate shares and check for null-session access and SMBv1.",
    },
    3306: {
        "service": "MySQL",
        "why_it_matters": "Database port exposed to the network — direct data access if reachable.",
        "common_risks": "Weak/default DB creds, unauthenticated access, data exfiltration.",
        "fix": "Bind to localhost / private net, strong creds, least-privilege accounts, firewall it.",
        "next_step": "Confirm it is not internet-reachable and test for default credentials.",
    },
    3389: {
        "service": "RDP",
        "why_it_matters": "Remote Desktop — a top ransomware entry point when exposed.",
        "common_risks": "Credential brute force, BlueKeep-class RCE, no MFA.",
        "fix": "Put behind VPN/gateway, enforce NLA + MFA, never expose to the internet.",
        "next_step": "Confirm RDP is not internet-facing; require VPN + MFA.",
    },
    5432: {
        "service": "PostgreSQL",
        "why_it_matters": "Database port — direct data access if network-reachable.",
        "common_risks": "Weak creds, trust auth, unauthenticated access.",
        "fix": "Bind to private interfaces, scram auth, least privilege, firewall.",
        "next_step": "Verify it is not externally reachable and test auth config.",
    },
    6379: {
        "service": "Redis",
        "why_it_matters": "In-memory store historically shipped with NO auth — instant data access / RCE.",
        "common_risks": "Unauthenticated access, config write to RCE.",
        "fix": "Require a strong password, bind to localhost, enable protected-mode, firewall.",
        "next_step": "Check for unauthenticated access with INFO/CONFIG commands.",
    },
    8080: {
        "service": "HTTP-alt",
        "why_it_matters": "Common app/proxy/admin port — often an unhardened dev or admin interface.",
        "common_risks": "Exposed admin panels, default creds, dev builds with debug on.",
        "fix": "Restrict access, remove default creds, disable debug, put behind auth.",
        "next_step": "Browse for admin/management panels and default credentials.",
    },
    27017: {
        "service": "MongoDB",
        "why_it_matters": "Document DB historically default-open — mass data breaches came from this.",
        "common_risks": "Unauthenticated access, full database read/write.",
        "fix": "Enable auth, bind to private net, least privilege, firewall.",
        "next_step": "Confirm auth is enabled and the port is not internet-facing.",
    },
}

# --------------------------------------------------------------------------- #
# HEADER_KB — HTTP security response headers (keyed lowercase)                #
# --------------------------------------------------------------------------- #
HEADER_KB: Dict[str, Dict[str, str]] = {
    "content-security-policy": {
        "missing_means": "The browser will run any script the page includes, from anywhere.",
        "risk": "Turns a single reflected input into full cross-site scripting (session/credential theft).",
        "fix": "Add a strict Content-Security-Policy (e.g. default-src 'self'; object-src 'none').",
    },
    "strict-transport-security": {
        "missing_means": "Browsers may connect over plain HTTP before redirecting.",
        "risk": "SSL-strip / on-path downgrade can intercept the first request and its cookies.",
        "fix": "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.",
    },
    "x-frame-options": {
        "missing_means": "The page can be embedded in an attacker's iframe.",
        "risk": "Clickjacking — users tricked into clicking hidden actions.",
        "fix": "Set X-Frame-Options: DENY (or a CSP frame-ancestors 'none').",
    },
    "x-content-type-options": {
        "missing_means": "Browsers may MIME-sniff responses and run them as a different type.",
        "risk": "A text/upload response can be executed as script (drive-by XSS).",
        "fix": "Set X-Content-Type-Options: nosniff.",
    },
    "referrer-policy": {
        "missing_means": "Full URLs (with tokens/paths) leak to third parties via the Referer header.",
        "risk": "Sensitive query parameters and session hints leak off-site.",
        "fix": "Set Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
    },
    "permissions-policy": {
        "missing_means": "No restriction on powerful browser features (camera, mic, geolocation).",
        "risk": "A compromised script or embed can abuse device capabilities.",
        "fix": "Set a least-privilege Permissions-Policy disabling unused features.",
    },
}

# --------------------------------------------------------------------------- #
# FINDING_KB — vulnerability classes by CWE and OWASP category                #
# Each entry: plain_explanation (what it is), why_it_matters (mechanism+impact),#
# typical_fix, next_step, blast (downstream blast radius for the causal line). #
# --------------------------------------------------------------------------- #
FINDING_KB: Dict[str, Dict[str, str]] = {
    "CWE-89": {
        "plain_explanation": "The app lets your input change the meaning of a database query (SQL injection).",
        "why_it_matters": "Input is parsed as SQL, so an attacker can bypass login and read or alter the whole database.",
        "typical_fix": "Use parameterized queries / prepared statements; least-privilege DB accounts.",
        "next_step": "Confirm data extraction depth, then patch and re-test.",
        "blast": "the entire application database and every user account",
    },
    "CWE-79": {
        "plain_explanation": "The app reflects your input into the page without escaping it (cross-site scripting).",
        "why_it_matters": "Injected JavaScript runs in a victim's browser as the site, stealing sessions or acting as them.",
        "typical_fix": "Context-aware output encoding, a strict CSP, and HttpOnly+SameSite cookies.",
        "next_step": "Demonstrate cookie/session theft impact, then encode output and add CSP.",
        "blast": "any user who opens a crafted link, including admins",
    },
    "CWE-22": {
        "plain_explanation": "The app builds a file path from your input, so '../' escapes the intended folder (path traversal).",
        "why_it_matters": "Lets an attacker read arbitrary server files — source, config, and secrets like .env.",
        "typical_fix": "Canonicalize paths and confirm they stay under an allow-listed base; serve by opaque ID.",
        "next_step": "Enumerate readable secrets, then patch the path handling and re-test.",
        "blast": "any file the web process can read, including credentials that unlock other systems",
    },
    "CWE-601": {
        "plain_explanation": "The app redirects to a URL taken from your input without checking it (open redirect).",
        "why_it_matters": "A trusted link silently forwards victims to attacker infrastructure for phishing.",
        "typical_fix": "Redirect only to an allow-list of internal paths/hosts; never to a raw user URL.",
        "next_step": "Confirm the redirect target is attacker-controlled, then allow-list destinations.",
        "blast": "users and brand trust; it supercharges credential phishing",
    },
    "CWE-918": {
        "plain_explanation": "The server fetches a URL you supply (server-side request forgery).",
        "why_it_matters": "An attacker pivots through the server to internal services and cloud metadata (IAM keys).",
        "typical_fix": "Allow-list outbound hosts, block link-local/metadata ranges, disable unused schemes.",
        "next_step": "Test reachability of cloud metadata, then lock down egress.",
        "blast": "the internal network and the cloud account hosting the app",
    },
    "CWE-798": {
        "plain_explanation": "A live secret (key/password/token) is exposed in code or a response.",
        "why_it_matters": "Anyone who reads it authenticates as the owner of whatever it unlocks.",
        "typical_fix": "Rotate the secret now; move secrets to a vault; add secret scanning in CI.",
        "next_step": "Rotate immediately and audit where the secret was used.",
        "blast": "every system the leaked credential is authorized to reach",
    },
    "CWE-287": {
        "plain_explanation": "Authentication can be bypassed or is improperly enforced.",
        "why_it_matters": "An attacker accesses accounts or functions without valid credentials.",
        "typical_fix": "Enforce auth server-side on every protected route; add MFA; fix session handling.",
        "next_step": "Map which protected routes are reachable unauthenticated, then enforce checks.",
        "blast": "protected accounts and the data/functions behind them",
    },
    "CWE-352": {
        "plain_explanation": "State-changing actions lack anti-forgery protection (CSRF).",
        "why_it_matters": "A malicious page can make a logged-in victim perform actions unknowingly.",
        "typical_fix": "Per-request CSRF tokens and SameSite cookies on all state-changing requests.",
        "next_step": "Confirm a forged cross-site action succeeds, then add CSRF tokens.",
        "blast": "any action a logged-in victim is authorized to take",
    },
    "CWE-434": {
        "plain_explanation": "The app accepts file uploads without proper validation.",
        "why_it_matters": "An attacker can upload a web shell or malicious file and may achieve code execution.",
        "typical_fix": "Validate type/extension server-side, store outside webroot, randomize names, scan content.",
        "next_step": "Test whether an uploaded file is executable/servable, then harden upload handling.",
        "blast": "the web server itself, potentially full remote code execution",
    },
    "CWE-502": {
        "plain_explanation": "The app deserializes untrusted data.",
        "why_it_matters": "Crafted serialized input can trigger remote code execution or object injection.",
        "typical_fix": "Avoid native deserialization of untrusted data; use safe formats with schema validation.",
        "next_step": "Confirm the sink and payload control, then replace unsafe deserialization.",
        "blast": "the application process, potentially full remote code execution",
    },
    "CWE-16": {
        "plain_explanation": "A service is deployed with insecure defaults or weak configuration (misconfiguration).",
        "why_it_matters": "Exposes data or management surfaces that should be private — an easy foothold.",
        "typical_fix": "Apply a hardened CIS baseline; make resources private by default; enforce with IaC checks.",
        "next_step": "Inventory what the misconfiguration exposes, then apply the hardened baseline.",
        "blast": "whatever the exposed service holds and anything its credentials reach",
    },
    "CWE-200": {
        "plain_explanation": "The app exposes sensitive information to users who shouldn't see it.",
        "why_it_matters": "Leaked internal data, stack traces, or PII aids further attacks and breaches privacy.",
        "typical_fix": "Suppress verbose errors in prod, restrict sensitive endpoints, review responses.",
        "next_step": "Catalog what is leaked, then restrict and sanitize the responses.",
        "blast": "the exposed data and the attacks it enables next",
    },
    # OWASP LLM Top 10 (AI targets)
    "LLM01": {
        "plain_explanation": "The model follows attacker instructions hidden in its input (prompt injection).",
        "why_it_matters": "Overrides system intent — data exfiltration, tool misuse, or policy bypass.",
        "typical_fix": "Isolate untrusted content, constrain tools, validate/escape model I/O, add guardrails.",
        "next_step": "Map which tools/data the injection can reach, then constrain and sandbox them.",
        "blast": "whatever data and tools the model can access on the user's behalf",
    },
    "LLM02": {
        "plain_explanation": "Model output is used downstream without validation (insecure output handling).",
        "why_it_matters": "Model-generated text becomes XSS, SSRF, or command execution in the consuming system.",
        "typical_fix": "Treat model output as untrusted: encode, validate, and sandbox before use.",
        "next_step": "Trace the output sink, then add encoding/validation at that boundary.",
        "blast": "the downstream system that consumes the model output",
    },
    "LLM06": {
        "plain_explanation": "The model reveals sensitive information in its responses (sensitive info disclosure).",
        "why_it_matters": "Training data, secrets, or other users' data leak through model outputs.",
        "typical_fix": "Scrub sensitive data from context, add output filtering, enforce per-user isolation.",
        "next_step": "Identify what can be elicited, then filter and isolate sensitive context.",
        "blast": "confidential data embedded in or reachable from the model context",
    },
}

# OWASP category text (e.g. "A03:2021-Injection") -> a CWE key above, for fallback.
_OWASP_TO_CWE = {
    "injection": "CWE-89",
    "a03": "CWE-89",
    "xss": "CWE-79",
    "cross-site scripting": "CWE-79",
    "broken access": "CWE-287",
    "a01": "CWE-287",
    "identification and authentication": "CWE-287",
    "a07": "CWE-287",
    "ssrf": "CWE-918",
    "a10": "CWE-918",
    "security misconfiguration": "CWE-16",
    "a05": "CWE-16",
    "llm01": "LLM01",
    "prompt injection": "LLM01",
    "llm02": "LLM02",
    "llm06": "LLM06",
    "sensitive information disclosure": "LLM06",
}

_GENERIC_FINDING = {
    "plain_explanation": "A weakness lets an attacker influence behavior the application treats as trusted.",
    "why_it_matters": "Depending on context it can cost confidentiality, integrity, or availability of the component.",
    "typical_fix": "Validate and encode untrusted input at the boundary and apply least privilege.",
    "next_step": "Confirm the impact, then remediate at the input boundary and re-test.",
    "blast": "the affected component and the data directly reachable from it",
}


def port_info(port: int) -> Optional[Dict[str, str]]:
    """Return the KB entry for a port, or None if unknown."""
    return PORT_KB.get(int(port)) if port is not None else None


def header_info(name: str) -> Optional[Dict[str, str]]:
    """Return the KB entry for a security header (case-insensitive), or None."""
    return HEADER_KB.get((name or "").strip().lower())


def finding_info(
    cwe: Optional[str] = None,
    owasp_category: Optional[str] = None,
    text: str = "",
) -> Dict[str, str]:
    """Resolve the best FINDING_KB entry from CWE, OWASP category, or free text.

    Always returns an entry (generic fallback), never None.
    """
    if cwe:
        key = cwe.strip().upper()
        if key in FINDING_KB:
            return FINDING_KB[key]
    hay = f"{owasp_category or ''} {text or ''}".lower()
    for needle, cwe_key in _OWASP_TO_CWE.items():
        if needle in hay and cwe_key in FINDING_KB:
            return FINDING_KB[cwe_key]
    return _GENERIC_FINDING


def detect_port(text: str) -> Optional[int]:
    """Best-effort extraction of a port number from a finding's text."""
    m = re.search(r"\bport[\s:]+(\d{1,5})\b", text or "", re.IGNORECASE)
    if m:
        try:
            p = int(m.group(1))
            if 0 < p < 65536:
                return p
        except ValueError:
            return None
    return None


def detect_header(text: str) -> Optional[str]:
    """Best-effort detection of a security-header name referenced in a finding."""
    low = (text or "").lower()
    for name in HEADER_KB:
        if name in low or name.replace("-", " ") in low:
            return name
    return None
