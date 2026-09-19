"""
Unit tests for REVENANT 3-Layer Scope Boundary Enforcement Engine.
Verifies allowed domains, wildcards, CIDRs, localhost/lab targets, and hard-blocks
on unauthorized assets, cloud metadata (169.254.169.254), and multicast.
"""

import pytest
from control_plane.schemas.scope import (
    ScopeEngine,
    ScopeManifest,
    ScopeViolationError,
)


class TestScopeEngine:
    """Test suite for ScopeEngine and ScopeManifest."""

    def test_empty_scope_refuses_all(self):
        """Empty manifest must refuse all targets when explicit scope is required."""
        engine = ScopeEngine(ScopeManifest(require_explicit_scope=True))
        allowed, reason = engine.is_allowed("https://example.com")
        assert not allowed
        assert "explicit authorization is mandatory" in reason.lower()

        with pytest.raises(ScopeViolationError):
            engine.validate_or_raise("192.168.1.1")

    def test_extract_host_normalization(self):
        """Host extractor must isolate clean hostname/IP regardless of URI wrapper."""
        cases = [
            ("http://example.com", "example.com"),
            ("https://example.com:8443/api/v1?token=xyz", "example.com"),
            ("http://admin:secret@sub.target.org:8080/#anchor", "sub.target.org"),
            ("192.168.1.50:3000", "192.168.1.50"),
            ("https://[::1]:8080/test", "::1"),
            ("localhost:30013", "localhost"),
        ]
        for raw, expected in cases:
            assert ScopeEngine.extract_host(raw) == expected

    def test_exact_domain_allowed_and_blocked(self):
        manifest = ScopeManifest(
            allowed_domains=["sanctioned-lab.local", "target.com"]
        )
        engine = ScopeEngine(manifest)

        # In-scope
        allowed, _ = engine.is_allowed("https://sanctioned-lab.local:8080/login")
        assert allowed
        allowed, _ = engine.is_allowed("target.com")
        assert allowed

        # Out-of-scope
        allowed, reason = engine.is_allowed("evil.com")
        assert not allowed
        assert "outside all authorized" in reason.lower()

        # Subdomain when only root is declared should be blocked
        allowed, _ = engine.is_allowed("sub.target.com")
        assert not allowed

    def test_wildcard_domains(self):
        manifest = ScopeManifest(
            allowed_wildcards=["*.target.com", "*.corp.internal"]
        )
        engine = ScopeEngine(manifest)

        # Subdomains allowed
        assert engine.is_allowed("api.target.com")[0]
        assert engine.is_allowed("auth.stage.target.com")[0]
        # Root domain also allowed
        assert engine.is_allowed("target.com")[0]

        # Other domains blocked
        assert not engine.is_allowed("target.org")[0]
        assert not engine.is_allowed("nottarget.com")[0]

    def test_cidr_ranges(self):
        manifest = ScopeManifest(
            allowed_cidrs=["192.168.10.0/24", "10.1.0.0/16"]
        )
        engine = ScopeEngine(manifest)

        # In CIDR
        assert engine.is_allowed("192.168.10.1")[0]
        assert engine.is_allowed("http://192.168.10.254:3000/")[0]
        assert engine.is_allowed("10.1.55.99")[0]

        # Outside CIDR
        assert not engine.is_allowed("192.168.11.1")[0]
        assert not engine.is_allowed("10.2.0.1")[0]
        assert not engine.is_allowed("8.8.8.8")[0]

    def test_denied_cidr_precedence(self):
        """Denied CIDRs override allowed CIDRs."""
        manifest = ScopeManifest(
            allowed_cidrs=["10.0.0.0/8"],
            denied_cidrs=["10.0.50.0/24"],
        )
        engine = ScopeEngine(manifest)

        # Allowed in general 10.0.0.0/8
        assert engine.is_allowed("10.0.1.1")[0]

        # Denied in specific exclusion
        allowed, reason = engine.is_allowed("10.0.50.10")
        assert not allowed
        assert "denied cidr" in reason.lower()

    def test_cloud_metadata_hard_blocked(self):
        """169.254.169.254 must always be blocked even if broad scope is supplied."""
        manifest = ScopeManifest(
            allowed_cidrs=["0.0.0.0/0"],  # Broad scope attempted
            allow_cloud_metadata=False,
        )
        engine = ScopeEngine(manifest)

        allowed, reason = engine.is_allowed("http://169.254.169.254/latest/meta-data")
        assert not allowed
        assert "cloud metadata" in reason.lower()

        with pytest.raises(ScopeViolationError):
            engine.validate_or_raise("169.254.169.254")

    def test_multicast_blocked(self):
        manifest = ScopeManifest(allowed_cidrs=["0.0.0.0/0"])
        engine = ScopeEngine(manifest)

        allowed, reason = engine.is_allowed("224.0.0.1")
        assert not allowed
        assert "multicast" in reason.lower()

    def test_localhost_lab_hosts(self):
        """Localhost and 127.0.0.1 are supported via allowed_hosts for safe labs."""
        manifest = ScopeManifest(
            allowed_hosts=["localhost", "127.0.0.1"]
        )
        engine = ScopeEngine(manifest)

        assert engine.is_allowed("http://localhost:3000")[0]
        assert engine.is_allowed("http://127.0.0.1:30013/crAPI")[0]
        assert not engine.is_allowed("http://127.0.0.2:3000")[0]
