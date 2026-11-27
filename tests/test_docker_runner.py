"""Unit tests for the env-driven execution runner (local | wsl | docker).

These verify the Docker-isolation seam added to adapters.base WITHOUT requiring a
Docker engine: runner resolution, command construction, and capability reporting.
"""
from typing import Any, Dict, List, Tuple

import pytest

from adapters.base import (
    BaseAdapter,
    DOCKER_IMAGE_MAP,
    build_docker_command,
    resolve_runner,
)
from control_plane.schemas.models import Finding, HostAsset


class _DummyAdapter(BaseAdapter):
    """Minimal concrete adapter named after a mapped tool, for runner tests."""

    def __init__(self, **kw):
        super().__init__(name="nuclei", category="web", **kw)

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        return [self.binary_path or "nuclei", "-u", target]

    def parse_output(self, stdout: str, stderr: str, target: str) -> Tuple[List[Finding], List[HostAsset]]:
        return [], []


def test_resolve_runner_default_is_local(monkeypatch):
    monkeypatch.delenv("REVENANT_RUNNER", raising=False)
    assert resolve_runner() == "local"


def test_resolve_runner_env_and_explicit(monkeypatch):
    monkeypatch.setenv("REVENANT_RUNNER", "docker")
    assert resolve_runner() == "docker"
    # explicit argument overrides the env var
    assert resolve_runner("wsl") == "wsl"
    # unknown value falls back to local, never crashes
    assert resolve_runner("bogus") == "local"


def test_default_adapter_is_local(monkeypatch):
    monkeypatch.delenv("REVENANT_RUNNER", raising=False)
    a = _DummyAdapter()
    assert a.runner == "local"
    assert a.is_docker_mode is False
    assert a.is_wsl_mode is False


def test_docker_mode_flags_and_image():
    a = _DummyAdapter(runner="docker")
    assert a.is_docker_mode is True
    assert a.docker_image == DOCKER_IMAGE_MAP["nuclei"]


def test_docker_is_installed_requires_docker_binary(monkeypatch):
    a = _DummyAdapter(runner="docker")
    monkeypatch.setattr("adapters.base.shutil.which", lambda name: None)
    assert a.is_installed() is False
    monkeypatch.setattr("adapters.base.shutil.which", lambda name: "/usr/bin/docker")
    assert a.is_installed() is True


def test_build_docker_command_mounts_and_rewrites_loopback():
    cmd = build_docker_command("projectdiscovery/nuclei:latest",
                               ["-u", "http://127.0.0.1:3000"], workdir="/tmp/work")
    assert cmd[:3] == ["docker", "run", "--rm"]
    assert "projectdiscovery/nuclei:latest" in cmd
    assert "-v" in cmd and "/tmp/work:/work" in cmd
    # loopback target rewritten so a container can reach the host listener
    assert "http://host.docker.internal:3000" in cmd
    assert "127.0.0.1" not in " ".join(cmd)


def test_wsl_backcompat_via_use_wsl(monkeypatch):
    monkeypatch.delenv("REVENANT_RUNNER", raising=False)
    a = _DummyAdapter(use_wsl=True)
    assert a.runner == "wsl"
