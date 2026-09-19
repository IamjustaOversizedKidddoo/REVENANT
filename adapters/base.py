"""
REVENANT — Universal Tool Adapter Base Class
Defines the standard execution contract and Layer 3 scope boundary enforcement
for all security tools in REVENANT.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from control_plane.schemas.models import Finding, HostAsset
from control_plane.schemas.scope import ScopeEngine, ScopeManifest, ScopeViolationError

logger = logging.getLogger("revenant.adapter")


class AdapterResult(BaseModel):
    """Normalized result returned from an adapter execution."""
    tool_name: str
    target: str
    exit_code: int = 0
    duration_seconds: float = 0.0
    findings: List[Finding] = Field(default_factory=list)
    discovered_assets: List[HostAsset] = Field(default_factory=list)
    raw_stdout: str = ""
    raw_stderr: str = ""
    error: Optional[str] = None


def to_wsl_path(path_str: str) -> str:
    """Convert Windows path (e.g. D:\\REVENANT\\foo) to WSL path (/mnt/d/REVENANT/foo)."""
    import os
    import re
    from pathlib import Path
    if not path_str or not isinstance(path_str, str):
        return path_str
    # Resolve relative paths that exist on disk to absolute paths
    if os.path.exists(path_str):
        try:
            path_str = str(Path(path_str).resolve())
        except Exception:
            pass
    m = re.match(r"^([a-zA-Z]):[\\/](.*)", path_str)
    if m:
        drive = m.group(1).lower()
        rest = m.group(2).replace("\\", "/")
        return f"/mnt/{drive}/{rest}"
    m2 = re.match(r"^([a-zA-Z]):$", path_str)
    if m2:
        return f"/mnt/{m2.group(1).lower()}"
    return path_str.replace("\\", "/")


_wsl_gw_cache: Dict[str, str] = {}

def get_wsl_gateway_ip(distro: str = "Ubuntu") -> str:
    """Detect the WSL host gateway IP address to reach Windows host listeners."""
    import re
    if distro in _wsl_gw_cache:
        return _wsl_gw_cache[distro]
    wsl_bin = r"C:\Windows\System32\wsl.exe" if os.path.exists(r"C:\Windows\System32\wsl.exe") else "wsl.exe"
    try:
        proc = subprocess.run(
            [wsl_bin, "-d", distro, "-u", "root", "--", "sh", "-c", "ip route show | grep default"],
            capture_output=True, text=True, timeout=5
        )
        for part in proc.stdout.split():
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", part):
                _wsl_gw_cache[distro] = part
                return part
    except Exception:
        pass
    _wsl_gw_cache[distro] = "127.0.0.1"
    return "127.0.0.1"


class BaseAdapter(ABC):
    """Abstract base class for all 66 tool adapters."""

    def __init__(
        self,
        name: str,
        category: str,
        version: str = "latest",
        binary_override: Optional[str] = None,
        use_wsl: bool = False,
        wsl_distro: str = "Ubuntu",
    ):
        self.name = name
        self.category = category
        self.version = version
        self.binary_override = binary_override
        self.use_wsl = use_wsl
        self.wsl_distro = wsl_distro

    @property
    def binary_path(self) -> Optional[str]:
        """Resolve executable binary path on host system or local bin directory."""
        if self.binary_override:
            return self.binary_override
        # 1. Check system PATH
        found = shutil.which(self.name)
        if found:
            return found
        # 2. Check local REVENANT/bin and .venv/Scripts directories
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        candidates = [
            root / "bin" / self.name,
            root / "bin" / f"{self.name}.exe",
            root / ".venv" / "Scripts" / self.name,
            root / ".venv" / "Scripts" / f"{self.name}.exe",
        ]
        for c in candidates:
            if c.is_file():
                return str(c)
        return None

    @property
    def is_wsl_mode(self) -> bool:
        """WSL2 execution bridge is only applicable when running on a Windows host."""
        return self.use_wsl and os.name == "nt"

    def is_installed(self) -> bool:
        """Check if tool binary is available in PATH, custom location, or WSL."""
        if self.is_wsl_mode:
            return True
        return self.binary_path is not None

    def validate_target_scope(self, target: str, scope: ScopeManifest) -> None:
        """
        Layer 3 Scope Enforcement:
        Re-verifies target authorization immediately before execution.
        Raises ScopeViolationError if unauthorized.
        """
        engine = ScopeEngine(scope)
        engine.validate_or_raise(target)

    @abstractmethod
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        """Construct the CLI argument list for the tool."""
        pass

    @abstractmethod
    def parse_output(
        self, stdout: str, stderr: str, target: str
    ) -> Tuple[List[Finding], List[HostAsset]]:
        """Parse raw tool stdout/stderr into normalized Findings and HostAssets."""
        pass

    def run(
        self,
        target: str,
        scope: ScopeManifest,
        params: Optional[Dict[str, Any]] = None,
        timeout_seconds: int = 300,
    ) -> AdapterResult:
        """
        Execute tool safely with scope check, timeout bounding, and result normalization.
        Supports both native Windows execution, native Linux/container execution, and WSL2 bridge.
        """
        import urllib.parse
        params = params or {}
        start_time = time.time()

        # 1. LAYER 3 SCOPE CHECK (Cannot be bypassed)
        self.validate_target_scope(target, scope)

        # 2. Check installation
        bin_path = self.binary_path
        if not bin_path and not self.is_wsl_mode:
            return AdapterResult(
                tool_name=self.name,
                target=target,
                exit_code=127,
                error=f"Tool binary '{self.name}' not found on system PATH.",
            )

        # 3. Build command
        cmd = self.build_command(target, params)

        # 4. Safe execution (WSL2 bridge on Windows or Native Execution in Container/Linux)
        wsl_gw = "127.0.0.1"
        if self.is_wsl_mode:
            from pathlib import Path
            tool_binary = cmd[0] if cmd[0].startswith("/") else Path(cmd[0]).stem
            wsl_gw = get_wsl_gateway_ip(self.wsl_distro)
            translated_args: List[str] = []
            for arg in cmd[1:]:
                # Translate localhost/127.0.0.1 to WSL gateway IP so Linux tool can reach Windows host
                if "127.0.0.1" in arg or "localhost" in arg:
                    translated_args.append(arg.replace("127.0.0.1", wsl_gw).replace("localhost", wsl_gw))
                elif (len(arg) > 2 and arg[1] == ":") or "\\" in arg:
                    translated_args.append(to_wsl_path(arg))
                else:
                    translated_args.append(arg)

            wsl_bin = r"C:\Windows\System32\wsl.exe" if os.path.exists(r"C:\Windows\System32\wsl.exe") else "wsl.exe"
            exec_cmd = [wsl_bin, "-d", self.wsl_distro, "-u", "root", "--", tool_binary] + translated_args
            run_env = None
        else:
            exec_cmd = cmd
            run_env = dict(subprocess.os.environ)
            run_env["PYTHONIOENCODING"] = "utf-8"
            run_env["PYTHONUTF8"] = "1"
            from pathlib import Path
            repo_root = Path(__file__).resolve().parent.parent
            bin_dir = str(repo_root / "bin")
            user_scripts = str(Path.home() / "AppData" / "Roaming" / "Python" / "Python314" / "Scripts")
            existing_path = run_env.get("PATH", "")
            run_env["PATH"] = f"{bin_dir}{os.pathsep}{user_scripts}{os.pathsep}{existing_path}"

        try:
            process = subprocess.run(
                exec_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=run_env,
                timeout=timeout_seconds,
                check=False,
            )

            # Auto-recover if WSL host service encountered E_UNEXPECTED
            if self.use_wsl and "E_UNEXPECTED" in (process.stdout + process.stderr):
                logger.warning("WSL returned E_UNEXPECTED; recycling WSL service and retrying once...")
                subprocess.run([wsl_bin, "--shutdown"], capture_output=True, timeout=10)
                time.sleep(2)
                process = subprocess.run(
                    exec_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    env=run_env,
                    timeout=timeout_seconds,
                    check=False,
                )

            duration = time.time() - start_time

            stdout_clean = process.stdout
            if self.use_wsl and wsl_gw != "127.0.0.1":
                parsed_target = urllib.parse.urlparse(target) if target.startswith("http") else None
                original_host = parsed_target.hostname if parsed_target else "127.0.0.1"
                stdout_clean = stdout_clean.replace(wsl_gw, original_host)

            findings, assets = self.parse_output(stdout_clean, process.stderr, target)

            return AdapterResult(
                tool_name=self.name,
                target=target,
                exit_code=process.returncode,
                duration_seconds=round(duration, 3),
                findings=findings,
                discovered_assets=assets,
                raw_stdout=stdout_clean,
                raw_stderr=process.stderr,
            )

        except subprocess.TimeoutExpired as e:
            duration = time.time() - start_time
            stdout_str = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
            stderr_str = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
            findings, assets = self.parse_output(stdout_str, stderr_str, target)
            return AdapterResult(
                tool_name=self.name,
                target=target,
                exit_code=124,
                duration_seconds=round(duration, 3),
                findings=findings,
                discovered_assets=assets,
                raw_stdout=stdout_str,
                raw_stderr=stderr_str,
                error=f"Execution timed out after {timeout_seconds} seconds.",
            )
        except Exception as e:
            duration = time.time() - start_time
            return AdapterResult(
                tool_name=self.name,
                target=target,
                exit_code=1,
                duration_seconds=round(duration, 3),
                error=f"Adapter execution error: {str(e)}",
            )
