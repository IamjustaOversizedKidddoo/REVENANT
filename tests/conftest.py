"""Pytest configuration ensuring control-plane and adapters are discoverable,
and that the sanctioned local lab servers the live tests target are running.
"""
import importlib.util
import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
CONTROL_PLANE_DIR = ROOT_DIR / "control-plane"

for p in [str(ROOT_DIR), str(CONTROL_PLANE_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)


def _port_open(host: str, port: int, timeout: float = 0.25) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def _wait_for_port(host: str, port: int, deadline: float = 15.0) -> bool:
    start = time.time()
    while time.time() - start < deadline:
        if _port_open(host, port):
            return True
        time.sleep(0.2)
    return False


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session", autouse=True)
def sanctioned_http_lab():
    """Boot the HTTP vulnerability lab (XSS/redirect/traversal/BOLA) on 127.0.0.1:3000.

    The DAST, crawler, and full-spectrum live tests target this server. If a lab is
    already listening (operator started it manually), reuse it instead of starting a
    second one.
    """
    host, port = "127.0.0.1", 3000
    if not _port_open(host, port):
        lab = _load_module(
            "sanctioned_lab_server", Path(__file__).parent / "sanctioned_lab_server.py"
        )
        server = lab.ThreadedHTTPServer((host, port), lab.LabServerHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        _wait_for_port(host, port)
    yield f"http://{host}:{port}"


@pytest.fixture(scope="session", autouse=True)
def sanctioned_ai_lab():
    """Boot the vulnerable AI lab (FastAPI) on 127.0.0.1:8001 via uvicorn in a thread.

    The AI red-team live tests target /v1/chat/completions here. Skips silently if
    uvicorn/fastapi are unavailable so the rest of the suite still runs.
    """
    host, port = "127.0.0.1", 8001
    if not _port_open(host, port):
        try:
            import uvicorn
        except ImportError:
            yield None
            return
        ai = _load_module(
            "sanctioned_ai_server",
            Path(__file__).parent / "fixtures" / "ai_lab" / "sanctioned_ai_server.py",
        )
        config = uvicorn.Config(ai.app, host=host, port=port, log_level="error")
        server = uvicorn.Server(config)
        threading.Thread(target=server.run, daemon=True).start()
        _wait_for_port(host, port)
    yield f"http://{host}:{port}"
