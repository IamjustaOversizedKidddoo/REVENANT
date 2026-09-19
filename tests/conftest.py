"""Pytest configuration ensuring control-plane and adapters are discoverable."""
import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
CONTROL_PLANE_DIR = ROOT_DIR / "control-plane"

for p in [str(ROOT_DIR), str(CONTROL_PLANE_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)
