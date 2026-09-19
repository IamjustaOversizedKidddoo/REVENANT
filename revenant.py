#!/usr/bin/env python3
"""
REVENANT — Unified Platform CLI Entrypoint
Run: python revenant.py <target> [options]
"""
import sys
from pathlib import Path

# Ensure control-plane and root are in sys.path
ROOT_DIR = Path(__file__).resolve().parent
CONTROL_PLANE_DIR = ROOT_DIR / "control-plane"

for p in [str(ROOT_DIR), str(CONTROL_PLANE_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from control_plane.cli import main

if __name__ == "__main__":
    main()
