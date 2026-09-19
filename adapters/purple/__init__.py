"""
REVENANT — Purple Teaming & Adversary Emulation Adapters
Exports AtomicRedTeamAdapter, CalderaAdapter, DetectionGapEngine, and safety types.
"""

from adapters.purple.atomic_adapter import (
    ATOMIC_TESTS_CATALOG,
    AtomicRedTeamAdapter,
    AtomicTest,
    SafetyViolationError,
)
from adapters.purple.caldera_adapter import CalderaAdapter
from adapters.purple.detection_engine import (
    DEFAULT_SIGMA_CATALOG,
    DetectionCoverageReport,
    DetectionGapEngine,
    DetectionRule,
)

__all__ = [
    "AtomicRedTeamAdapter",
    "AtomicTest",
    "ATOMIC_TESTS_CATALOG",
    "SafetyViolationError",
    "CalderaAdapter",
    "DetectionGapEngine",
    "DetectionRule",
    "DetectionCoverageReport",
    "DEFAULT_SIGMA_CATALOG",
]
