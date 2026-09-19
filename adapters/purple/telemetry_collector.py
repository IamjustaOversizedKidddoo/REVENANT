"""
REVENANT — Telemetry Collector for Purple Teaming
Reads real process execution evidence from:
  1. evidence_live/telemetry_events.json  (primary — written by AtomicRedTeamAdapter)
  2. Windows Application Event Log via PowerShell (secondary, if available)

Returns List[Dict] telemetry events for DetectionGapEngine.evaluate_emulation().
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("revenant.purple.telemetry_collector")

# Default path where AtomicRedTeamAdapter writes execution evidence
TELEMETRY_JSON_PATH = Path("evidence_live") / "telemetry_events.json"


class TelemetryCollector:
    """
    Reads real telemetry evidence produced during atomic test execution.
    Supports JSON file storage and Windows Application Event Log as sources.
    """

    def __init__(self, json_path: Optional[Path] = None):
        self.json_path = json_path or TELEMETRY_JSON_PATH

    def load_from_json(self) -> List[Dict[str, Any]]:
        """Load telemetry events from the JSON evidence file."""
        if not self.json_path.exists():
            logger.debug("Telemetry JSON not found at %s", self.json_path)
            return []
        try:
            with open(self.json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                logger.info("Loaded %d telemetry events from %s", len(data), self.json_path)
                return data
            return []
        except Exception as e:
            logger.warning("Failed to load telemetry JSON: %s", e)
            return []

    def load_from_windows_event_log(self) -> List[Dict[str, Any]]:
        """
        Query Windows Application Event Log for Revenant-tagged events.
        Uses PowerShell's Get-WinEvent — returns empty list on access failure.
        """
        ps_cmd = (
            "Get-WinEvent -LogName Application -MaxEvents 100 "
            "-ErrorAction SilentlyContinue "
            "| Where-Object { $_.Message -like '*REVENANT*' } "
            "| Select-Object TimeCreated, Id, Message "
            "| ConvertTo-Json -Depth 2"
        )
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0 and result.stdout.strip():
                raw = json.loads(result.stdout.strip())
                if isinstance(raw, dict):
                    raw = [raw]
                events = []
                for ev in raw:
                    events.append({
                        "source": "windows_event_log",
                        "event_id": ev.get("Id"),
                        "timestamp": str(ev.get("TimeCreated", "")),
                        "message": ev.get("Message", ""),
                    })
                logger.info("Loaded %d events from Windows Application Event Log", len(events))
                return events
        except Exception as e:
            logger.debug("Windows Event Log query failed (non-critical): %s", e)
        return []

    def collect(self) -> List[Dict[str, Any]]:
        """
        Collect telemetry from all available sources.
        JSON file is always checked; Event Log is attempted as bonus.
        """
        events = self.load_from_json()
        win_events = self.load_from_windows_event_log()
        events.extend(win_events)
        return events


def write_telemetry_event(
    technique_id: str,
    command: str,
    stdout: str,
    stderr: str,
    exit_code: int,
    timestamp: str,
    json_path: Optional[Path] = None,
) -> None:
    """
    Append a single atomic test execution record to the telemetry JSON file.
    Thread-unsafe for concurrent writes; designed for sequential atomic execution.
    """
    path = json_path or TELEMETRY_JSON_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    # Load existing events
    existing: List[Dict[str, Any]] = []
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = []

    event = {
        "technique_id": technique_id,
        "command": command,
        "stdout_snippet": stdout[:500] if stdout else "",
        "stderr_snippet": stderr[:200] if stderr else "",
        "exit_code": exit_code,
        "timestamp": timestamp,
        "source": "atomic_red_team",
    }
    existing.append(event)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)

    logger.debug("Telemetry event written for %s to %s", technique_id, path)
