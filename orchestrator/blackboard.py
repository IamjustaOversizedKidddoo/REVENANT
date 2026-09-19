"""
REVENANT — Stigmergic Blackboard Architecture with SQLite / Persistent Storage
Shared mission state management. Autonomous agents react to findings/events
posted on the blackboard and emit new findings without direct peer coupling.
Supports durable SQLite persistence and state rehydration across process restarts.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from control_plane.schemas.models import Finding, HostAsset


class EventType(str, Enum):
    TARGET_REGISTERED = "TARGET_REGISTERED"
    HOST_DISCOVERED = "HOST_DISCOVERED"
    PORT_OPEN = "PORT_OPEN"
    HTTP_ENDPOINT = "HTTP_ENDPOINT"
    TECH_DETECTED = "TECH_DETECTED"
    REPO_DISCOVERED = "REPO_DISCOVERED"
    SECRET_EXPOSED = "SECRET_EXPOSED"
    CRAWL_COMPLETED = "CRAWL_COMPLETED"
    PARAMETER_DISCOVERED = "PARAMETER_DISCOVERED"
    DAST_CANDIDATE = "DAST_CANDIDATE"
    CLOUD_ASSET_DISCOVERED = "CLOUD_ASSET_DISCOVERED"
    CONTAINER_DISCOVERED = "CONTAINER_DISCOVERED"
    IDENTITY_ASSET_DISCOVERED = "IDENTITY_ASSET_DISCOVERED"
    AI_ENDPOINT_DISCOVERED = "AI_ENDPOINT_DISCOVERED"
    MOBILE_APP_DISCOVERED = "MOBILE_APP_DISCOVERED"
    FORENSICS_ARTIFACT_DISCOVERED = "FORENSICS_ARTIFACT_DISCOVERED"
    MISCONFIGURATION_DETECTED = "MISCONFIGURATION_DETECTED"
    PRIVILEGE_ESCALATION_PATH_DETECTED = "PRIVILEGE_ESCALATION_PATH_DETECTED"
    VULNERABILITY_CANDIDATE = "VULNERABILITY_CANDIDATE"
    VULNERABILITY_CONFIRMED = "VULNERABILITY_CONFIRMED"
    AI_VULNERABILITY_CONFIRMED = "AI_VULNERABILITY_CONFIRMED"
    MOBILE_VULNERABILITY_CONFIRMED = "MOBILE_VULNERABILITY_CONFIRMED"
    TTP_EMULATED = "TTP_EMULATED"
    DETECTION_GAP_IDENTIFIED = "DETECTION_GAP_IDENTIFIED"
    CAMPAIGN_COMPLETE = "CAMPAIGN_COMPLETE"


class BlackboardEvent(BaseModel):
    """An immutable, timestamped event posted to the blackboard."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: EventType
    source_agent: str
    target: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    handled_by: List[str] = Field(default_factory=list)


class Blackboard:
    """
    Thread-safe mission state and stigmergic event blackboard with durable persistence.
    Saves events, assets, and findings to SQLite.
    """

    def __init__(self, campaign_id: Optional[str] = None, db_path: Optional[str] = None):
        self.campaign_id = campaign_id or str(uuid.uuid4())
        self.db_path = db_path
        self._lock = threading.RLock()
        self._events: List[BlackboardEvent] = []
        self._assets: Dict[str, HostAsset] = {}
        self._findings: Dict[str, Finding] = {}

        if self.db_path:
            self._init_db()
            self._load_from_db()

    def _get_conn(self) -> Optional[sqlite3.Connection]:
        if not self.db_path or self.db_path == ":memory:":
            return None
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        conn = self._get_conn()
        if not conn:
            return
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        try:
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS events (
                        id TEXT PRIMARY KEY,
                        campaign_id TEXT,
                        event_type TEXT,
                        source_agent TEXT,
                        target TEXT,
                        payload TEXT,
                        timestamp TEXT,
                        handled_by TEXT
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS assets (
                        id TEXT PRIMARY KEY,
                        campaign_id TEXT,
                        asset_key TEXT UNIQUE,
                        asset_data TEXT
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id TEXT PRIMARY KEY,
                        campaign_id TEXT,
                        finding_data TEXT
                    )
                """)
        finally:
            conn.close()

    def _load_from_db(self) -> None:
        conn = self._get_conn()
        if not conn:
            return
        try:
            cur = conn.execute(
                "SELECT id, event_type, source_agent, target, payload, timestamp, handled_by FROM events WHERE campaign_id = ?",
                (self.campaign_id,),
            )
            for row in cur.fetchall():
                ev = BlackboardEvent(
                    id=row[0],
                    event_type=EventType(row[1]),
                    source_agent=row[2],
                    target=row[3],
                    payload=json.loads(row[4]),
                    timestamp=datetime.fromisoformat(row[5]),
                    handled_by=json.loads(row[6]),
                )
                self._events.append(ev)

            cur = conn.execute(
                "SELECT asset_key, asset_data FROM assets WHERE campaign_id = ?",
                (self.campaign_id,),
            )
            for row in cur.fetchall():
                key, data = row[0], json.loads(row[1])
                self._assets[key] = HostAsset.model_validate(data)

            cur = conn.execute(
                "SELECT id, finding_data FROM findings WHERE campaign_id = ?",
                (self.campaign_id,),
            )
            for row in cur.fetchall():
                fid, data = row[0], json.loads(row[1])
                self._findings[fid] = Finding.model_validate(data)
        finally:
            conn.close()

    def post_event(self, event: BlackboardEvent) -> None:
        """Publish a new event to the blackboard and persist it."""
        with self._lock:
            self._events.append(event)
            conn = self._get_conn()
            if conn:
                try:
                    with conn:
                        conn.execute(
                            "INSERT OR REPLACE INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                event.id,
                                self.campaign_id,
                                event.event_type.value,
                                event.source_agent,
                                event.target,
                                json.dumps(event.payload, default=str),
                                event.timestamp.isoformat(),
                                json.dumps(event.handled_by),
                            ),
                        )
                finally:
                    conn.close()

    def get_events(self, event_type: Optional[EventType] = None) -> List[BlackboardEvent]:
        """Retrieve all events, optionally filtered by EventType."""
        with self._lock:
            if event_type:
                return [e for e in self._events if e.event_type == event_type]
            return list(self._events)

    def get_unhandled_events(self, agent_name: str) -> List[BlackboardEvent]:
        """Fetch all events that this specific agent has not yet handled."""
        with self._lock:
            return [e for e in self._events if agent_name not in e.handled_by]

    def mark_handled(self, event_id: str, agent_name: str) -> None:
        """Mark an event as processed by a given agent and update persistence."""
        with self._lock:
            for event in self._events:
                if event.id == event_id and agent_name not in event.handled_by:
                    event.handled_by.append(agent_name)
                    conn = self._get_conn()
                    if conn:
                        try:
                            with conn:
                                conn.execute(
                                    "UPDATE events SET handled_by = ? WHERE id = ?",
                                    (json.dumps(event.handled_by), event.id),
                                )
                        finally:
                            conn.close()

    def add_asset(self, asset: HostAsset) -> None:
        """Index a discovered host or network asset, merging endpoints and ports."""
        with self._lock:
            key = asset.ip or asset.hostname or asset.id
            if key in self._assets:
                existing = self._assets[key]
                port_nums = {p.port for p in existing.ports}
                for p in asset.ports:
                    if p.port not in port_nums:
                        existing.ports.append(p)
                        port_nums.add(p.port)
                endpoint_urls = {ep.url for ep in existing.endpoints}
                for ep in asset.endpoints:
                    if ep.url not in endpoint_urls:
                        existing.endpoints.append(ep)
                        endpoint_urls.add(ep.url)
                saved_asset = existing
            else:
                self._assets[key] = asset
                saved_asset = asset

            conn = self._get_conn()
            if conn:
                try:
                    with conn:
                        conn.execute(
                            "INSERT OR REPLACE INTO assets VALUES (?, ?, ?, ?)",
                            (
                                saved_asset.id,
                                self.campaign_id,
                                key,
                                json.dumps(saved_asset.model_dump(mode="json")),
                            ),
                        )
                finally:
                    conn.close()

    def get_assets(self) -> List[HostAsset]:
        """Retrieve all discovered assets."""
        with self._lock:
            return list(self._assets.values())

    def add_finding(self, finding: Finding) -> None:
        """Store a vulnerability finding and persist to disk."""
        with self._lock:
            self._findings[finding.id] = finding
            conn = self._get_conn()
            if conn:
                try:
                    with conn:
                        conn.execute(
                            "INSERT OR REPLACE INTO findings VALUES (?, ?, ?)",
                            (
                                finding.id,
                                self.campaign_id,
                                json.dumps(finding.model_dump(mode="json")),
                            ),
                        )
                finally:
                    conn.close()

    def get_findings(self) -> List[Finding]:
        """Retrieve all stored findings."""
        with self._lock:
            return list(self._findings.values())

    def get_summary(self) -> Dict[str, Any]:
        """Generate a snapshot of the current mission state."""
        with self._lock:
            return {
                "campaign_id": self.campaign_id,
                "total_events": len(self._events),
                "total_assets": len(self._assets),
                "total_findings": len(self._findings),
                "findings_by_severity": {
                    sev: len([f for f in self._findings.values() if f.severity == sev])
                    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                },
            }


# Alias for stigmergic blackboard terminology
StigmergicBlackboard = Blackboard
