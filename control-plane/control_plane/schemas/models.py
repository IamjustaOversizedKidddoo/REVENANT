"""
REVENANT — Unified Platform Data Models (Pydantic v2)
Standard data schemas for targets, discovered assets, findings, tasks, and evidence.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AssetType(str, Enum):
    IP = "IP"
    CIDR = "CIDR"
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    URL = "URL"
    PORT = "PORT"
    ENDPOINT = "ENDPOINT"
    REPO = "REPO"
    FILE = "FILE"
    CLOUD_ACCOUNT = "CLOUD_ACCOUNT"
    CONTAINER_IMAGE = "CONTAINER_IMAGE"
    IAC_CONFIG = "IAC_CONFIG"
    IDENTITY_ACCOUNT = "IDENTITY_ACCOUNT"
    IDENTITY_DOMAIN = "IDENTITY_DOMAIN"
    CERT_TEMPLATE = "CERT_TEMPLATE"
    AI_ENDPOINT = "AI_ENDPOINT"
    AI_MODEL = "AI_MODEL"
    MOBILE_APP = "MOBILE_APP"
    MOBILE_PACKAGE = "MOBILE_PACKAGE"
    EMULATION_HOST = "EMULATION_HOST"
    DETECTION_GAP = "DETECTION_GAP"


class CodeLocation(BaseModel):
    """Specific source code or repository location where a vulnerability occurs."""
    file_path: str
    start_line: int
    end_line: Optional[int] = None
    snippet: Optional[str] = None
    commit_hash: Optional[str] = None
    author: Optional[str] = None


class Target(BaseModel):
    """Declared assessment target."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    raw_input: str
    target_type: AssetType
    normalized: str
    in_scope: bool = True
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PortInfo(BaseModel):
    """Network port scan result."""
    port: int
    protocol: str = "tcp"  # "tcp" | "udp"
    state: str = "open"    # "open" | "filtered" | "closed"
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None


class EndpointInfo(BaseModel):
    """Web / HTTP endpoint discovery information."""
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    title: Optional[str] = None
    tech_stack: List[str] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    parameters: List[str] = Field(default_factory=list)
    forms: List[Dict[str, Any]] = Field(default_factory=list)


class HostAsset(BaseModel):
    """Discovered network host or domain asset."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ip: Optional[str] = None
    hostname: Optional[str] = None
    ports: List[PortInfo] = Field(default_factory=list)
    endpoints: List[EndpointInfo] = Field(default_factory=list)
    os: Optional[str] = None
    cloud_provider: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Finding(BaseModel):
    """Standardized vulnerability finding across all 66 security tools."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    severity: Severity
    target: str
    tool: str
    cve: Optional[str] = None
    cwe: Optional[str] = None
    cvss_score: Optional[float] = None
    mitre_attack_ids: List[str] = Field(default_factory=list)
    owasp_category: Optional[str] = None
    endpoint: Optional[str] = None
    code_location: Optional[CodeLocation] = None
    secret_type: Optional[str] = None
    reproduction_steps: Optional[str] = None
    evidence: Optional[str] = None
    request_proof: Optional[str] = None
    response_proof: Optional[str] = None
    remediation: Optional[str] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    verified: bool = False
    verified_valid: bool = False
    false_positive: bool = False


class TaskStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    SCOPE_BLOCKED = "SCOPE_BLOCKED"


class Task(BaseModel):
    """Unit of work dispatched to a tool adapter."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str
    target: str
    params: Dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = 300
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
