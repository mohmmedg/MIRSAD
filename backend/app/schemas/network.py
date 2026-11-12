"""Structured network-scan output."""
from datetime import datetime
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field

class ScanStatus(str, Enum):
    CREATED = "created"
    QUEUED = "queued"
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"

class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"

class ScriptResult(BaseModel):
    script_id: str
    output: str = ""

class PortInfo(BaseModel):
    port: int
    protocol: str = Field(description="tcp or udp")
    state: PortState
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    cpe: list[str] = Field(default_factory=list)
    scripts: list[ScriptResult] = Field(default_factory=list)

class OSMatch(BaseModel):
    name: str
    accuracy: int = Field(description="confidence 0-100")

class NetworkScanResult(BaseModel):
    scan_id: str
    module: str = "network"
    target: str
    scan_type: str
    status: ScanStatus
    started_at: datetime
    finished_at: datetime | None = None
    duration_seconds: float | None = None

    host_up: bool | None = None
    host_count: int = 0
    addresses: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    open_ports: list[PortInfo] = Field(default_factory=list)
    filtered_ports_count: int = 0
    closed_ports_count: int = 0
    os_matches: list[OSMatch] = Field(default_factory=list)
    host_scripts: list[ScriptResult] = Field(default_factory=list)
    traceroute: list[dict[str, Any]] = Field(default_factory=list)
    scan_warnings: list[str] = Field(default_factory=list)
    coverage: dict[str, Any] = Field(default_factory=dict)

    error_message: str | None = None
    raw_nmap_command: str | None = None
