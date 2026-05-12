"""Scan-related domain models."""
from enum import Enum
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PARTIAL = "partial"


class ToolType(str, Enum):
    PENTESTGPT = "pentestgpt"
    PENLIGENT = "penligent"
    NODEZERO = "nodezero"
    BURPSUITE = "burpsuite"
    METASPLOIT = "metasploit"
    NESSUS = "nessus"
    OPENVAS = "openvas"
    STACKHAWK = "stackhawk"
    PYRIT = "pyrit"
    SHODAN = "shodan"
    CENSYS = "censys"
    BBOT = "bbot"
    NUCLEI = "nuclei"
    HORIZON3 = "horizon3"
    CUSTOM = "custom"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class ScanTask(BaseModel):
    """A scan task submitted to the platform."""
    id: str
    target: str
    target_type: str = Field(default="domain", description="domain, ip, url, cidr")
    tools: List[ToolType]
    status: ScanStatus = ScanStatus.PENDING
    priority: int = Field(default=5, ge=1, le=10)
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress: float = Field(default=0.0, ge=0.0, le=100.0)
    error: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Result from a completed scan."""
    scan_id: str
    tool: ToolType
    status: ScanStatus
    findings_count: int = 0
    raw_output: Optional[str] = None
    summary: Optional[str] = None
    duration_seconds: Optional[float] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
