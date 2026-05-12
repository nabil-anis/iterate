"""Finding domain models."""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from .scan import Severity, ToolType


class FindingSource(BaseModel):
    """Source information for a finding."""
    tool: ToolType
    scan_id: str
    raw_id: Optional[str] = None
    raw_severity: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None


class Finding(BaseModel):
    """A security finding from one or more tools."""
    id: str
    title: str
    description: str
    severity: Severity
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    
    target: str
    affected_component: Optional[str] = None
    affected_endpoint: Optional[str] = None
    
    sources: List[FindingSource]
    is_deduplicated: bool = False
    duplicate_count: int = 1
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    
    # Compliance mappings
    compliance_mappings: Dict[str, List[str]] = Field(default_factory=dict)
    
    status: str = "open"  # open, in_progress, resolved, false_positive, accepted_risk
    assigned_to: Optional[str] = None
    
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    
    metadata: Dict[str, Any] = Field(default_factory=dict)
