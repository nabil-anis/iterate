"""Report generation models."""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from .scan import Severity


class ReportSection(BaseModel):
    """A section within a security report."""
    title: str
    content: str
    section_type: str  # executive_summary, methodology, findings, metrics, compliance, remediation
    findings_ids: List[str] = Field(default_factory=list)
    order: int = 0


class Report(BaseModel):
    """A comprehensive security report."""
    id: str
    title: str
    report_type: str  # vapt, compliance, executive, technical, soc
    scan_ids: List[str] = Field(default_factory=list)
    sections: List[ReportSection] = Field(default_factory=list)
    status: str = "draft"  # draft, generated, reviewed, final
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    generated_at: Optional[datetime] = None
    framework: Optional[str] = None
    
    # Metrics
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    metadata: Dict[str, Any] = Field(default_factory=dict)
