"""Central intelligence repository for threat data."""
import logging
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta
from uuid import uuid4
from dataclasses import dataclass, field

from platform.models.scan import Severity

logger = logging.getLogger(__name__)


@dataclass
class ThreatIntel:
    """Threat intelligence entry."""
    id: str
    source: str
    indicator_type: str  # ip, domain, hash, url, cve
    indicator: str
    confidence: float  # 0-1
    severity: Severity
    tags: List[str] = field(default_factory=list)
    description: str = ""
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    related_iocs: List[str] = field(default_factory=list)
    tlp: str = "AMBER"  # Traffic Light Protocol


class IntelligenceRepository:
    """Central repository for threat intelligence data."""
    
    def __init__(self):
        self._intel: Dict[str, ThreatIntel] = {}
        self._indicators: Dict[str, List
