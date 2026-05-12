"""Classifies security tasks to determine the best approach."""
import logging
from typing import Dict, List, Optional, Tuple
from enum import Enum

from app.models.scan import ScanTask, ToolType

logger = logging.getLogger(__name__)


class TaskCategory(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_SCAN = "vulnerability_scan"
    WEB_APPLICATION = "web_application"
    NETWORK = "network"
    API_SECURITY = "api_security"
    CLOUD = "cloud"
    SOCIAL_ENGINEERING = "social_engineering"
    EXPLOITATION = "exploitation"
    COMPLIANCE = "compliance"
    THREAT_HUNTING = "threat_hunting"
    INCIDENT_RESPONSE = "incident_response"
    UNKNOWN = "unknown"


class TaskClassifier:
    """Classifies scan tasks into categories for optimal tool selection."""
    
    def __init__(self):
        self._classifiers = {
            # keyword-based classification rules
            "recon": TaskCategory.RECONNAISSANCE,
            "reconnaissance": TaskCategory.RECONNAISSANCE,
            "osint": TaskCategory.RECONNAISSANCE,
            "subdomain": TaskCategory.RECONNAISSANCE,
            "web": TaskCategory.WEB_APPLICATION,
            "website": TaskCategory.WEB_APPLICATION,
            "api": TaskCategory.API_SECURITY,
            "rest": TaskCategory.API_SECURITY,
            "network": TaskCategory.NETWORK,
            "port": TaskCategory.NETWORK,
            "vulnerability": TaskCategory.VULNERABILITY_SCAN,
            "vuln": TaskCategory.VULNERABILITY_SCAN,
            "nessus": TaskCategory.VULNERABILITY_SCAN,
            "exploit": TaskCategory.EXPLOITATION,
            "penetration": TaskCategory.EXPLOITATION,
            "cloud": TaskCategory.CLOUD,
            "aws": TaskCategory.CLOUD,
            "azure": TaskCategory.CLOUD,
            "gcp": TaskCategory.CLOUD,
            "compliance": TaskCategory.COMPLIANCE,
            "audit": TaskCategory.COMPLIANCE,
            "hipaa": TaskCategory.COMPLIANCE,
            "pci": TaskCategory.COMPLIANCE,
            "soc": TaskCategory.COMPLIANCE,
            "hunt": TaskCategory.THREAT_HUNTING,
            "threat": TaskCategory.THREAT_HUNTING,
            "incident": TaskCategory.INCIDENT_RESPONSE,
            "forensic": TaskCategory.INCIDENT_RESPONSE,
        }
    
    async def classify(self, task: ScanTask) -> TaskCategory:
        """Classify a scan task based on target, tools, and metadata."""
        
        # Check explicit category in metadata
        explicit = task.metadata.get("category", "").lower()
        if explicit:
            try:
                return TaskCategory(explicit)
            except ValueError:
                pass
        
        # Classify based on target type
        if task.target_type == "url" or task.target.startswith(("http://", "https://")):
            domain = task.target.split("://")[-1].split("/")[0]
            if "api" in domain or "api" in task.target.lower():
                return TaskCategory.API_SECURITY
            return TaskCategory.WEB_APPLICATION
        
        if task.target_type == "cidr" or "/" in task.target:
            return TaskCategory.NETWORK
        
        # Classify based on selected tools
        tools = set(task.tools)
        if ToolType.SHODAN in tools or ToolType.CENSYS in tools or ToolType.BBOT in tools:
            return TaskCategory.RECONNAISSANCE
        if ToolType.NESSUS in tools or ToolType.OPENVAS in tools:
            return TaskCategory.VULNERABILITY_SCAN
        if ToolType.METASPLOIT in tools:
            return TaskCategory.EXPLOITATION
        if ToolType.STACKHAWK in tools:
            return TaskCategory.API_SECURITY
        
        # Classify based on target string keywords
        target_lower = task.target.lower()
        for keyword, category in self._classifiers.items():
            if keyword in target_lower:
                return category
        
        # Default based on tool selection
        if not task.tools:
            return TaskCategory.RECONNAISSANCE
        
        return TaskCategory.UNKNOWN
