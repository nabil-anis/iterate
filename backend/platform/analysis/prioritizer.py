"""Intelligent finding prioritization engine."""
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict

from platform.models.finding import Finding, FindingSource
from platform.models.scan import Severity, ScanResult

logger = logging.getLogger(__name__)


class FindingPrioritizer:
    """Prioritizes findings using contextual and risk-based scoring."""
    
    # Base weights for scoring
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 40,
        Severity.HIGH: 25,
        Severity.MEDIUM: 10,
        Severity.LOW: 3,
        Severity.INFO: 0,
        Severity.UNKNOWN: 5,
    }
    
    TOOL_RELIABILITY_SCORES = {
        "nessus": 0.85, "openvas": 0.70, "burpsuite": 0.80,
        "metasploit": 0.90, "nuclei": 0.85, "shodan": 0.75,
        "censys": 0.70, "bbot": 0.65, "pentestgpt": 0.60,
        "stackhawk": 0.80, "pirit": 0.75, "nodezero": 0.85,
    }
    
    def __init__(self):
        self._priority_cache: Dict[str, float] = {}
    
    async def prioritize(self, findings: List[Finding], 
                        scan_results: Optional[List[ScanResult]] = None) -> List[Finding]:
        """Prioritize findings by contextual risk scoring."""
        if not findings:
            return []
        
        scored = []
        for finding in findings:
            priority_score = await self._calculate_priority_score(finding, scan_results)
            scored.append((priority_score, finding))
        
        scored.sort(key=lambda x: x[0], reverse=True)
        
        # Assign priority rankings
        prioritized = []
        for rank, (score, finding) in enumerate(scored, 1):
            finding.metadata["priority_score"] = score
            finding.metadata["priority_rank"] = rank
            finding.metadata["priority_label"] = self._priority_label(score)
            prioritized.append(finding)
        
        logger.info(f"Prioritized {len(prioritized)} findings")
        return prioritized
    
    async def _calculate_priority_score(self, finding: Finding,
                                        scan_results: Optional[List[ScanResult]] = None) -> float:
        """Calculate comprehensive priority score for a finding."""
        score = 0.0
        
        # 1. Base severity score
        sev_key = finding.severity if isinstance(finding.severity, Severity) else Severity.UNKNOWN
        score += self.SEVERITY_WEIGHTS.get(sev_key, 5)
        
        # 2. CVSS boost
        if finding.cvss_score:
            cvss_contribution = min(finding.cvss_score * 8, 30)
            score += cvss_contribution
        
        # 3. Tool reliability factor
        max_reliability = 0.0
        for source in finding.sources:
            tool_name = source.tool.value if hasattr(source.tool, 'value') else str(source.tool)
            reliability = self.TOOL_RELIABILITY_SCORES.get(tool_name.lower(), 0.5)
            max_reliability = max(max_reliability, reliability)
        score *= max_reliability
        
        # 4. Multi-source confirmation bonus
        unique_tools = set()
        for source in finding.sources:
            t_name = source.tool.value if hasattr(source.tool, 'value') else str(source.tool)
            unique_tools.add(t_name)
        
        if len(unique_tools) >= 3:
            score *= 1.5  # 50% boost for findings confirmed by 3+ tools
        elif len(unique_tools) >= 2:
            score *= 1.25  # 25% boost for cross-tool confirmation
        
        # 5. Exploit availability boost
        if finding.metadata.get("exploit_available"):
            score *= 1.3
        
        # 6. Affected count boost
        affected_count = finding.metadata.get("affected_count", 1)
        if affected_count > 1:
            score *= min(1.0 + (affected_count - 1) * 0.1, 2.0)
        
        # 7. Age decay (newer = higher priority)
        if finding.metadata.get("scan_timestamp"):
            try:
                scan_time = datetime.fromisoformat(finding.metadata["scan_timestamp"])
                age_hours = (datetime.utcnow() - scan_time).total_seconds() / 3600
                if age_hours > 48:
                    score *= 0.9  # Slight decay for older findings
            except (ValueError, TypeError):
                pass
        
        return round(score, 2)
    
    def _priority_label(self, score: float) -> str:
        """Get human-readable priority label."""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 35:
            return "medium"
        elif score >= 15:
            return "low"
        return "info"
    
    def get_priority_summary(self, findings: List[Finding]) -> Dict[str, int]:
        """Get summary of priority distribution."""
        summary = defaultdict(int)
        for f in findings:
            label = f.metadata.get("priority_label", "unknown")
            summary[label] += 1
        return dict(summary)
