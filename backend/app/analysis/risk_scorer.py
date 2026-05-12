"""Risk scoring engine for findings and overall posture."""
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

from app.models.finding import Finding
from app.models.scan import Severity

logger = logging.getLogger(__name__)


@dataclass
class RiskScore:
    """Comprehensive risk score for a finding or collection."""
    overall_score: float  # 0-100
    likelihood: float     # 0-100
    impact: float         # 0-100
    confidence: float     # 0-100
    entropy: float        # 0-100 (uncertainty measure)
    factors: Dict[str, float]
    label: str


class RiskScorer:
    """Calculates risk scores using multiple factors and industry frameworks."""
    
    # CVSS-like risk matrix
    LIKELIHOOD_MAP = {
        Severity.CRITICAL: 80, Severity.HIGH: 65,
        Severity.MEDIUM: 45, Severity.LOW: 25,
        Severity.INFO: 5, Severity.UNKNOWN: 30,
    }
    
    IMPACT_MAP = {
        Severity.CRITICAL: 90, Severity.HIGH: 70,
        Severity.MEDIUM: 45, Severity.LOW: 20,
        Severity.INFO: 5, Severity.UNKNOWN: 35,
    }
    
    CONFIDENCE_MAP = {
        Severity.CRITICAL: 85, Severity.HIGH: 75,
        Severity.MEDIUM: 60, Severity.LOW: 40,
        Severity.INFO: 30, Severity.UNKNOWN: 20,
    }
    
    async def score_findings(self, findings: List[Finding]) -> Dict[str, float]:
        """Score individual findings and return risk results."""
        scores = {}
        for finding in findings:
            score = await self._calculate_single_score(finding)
            scores[finding.id] = score.overall_score
            finding.metadata["risk_score"] = score.overall_score
            finding.metadata["risk_label"] = score.label
        return scores
    
    async def score_posture(self, findings: List[Finding]) -> RiskScore:
        """Score overall security posture based on all findings."""
        if not findings:
            return RiskScore(0, 0, 0, 100, 0, {}, "excellent")
        
        individual_scores = []
        for f in findings:
            individual_scores.append(await self._calculate_single_score(f))
        
        # Aggregate
        overall = sum(s.overall_score for s in individual_scores) / len(individual_scores)
        likelihood = sum(s.likelihood for s in individual_scores) / len(individual_scores)
        impact = sum(s.impact for s in individual_scores) / len(individual_scores)
        
        # Confidence decreases with conflicting data
        scores_list = [s.overall_score for s in individual_scores]
        confidence = 100 - (max(scores_list) - min(scores_list)) / 2
        
        # Entropy (uncertainty) based on distribution
        from math import log
        n = len(scores_list)
        if n > 1:
            mean = sum(scores_list) / n
            entropy = sum((s - mean) ** 2 for s in scores_list) / n
            entropy = min(entropy / 100, 100)
        else:
            entropy = 0
        
        label = self._risk_label(overall)
        
        return RiskScore(
            overall_score=round(overall, 1),
            likelihood=round(likelihood, 1),
            impact=round(impact, 1),
            confidence=round(confidence, 1),
            entropy=round(entropy, 1),
            factors={},
            label=label,
        )
    
    async def _calculate_single_score(self, finding: Finding) -> RiskScore:
        """Calculate multi-factor risk score for a single finding."""
        severity = finding.severity if isinstance(finding.severity, Severity) else Severity.UNKNOWN
        
        # Base scores from severity
        likelihood = self.LIKELIHOOD_MAP.get(severity, 30)
        impact = self.IMPACT_MAP.get(severity, 35)
        confidence = self.CONFIDENCE_MAP.get(severity, 20)
        
        # Adjust for CVSS
        if finding.cvss_score:
            likelihood = min(likelihood + finding.cvss_score * 5, 95)
            impact = min(impact + finding.cvss_score * 3, 95)
            confidence = min(confidence + finding.cvss_score * 5, 95)
        
        # Adjust for duplicate count (confirmed)
        if finding.duplicate_count > 0:
            confidence = min(confidence + finding.duplicate_count * 5, 95)
        
        # Adjust for cross-tool confirmation
        unique_tools = {s.tool for s in finding.sources}
        if len(unique_tools) >= 2:
            confidence = min(confidence + 10, 95)
            likelihood = min(likelihood + 5, 95)
        
        # Calculate overall (CVSS-like formula)
        overall = round((impact * likelihood) / 100.0, 1)
        overall = min(max(overall, 0), 100)
        
        factors = {
            "severity_weight": self.LIKELIHOOD_MAP.get(severity, 30),
            "cvss_boost": finding.cvss_score or 0,
            "multi_tool_boost": 10 if len(unique_tools) >= 2 else 0,
            "duplicate_boost": finding.duplicate_count * 5,
        }
        
        return RiskScore(
            overall_score=overall,
            likelihood=round(likelihood, 1),
            impact=round(impact, 1),
            confidence=round(confidence, 1),
            entropy=0.0,
            factors=factors,
            label=self._risk_label(overall),
        )
    
    def _risk_label(self, score: float) -> str:
        if score >= 75: return "critical"
        elif score >= 55: return "high"
        elif score >= 35: return "medium"
        elif score >= 15: return "low"
        return "minimal"
