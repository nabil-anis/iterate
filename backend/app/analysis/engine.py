"""Unified analysis engine for cross-tool finding correlation and decision making."""
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from uuid import uuid4

from app.models.finding import Finding, FindingSource
from app.models.scan import Severity, ScanResult, ScanStatus
from app.models.report import Report, ReportSection, ReportFormat
from app.models.compliance import ComplianceMapping, ComplianceFramework
from .correlation import FindingCorrelator
from .prioritizer import FindingPrioritizer
from .report_generator import ReportGenerator
from .risk_scorer import RiskScorer

logger = logging.getLogger(__name__)


class AnalysisEngine:
    """Central analysis engine that correlates, prioritizes, and enriches findings."""
    
    def __init__(self):
        self.correlator = FindingCorrelator()
        self.prioritizer = FindingPrioritizer()
        self.report_generator = ReportGenerator()
        self.risk_scorer = RiskScorer()
        self._analysis_cache: Dict[str, Dict] = {}
    
    async def analyze_scan_results(self, results: List[ScanResult]) -> Dict[str, Any]:
        """Run full analysis pipeline on scan results."""
        analysis_id = str(uuid4())
        logger.info(f"Starting analysis {analysis_id} on {len(results)} scan results")
        
        # Step 1: Extract and normalize findings
        all_findings = []
        for result in results:
            if result.status == ScanStatus.COMPLETED and result.findings:
                all_findings.extend(result.findings)
        
        logger.info(f"Extracted {len(all_findings)} raw findings")
        
        # Step 2: Correlate findings across tools
        correlated = await self.correlator.correlate(all_findings)
        logger.info(f"Correlation produced {len(correlated)} unique findings")
        
        # Step 3: Prioritize findings
        prioritized = await self.prioritizer.prioritize(correlated, results)
        
        # Step 4: Score risks
        risk_scores = await self.risk_scorer.score_findings(prioritized)
        
        # Step 5: Generate analysis summary
        analysis = {
            "analysis_id": analysis_id,
            "timestamp": datetime.utcnow().isoformat(),
            "total_raw_findings": len(all_findings),
            "total_correlated_findings": len(correlated),
            "total_prioritized": len(prioritized),
            "severity_distribution": self._severity_distribution(prioritized),
            "risk_scores": risk_scores,
            "findings": [f.dict() for f in prioritized],
            "top_risks": self._extract_top_risks(prioritized, risk_scores),
            "recommendations": self._generate_recommendations(prioritized, risk_scores),
        }
        
        self._analysis_cache[analysis_id] = analysis
        return analysis
    
    async def generate_report(self, analysis: Dict[str, Any], 
                              format: ReportFormat = ReportFormat.PDF,
                              framework: Optional[ComplianceFramework] = None) -> Report:
        """Generate a comprehensive security report."""
        return await self.report_generator.generate(analysis, format, framework)
    
    async def analyze_finding_cross_reference(self, finding_id: str) -> Dict[str, Any]:
        """Deep analysis of a specific finding with cross-references."""
        analysis = {
            "finding_id": finding_id,
            "related_cves": [],
            "exploit_availability": False,
            "mitre_attack_techniques": [],
            "similar_findings": [],
            "remediation_priority": "high",
        }
        return analysis
    
    def _severity_distribution(self, findings: List[Finding]) -> Dict[str, int]:
        dist = {}
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            dist[sev] = dist.get(sev, 0) + 1
        return dist
    
    def _extract_top_risks(self, findings: List[Finding], 
                          risk_scores: Dict[str, float], top_n: int = 5) -> List[Dict]:
        scored = []
        for f in findings:
            score = risk_scores.get(f.id, 0.0)
            scored.append((score, f))
        scored.sort(key=lambda x: x[0], reverse=True)
        
        return [
            {
                "finding_id": f.id,
                "title": f.title,
                "target": f.target,
                "risk_score": score,
                "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
            }
            for score, f in scored[:top_n]
        ]
    
    def _generate_recommendations(self, findings: List[Finding],
                                 risk_scores: Dict[str, float]) -> List[str]:
        recommendations = []
        
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        
        if critical_count > 0:
            recommendations.append(
                f"Address {critical_count} critical findings immediately - "
                "these represent active compromise or high-confidence vulnerabilities"
            )
        if high_count > 3:
            recommendations.append(
                "High volume of high-severity findings suggests systemic security gaps "
                "requiring architectural remediation"
            )
        
        # Tool-specific recommendations
        tools_used = set()
        for f in findings[:20]:
            for s in f.sources:
                if hasattr(s, 'tool'):
                    tools_used.add(s.tool.value if hasattr(s.tool, 'value') else str(s.tool))
        
        if "nessus" in tools_used or "openvas" in tools_used:
            recommendations.append(
                "Schedule recurring vulnerability scans and establish a patch management SLA"
            )
        if "burpsuite" in tools_used or "stackhawk" in tools_used:
            recommendations.append(
                "Integrate DAST scanning into CI/CD pipeline for continuous web/API security"
            )
        
        recommendations.append(
            "Establish a remediation tracking process with defined SLAs per severity level"
        )
        
        return recommendations
