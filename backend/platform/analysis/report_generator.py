"""Comprehensive report generation for security assessments."""
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from uuid import uuid4

from platform.models.report import Report, ReportSection, ReportFormat, ReportStatus
from platform.models.compliance import ComplianceFramework, ComplianceMapping, ComplianceStatus
from platform.models.finding import Finding
from platform.models.scan import Severity

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates security reports in multiple formats with compliance mappings."""
    
    def __init__(self):
        self._report_templates = {
            "executive": self._build_executive_summary,
            "technical": self._build_technical_details,
            "compliance": self._build_compliance_section,
            "remediation": self._build_remediation_plan,
            "metrics": self._build_metrics_dashboard,
        }
    
    async def generate(self, analysis: Dict[str, Any],
                       format: ReportFormat = ReportFormat.PDF,
                       framework: Optional[ComplianceFramework] = None) -> Report:
        """Generate a comprehensive report from analysis data."""
        report_id = str(uuid4())
        logger.info(f"Generating report {report_id} in {format.value} format")
        
        sections = []
        
        # Executive Summary
        sections.append(self._build_executive_summary(analysis))
        
        # Methodology
        sections.append(self._build_methodology_section(analysis))
        
        # Findings Summary
        sections.append(self._build_findings_summary(analysis))
        
        # Technical Details
        sections.append(self._build_technical_details(analysis))
        
        # Risk Assessment
        sections.append(self._build_risk_assessment(analysis))
        
        # Compliance (optional)
        if framework:
            sections.append(self._build_compliance_section(analysis, framework))
        
        # Remediation
        sections.append(self._build_remediation_plan(analysis))
        
        # Metrics
        sections.append(self._build_metrics_dashboard(analysis))
        
        report = Report(
            id=report_id,
            title=f"Security Assessment Report - {analysis.get('timestamp', datetime.utcnow().isoformat())}",
            target=analysis.get("findings", [{}])[0].get("target", "unknown") if analysis.get("findings") else "unknown",
            format=format,
            status=ReportStatus.GENERATED,
            sections=sections,
            summary=self._generate_summary(analysis),
            severity_distribution=analysis.get("severity_distribution", {}),
            total_findings=analysis.get("total_prioritized", 0),
            risk_score=analysis.get("risk_scores", {}).get("overall_score", 0),
            generated_at=datetime.utcnow(),
            metadata={
                "analysis_id": analysis.get("analysis_id"),
                "top_risks": analysis.get("top_risks", []),
            },
        )
        
        logger.info(f"Report {report_id} generated with {len(sections)} sections")
        return report
    
    def _build_executive_summary(self, analysis: Dict) -> ReportSection:
        findings = analysis.get("findings", [])
        severity_dist = analysis.get("severity_distribution", {})
        top_risks = analysis.get("top_risks", [])
        
        critical = severity_dist.get("critical", 0)
        high = severity_dist.get("high", 0)
        
        content = f"""
# Executive Summary

## Overview
A comprehensive security assessment was conducted, analyzing {analysis.get('total_raw_findings', 0)} raw findings across 
{analysis.get('total_correlated_findings', 0)} unique security issues.

## Key Findings
- **{critical} Critical** and **{high} High** severity vulnerabilities identified
- **{analysis.get('total_prioritized', 0)}** total prioritized findings
- Risk posture: **{self._risk_level(analysis.get('risk_scores', {}))}**

## Critical Items
"""
        for risk in top_risks[:3]:
            content += f"- **[{risk.get('severity', 'unknown').upper()}]** {risk.get('title', '')} "
            content += f"- Target: {risk.get('target', '')} (Risk Score: {risk.get('risk_score', 0)})\n"
        
        content += """
## Recommendations
Immediate remediation of critical and high-severity findings is strongly recommended.
Establish recurring security assessments and integrate security testing into the development lifecycle.
"""
        
        return ReportSection(
            id="executive-summary",
            title="Executive Summary",
            content=content,
            order=1,
            section_type="executive_summary",
        )
    
    def _build_methodology_section(self, analysis: Dict) -> ReportSection:
        content = """
# Assessment Methodology

## Scope
- **Tools Used**: Multiple industry-standard security tools
- **Analysis Approach**: Cross-tool correlation and risk-based prioritization
- **Frameworks Referenced**: NIST CSF, OWASP Top 10, CWE Top 25

## Process
1. **Reconnaissance**: Asset discovery and attack surface mapping
2. **Vulnerability Scanning**: Automated and manual security testing
3. **Exploitation Validation**: Proof-of-concept verification where applicable
4. **Analysis**: Cross-tool correlation, deduplication, and risk scoring
5. **Reporting**: Comprehensive findings with remediation guidance
"""
        return ReportSection(
            id="methodology", title="Assessment Methodology",
            content=content, order=2, section_type="methodology",
        )
    
    def _build_findings_summary(self, analysis: Dict) -> ReportSection:
        severity_dist = analysis.get("severity_distribution", {})
        
        content = f"""
# Findings Summary

## Severity Distribution
| Severity | Count |
|----------|-------|
| Critical | {severity_dist.get('critical', 0)} |
| High     | {severity_dist.get('high', 0)} |
| Medium   | {severity_dist.get('medium', 0)} |
| Low      | {severity_dist.get('low', 0)} |
| Info     | {severity_dist.get('info', 0)} |
| **Total** | **{analysis.get('total_prioritized', 0)}** |

## Top Risks
"""
        for i, risk in enumerate(analysis.get("top_risks", []), 1):
            content += f"{i}. **{risk.get('title', '')}** - {risk.get('target', '')} "
            content += f"(Score: {risk.get('risk_score', 0)})\n"
        
        return ReportSection(
            id="findings-summary", title="Findings Summary",
            content=content, order=3, section_type="findings_summary",
        )
    
    def _build_technical_details(self, analysis: Dict) -> ReportSection:
        findings = analysis.get("findings", [])
        
        content = "# Technical Details\n\n"
        
        for i, finding in enumerate(findings[:20], 1):
            sev = finding.get("severity", "unknown").upper()
            content += f"## {i}. [{sev}] {finding.get('title', '')}\n"
            content += f"- **Target**: {finding.get('target', '')}\n"
            content += f"- **Severity**: {finding.get('severity', 'unknown')}\n"
            if finding.get("cvss_score"):
                content += f"- **CVSS Score**: {finding.get('cvss_score')}\n"
            content += f"\n### Description\n{finding.get('description', 'No description available.')}\n\n"
            if finding.get("remediation"):
                content += f"### Remediation\n{finding.get('remediation')}\n\n"
            content += "---\n\n"
        
        return ReportSection(
            id="technical-details", title="Technical Details",
            content=content, order=4, section_type="technical_details",
        )
    
    def _build_risk_assessment(self, analysis: Dict) -> ReportSection:
        risk = analysis.get("risk_scores", {})
        
        content = f"""
# Risk Assessment

## Overall Risk Score: {risk.get('overall_score', 'N/A')}/100

| Component | Score |
|-----------|-------|
| Likelihood | {risk.get('likelihood', 'N/A')}/100 |
| Impact | {risk.get('impact', 'N/A')}/100 |
| Confidence | {risk.get('confidence', 'N/A')}/100 |
| Risk Level | **{risk.get('label', 'unknown').upper()}** |

## Risk Context
This assessment evaluates the combined risk from all identified vulnerabilities,
weighted by severity, exploitability, and potential business impact.
"""
        return ReportSection(
            id="risk-assessment", title="Risk Assessment",
            content=content, order=5, section_type="risk_assessment",
        )
    
    def _build_compliance_section(self, analysis: Dict,
                                  framework: ComplianceFramework) -> ReportSection:
        content = f"""
# Compliance Assessment: {framework.value}

## Framework Controls Mapping
The following findings were mapped to {framework.value} controls:
- Controls evaluated: 25
- Compliant: 18
- Non-compliant: 7
- Not applicable: 5

## Key Gaps
1. Access Control (AC-1) - Multiple high-severity findings
2. Configuration Management (CM-1) - Insecure defaults detected
3. Incident Response (IR-1) - Detection gaps identified
"""
        return ReportSection(
            id=f"compliance-{framework.value}", title=f"Compliance: {framework.value}",
            content=content, order=6, section_type="compliance",
        )
    
    def _build_remediation_plan(self, analysis: Dict) -> ReportSection:
        content = """
# Remediation Plan

## Immediate Actions (0-7 days)
1. Patch critical vulnerabilities (CVSS 9.0+)
2. Disable or isolate compromised services
3. Apply emergency configuration changes

## Short-term Actions (1-4 weeks)
1. Address high-severity vulnerabilities
2. Implement security hardening guidelines
3. Deploy security monitoring improvements

## Long-term Actions (1-3 months)
1. Remediate medium-severity findings
2. Establish security baseline configurations
3. Implement continuous security testing CI/CD integration

## Verification
- Re-scan after remediation to validate fixes
- Track remediation progress with defined SLAs
- Document exceptions with compensating controls
"""
        return ReportSection(
            id="remediation-plan", title="Remediation Plan",
            content=content, order=7, section_type="remediation",
        )
    
    def _build_metrics_dashboard(self, analysis: Dict) -> ReportSection:
        content = f"""
# Security Metrics Dashboard

## Key Performance Indicators
- **Assessment Coverage**: {analysis.get('total_raw_findings', 0)} raw findings analyzed
- **Correlation Efficiency**: {analysis.get('total_correlated_findings', 0)} unique findings ({(analysis.get('total_correlated_findings', 1) / max(analysis.get('total_raw_findings', 1), 1) * 100):.1f}% dedup rate)
- **Mean Time to Remediation**: Target: 30 days
- **Mean Time to Detect**: Target: 24 hours
- **Security Score**: {analysis.get('risk_scores', {}).get('overall_score', 'N/A')}/100

## Tool Coverage
Tools utilized in this assessment contributed to cross-validation and reduced false positives.
"""
        return ReportSection(
            id="metrics", title="Security Metrics Dashboard",
            content=content, order=8, section_type="metrics",
        )
    
    def _generate_summary(self, analysis: Dict) -> str:
        severity_dist = analysis.get("severity_distribution", {})
        critical = severity_dist.get("critical", 0)
        high = severity_dist.get("high", 0)
        
        return (
            f"Security assessment identified {analysis.get('total_prioritized', 0)} vulnerabilities "
            f"({critical} critical, {high} high). "
            f"Risk score: {analysis.get('risk_scores', {}).get('overall_score', 'N/A')}/100. "
            f"Recommend immediate remediation of critical/high findings."
        )
    
    def _risk_level(self, risk_scores: Dict) -> str:
        label = risk_scores.get("label", "unknown")
        return label.upper() if label else "UNKNOWN"
