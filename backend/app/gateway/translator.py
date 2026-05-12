"""Protocol Translator - normalizes tool-specific formats to standardized schema."""
import re
import json
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from uuid import uuid4

from app.models.scan import Severity, ToolType
from app.models.finding import Finding, FindingSource


class ProtocolTranslator:
    """Translates tool-specific outputs into standardized platform findings."""
    
    SEVERITY_MAP = {
        "critical": Severity.CRITICAL, "crit": Severity.CRITICAL,
        "4": Severity.CRITICAL, "5": Severity.CRITICAL,
        "high": Severity.HIGH, "h": Severity.HIGH, "3": Severity.HIGH,
        "medium": Severity.MEDIUM, "med": Severity.MEDIUM, "m": Severity.MEDIUM,
        "2": Severity.MEDIUM,
        "low": Severity.LOW, "l": Severity.LOW, "1": Severity.LOW,
        "info": Severity.INFO, "informational": Severity.INFO,
        "note": Severity.INFO, "0": Severity.INFO, "none": Severity.INFO,
    }
    
    @staticmethod
    def normalize_severity(raw: Any) -> Severity:
        """Normalize any severity format to standardized enum."""
        raw_str = str(raw).lower().strip()
        return ProtocolTranslator.SEVERITY_MAP.get(raw_str, Severity.UNKNOWN)
    
    @staticmethod
    def extract_cvss(raw: Dict) -> Tuple[Optional[float], Optional[str]]:
        """Extract CVSS score and vector from raw data."""
        for key in ["cvss", "cvss_score", "cvss3_score", "cvss_base_score"]:
            val = raw.get(key)
            if val is not None:
                try:
                    score = float(val)
                    vector = raw.get(
                        f"{key}_vector", 
                        raw.get("cvss_vector", raw.get("cvss3_vector"))
                    )
                    return score, vector
                except (ValueError, TypeError):
                    pass
        return None, None
    
    @staticmethod
    def translate_burp_issue(issue: Dict, scan_id: str) -> Finding:
        """Translate a Burp Suite issue to standardized Finding."""
        sev = ProtocolTranslator.normalize_severity(
            issue.get("severity", issue.get("confidence", "info"))
        )
        cvss_score, cvss_vector = ProtocolTranslator.extract_cvss(issue)
        
        return Finding(
            id=str(uuid4()),
            title=issue.get("name", issue.get("title", "Burp Issue")),
            description=issue.get("description", issue.get("detail", "")),
            severity=sev,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            target=issue.get("host", ""),
            affected_endpoint=f"{issue.get('protocol', 'https')}://{issue.get('host', '')}{issue.get('path', '')}",
            sources=[FindingSource(tool=ToolType.BURPSUITE, scan_id=scan_id, raw_data=issue)],
            remediation=issue.get("remediation", issue.get("remediation_detail")),
            references=issue.get("references", []),
        )
    
    @staticmethod
    def translate_nessus_vuln(vuln: Dict, scan_id: str) -> Finding:
        """Translate a Nessus vulnerability to standardized Finding."""
        sev = ProtocolTranslator.normalize_severity(
            vuln.get("severity", vuln.get("risk_factor", "info"))
        )
        cvss_score, cvss_vector = ProtocolTranslator.extract_cvss({
            "cvss_score": vuln.get("cvss_base_score"),
            "cvss_vector": vuln.get("cvss_vector"),
        })
        
        return Finding(
            id=str(uuid4()),
            title=vuln.get("plugin_name", vuln.get("name", "Nessus Finding")),
            description=vuln.get("description", vuln.get("synopsis", "")),
            severity=sev,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            target=vuln.get("hostname", vuln.get("host", "")),
            affected_component=f"Port {vuln.get('port', 'unknown')} ({vuln.get('protocol', 'tcp')})",
            sources=[FindingSource(tool=ToolType.NESSUS, scan_id=scan_id, raw_data=vuln)],
            remediation=vuln.get("solution", vuln.get("remediation")),
            references=vuln.get("see_also", []),
        )
    
    @staticmethod
    def translate_nuclei_result(result: Dict, scan_id: str) -> Finding:
        """Translate a Nuclei result to standardized Finding."""
        sev = ProtocolTranslator.normalize_severity(
            result.get("severity", result.get("info", {}).get("severity", "info"))
        )
        info = result.get("info", {})
        
        return Finding(
            id=str(uuid4()),
            title=info.get("name", result.get("template-id", "Nuclei Finding")),
            description=info.get("description", ""),
            severity=sev,
            target=result.get("host", result.get("matched-at", "")),
            affected_endpoint=result.get("matched-at", ""),
            sources=[FindingSource(
                tool=ToolType.NUCLEI, scan_id=scan_id,
                raw_id=result.get("template-id"),
                raw_data=result,
            )],
            remediation=info.get("remediation", ""),
            references=info.get("reference", []),
        )
    
    @staticmethod
    def translate_metasploit_vuln(vuln: Dict, scan_id: str) -> Finding:
        """Translate a Metasploit vulnerability to standardized Finding."""
        sev = ProtocolTranslator.normalize_severity(
            vuln.get("severity", vuln.get("risk", "medium"))
        )
        
        return Finding(
            id=str(uuid4()),
            title=vuln.get("name", vuln.get("title", "Metasploit Finding")),
            description=vuln.get("description", vuln.get("abstract", "")),
            severity=sev,
            target=vuln.get("host", ""),
            affected_component=vuln.get("port", ""),
            sources=[FindingSource(
                tool=ToolType.METASPLOIT, scan_id=scan_id,
                raw_id=vuln.get("ref_id"),
                raw_data=vuln,
            )],
            remediation=vuln.get("solution", ""),
            references=vuln.get("refs", []),
        )
    
    @staticmethod
    def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
        """Deduplicate findings based on title + target similarity."""
        seen: Dict[str, List[Finding]] = {}
        
        for finding in findings:
            key = f"{finding.title.lower().strip()}:{finding.target.lower().strip()}"
            if key in seen:
                seen[key][0].duplicate_count += 1
                seen[key][0].is_deduplicated = True
                seen[key][0].sources.extend(finding.sources)
            else:
                seen[key] = [finding]
        
        return [v[0] for v in seen.values()]
