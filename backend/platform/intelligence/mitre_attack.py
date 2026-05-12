"""MITRE ATT&CK framework mapping and analysis."""
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class MitreTechnique:
    """MITRE ATT&CK technique."""
    id: str  # TXXXX
    name: str
    tactic: str  # TAXXXX
    tactic_name: str
    description: str = ""
    detection: str = ""
    mitigation: str = ""
    platforms: List[str] = field(default_factory=list)
    permissions_required: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    sub_techniques: List[str] = field(default_factory=list)


@dataclass
class MitreTactic:
    """MITRE ATT&CK tactic."""
    id: str  # TAXXXX
    name: str
    description: str = ""
    techniques: List[str] = field(default_factory=list)


class MitreAttackMapper:
    """Maps findings and behaviors to MITRE ATT&CK framework."""
    
    # Core MITRE ATT&CK v14 techniques mapping
    TECHNIQUES: Dict[str, MitreTechnique] = {
        "T1190": MitreTechnique(
            id="T1190", name="Exploit Public-Facing Application",
            tactic="TA0001", tactic_name="Initial Access",
            description="Adversaries exploit public-facing applications for initial access",
            platforms=["Linux", "Windows", "macOS", "Network", "Containers"],
            detection="Monitor application logs for exploit signatures",
            mitigation="Keep applications patched and use WAF",
        ),
        "T1078": MitreTechnique(
            id="T1078", name="Valid Accounts",
            tactic="TA0001", tactic_name="Initial Access",
            platforms=["Linux", "Windows", "macOS", "Cloud", "Network"],
        ),
        "T1059": MitreTechnique(
            id="T1059", name="Command and Scripting Interpreter",
            tactic="TA0002", tactic_name="Execution",
            platforms=["Linux", "Windows", "macOS", "Network", "Containers"],
        ),
        "T1505": MitreTechnique(
            id="T1505", name="Server Software Component",
            tactic="TA0003", tactic_name="Persistence",
            platforms=["Linux", "Windows", "macOS"],
        ),
        "T1098": MitreTechnique(
            id="T1098", name="Account Manipulation",
            tactic="TA0003", tactic_name="Persistence",
        ),
        "T1078.003": MitreTechnique(
            id="T1078.003", name="Local Accounts",
            tactic="TA0003", tactic_name="Persistence",
        ),
        "T1068": MitreTechnique(
            id="T1068", name="Exploitation for Privilege Escalation",
            tactic="TA0004", tactic_name="Privilege Escalation",
            platforms=["Linux", "Windows", "macOS"],
        ),
        "T1134": MitreTechnique(
            id="T1134", name="Access Token Manipulation",
            tactic="TA0004", tactic_name="Privilege Escalation",
        ),
        "T1003": MitreTechnique(
            id="T1003", name="OS Credential Dumping",
            tactic="TA0006", tactic_name="Credential Access",
            detection="Monitor LSASS access, event ID 4663",
            mitigation="Enable Credential Guard, limit privileged accounts",
        ),
        "T1552": MitreTechnique(
            id="T1552", name="Unsecured Credentials",
            tactic="TA0006", tactic_name="Credential Access",
        ),
        "T1046": MitreTechnique(
            id="T1046", name="Network Service Scanning",
            tactic="TA0007", tactic_name="Discovery",
            detection="Monitor for port scans and service enumeration",
            mitigation="Restrict network access with firewalls",
        ),
        "T1082": MitreTechnique(
            id="T1082", name="System Information Discovery",
            tactic="TA0007", tactic_name="Discovery",
        ),
        "T1083": MitreTechnique(
            id="T1083", name="File and Directory Discovery",
            tactic="TA0007", tactic_name="Discovery",
        ),
        "T1210": MitreTechnique(
            id="T1210", name="Exploitation of Remote Services",
            tactic="TA0008", tactic_name="Lateral Movement",
        ),
        "T1021": MitreTechnique(
            id="T1021", name="Remote Services",
            tactic="TA0008", tactic_name="Lateral Movement",
        ),
        "T1041": MitreTechnique(
            id="T1041", name="Exfiltration Over C2 Channel",
            tactic="TA0010", tactic_name="Exfiltration",
        ),
        "T1567": MitreTechnique(
            id="T1567", name="Exfiltration Over Web Service",
            tactic="TA0010", tactic_name="Exfiltration",
        ),
        "T1071": MitreTechnique(
            id="T1071", name="Application Layer Protocol",
            tactic="TA0011", tactic_name="Command and Control",
            detection="Monitor for unusual protocol use",
            mitigation="Network segmentation, protocol filtering",
        ),
        "T1573": MitreTechnique(
            id="T1573", name="Encrypted Channel",
            tactic="TA0011", tactic_name="Command and Control",
        ),
        "T1490": MitreTechnique(
            id="T1490", name="Inhibit System Recovery",
            tactic="TA0040", tactic_name="Impact",
            detection="Monitor volume shadow copy deletion",
            mitigation="Maintain offline backups",
        ),
    }
    
    TACTICS: Dict[str, MitreTactic] = {
        "TA0001": MitreTactic(id="TA0001", name="Initial Access"),
        "TA0002": MitreTactic(id="TA0002", name="Execution"),
        "TA0003": MitreTactic(id="TA0003", name="Persistence"),
        "TA0004": MitreTactic(id="TA0004", name="Privilege Escalation"),
        "TA0005": MitreTactic(id="TA0005", name="Defense Evasion"),
        "TA0006": MitreTactic(id="TA0006", name="Credential Access"),
        "TA0007": MitreTactic(id="TA0007", name="Discovery"),
        "TA0008": MitreTactic(id="TA0008", name="Lateral Movement"),
        "TA0009": MitreTactic(id="TA0009", name="Collection"),
        "TA0010": MitreTactic(id="TA0010", name="Exfiltration"),
        "TA0011": MitreTactic(id="TA0011", name="Command and Control"),
        "TA0040": MitreTactic(id="TA0040", name="Impact"),
    }
    
    def __init__(self):
        self._technique_cache: Dict[str, Dict] = {}
    
    async def map_finding(self, finding: Dict) -> Dict:
        """Map a finding to MITRE ATT&CK techniques."""
        title = finding.get("title", "").lower()
        description = finding.get("description", "").lower()
        combined = f"{title} {description}"
        
        matched_techniques = []
        
        for tech_id, technique in self.TECHNIQUES.items():
            # Check for keyword matches
            tech_keywords = technique.name.lower().split()
            if any(kw in combined for kw in tech_keywords):
                tactic = self.TACTICS.get(technique.tactic)
                matched_techniques.append({
                    "technique_id": technique.id,
                    "technique_name": technique.name,
                    "tactic_id": technique.tactic,
                    "tactic_name": tactic.name if tactic else "Unknown",
                    "confidence": 0.7,
                })
        
        # Additional CVE-to-technique mapping
        import re
        cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', combined, re.IGNORECASE)
        for cve_id in cve_ids:
            tech = self._cve_to_technique(cve_id.upper())
            if tech and tech not in [m["technique_id"] for m in matched_techniques]:
                tactic = self.TACTICS.get(tech.tactic)
                matched_techniques.append({
                    "technique_id": tech.id,
                    "technique_name": tech.name,
                    "tactic_id": tech.tactic,
                    "tactic_name": tactic.name if tactic else "Unknown",
                    "confidence": 0.8,
                    "cve_match": cve_id,
                })
        
        return {
            "finding_id": finding.get("id"),
            "finding_title": finding.get("title"),
            "mitre_mappings": matched_techniques,
            "tactics_covered": list(set(m["tactic_name"] for m in matched_techniques)),
            "total_techniques": len(matched_techniques),
        }
    
    async def map_findings_batch(self, findings: List[Dict]) -> Dict:
        """Map multiple findings to MITRE ATT&CK."""
        results = []
        all_techniques = set()
        all_tactics = set()
        
        for finding in findings:
            mapping = await self.map_finding(finding)
            results.append(mapping)
            for tech in mapping.get("mitre_mappings", []):
                all_techniques.add(tech["technique_id"])
                all_tactics.add(tech["tactic_name"])
        
        return {
            "findings_mapped": len(results),
            "techniques_identified": list(all_techniques),
            "tactics_covered": list(all_tactics),
            "coverage_percentage": (len(all_techniques) / max(len(self.TECHNIQUES), 1)) * 100,
            "mappings": results,
        }
    
    def build_kill_chain(self, mapped_findings: List[Dict]) -> Dict:
        """Build a kill chain visualization from mapped findings."""
        tactic_order = [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Exfiltration", "Command and Control", "Impact",
        ]
        
        kill_chain = []
        for tactic_name in tactic_order:
            techs = []
            for mapping in mapped_findings:
                for tech in mapping.get("mitre_mappings", []):
                    if tech["tactic_name"] == tactic_name and tech["technique_id"] not in [t["id"] for t in techs]:
                        techs.append({
                            "id": tech["technique_id"],
                            "name": tech["technique_name"],
                            "finding": mapping.get("finding_title"),
                            "confidence": tech.get("confidence", 0.5),
                        })
            
            if techs:
                kill_chain.append({
                    "tactic": tactic_name,
                    "techniques": techs,
                    "count": len(techs),
                })
        
        return {
            "kill_chain": kill_chain,
            "total_tactics": len(kill_chain),
            "total_techniques": sum(k["count"] for k in kill_chain),
            "completeness": len(kill_chain) / len(tactic_order) * 100,
        }
    
    def _cve_to_technique(self, cve_id: str) -> Optional[MitreTechnique]:
        """Map a CVE to potential MITRE technique."""
        # Common mappings
        cve_technique_map = {
            "CVE-2021": "T1190",  # Public-facing app exploits
            "CVE-2022": "T1190",
            "CVE-2023": "T1190",
            "CVE-2024": "T1190",
        }
        
        prefix = cve_id[:9]  # CVE-YYYY
        tech_id = cve_technique_map.get(prefix)
        if tech_id:
            return self.TECHNIQUES.get(tech_id)
        return None
    
    def get_technique(self, technique_id: str) -> Optional[MitreTechnique]:
        return self.TECHNIQUES.get(technique_id)
    
    def get_tactic(self, tactic_id: str) -> Optional[MitreTactic]:
        return self.TACTICS.get(tactic_id.upper())
    
    def get_all_techniques(self) -> List[MitreTechnique]:
        return list(self.TECHNIQUES.values())
    
    def get_all_tactics(self) -> List[MitreTactic]:
        return list(self.TACTICS.values())
