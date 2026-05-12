"""Wireless security assessment module."""
import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class WirelessSecurityModule:
    """Assesses wireless network security."""
    
    # Common WPS PINs and weaknesses
    WEAK_WPS_PINS = ["12345670", "00000000", "11111111", "22222222"]
    
    async def assess_network(self, ap_info: Dict) -> Dict[str, Any]:
        """Assess a wireless access point."""
        findings = []
        
        # Encryption check
        encryption = ap_info.get("encryption", "").lower()
        if not encryption or encryption in ("none", "open"):
            findings.append({
                "issue": "Open Network",
                "severity": "critical",
                "detail": "Network has no encryption enabled",
                "remediation": "Enable WPA3 or WPA2-Enterprise",
            })
        elif encryption == "wep":
            findings.append({
                "issue": "WEP Encryption",
                "severity": "critical",
                "detail": "WEP can be cracked in minutes",
                "remediation": "Upgrade to WPA3 or WPA2-Enterprise",
            })
        elif encryption == "wpa" or encryption == "wpa2":
            # Check for WPS
            if ap_info.get("wps_enabled", False):
                wps_pin = ap_info.get("wps_pin", "")
                if wps_pin in self.WEAK_WPS_PINS:
                    findings.append({
                        "issue": "Weak WPS PIN",
                        "severity": "high",
                        "detail": f"WPS PIN {wps_pin} is commonly used and vulnerable",
                        "remediation": "Disable WPS or use strong PIN",
                    })
        
        # SSID broadcast
        if ap_info.get("ssid_broadcast", True) is False:
            findings.append({
                "issue": "Hidden SSID",
                "severity": "low",
                "detail": "Hidden SSID provides no real security but may cause compatibility issues",
                "remediation": "Enable SSID broadcast - use encryption instead of obscurity",
            })
        
        # Channel analysis
        channel = ap_info.get("channel", 0)
        if channel in (0,):
            findings.append({
                "issue": "Auto Channel Selection",
                "severity": "info",
                "detail": "Auto channel selection may cause interference",
                "remediation": "Manually set channel based on spectrum analysis",
            })
        
        # Client isolation
        if not ap_info.get("client_isolation", False):
            findings.append({
                "issue": "Client Isolation Disabled",
                "severity": "medium",
                "detail": "Clients can communicate directly, enabling lateral movement",
                "remediation": "Enable AP isolation / client separation",
            })
        
        score = 100.0
        for f in findings:
            if f["severity"] == "critical": score -= 30
            elif f["severity"] == "high": score -= 15
            elif f["severity"] == "medium": score -= 5
        
        return {
            "ssid": ap_info.get("ssid", "unknown"),
            "bssid": ap_info.get("bssid", "unknown"),
            "channel": channel,
            "encryption": encryption,
            "signal_strength": ap_info.get("signal", "unknown"),
            "findings": findings,
            "total_findings": len(findings),
            "security_score": max(score, 0),
            "recommendations": [
                f"Enable {self._best_encryption(encryption)} encryption",
                "Disable WPS",
                "Enable client isolation for guest networks",
                "Conduct periodic wireless surveys",
            ],
        }
    
    def _best_encryption(self, current: str) -> str:
        if current in ("none", "wep"):
            return "WPA3"
        return "WPA3-Enterprise"
