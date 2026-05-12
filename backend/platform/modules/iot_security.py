"""IoT security assessment module."""
import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class IoTSecurityModule:
    """Assesses IoT device security posture."""
    
    async def assess_device(self, device_info: Dict) -> Dict[str, Any]:
        """Assess a single IoT device."""
        checks = self._run_checks(device_info)
        
        return {
            "device_id": device_info.get("id", "unknown"),
            "device_type": device_info.get("type", "unknown"),
            "firmware_version": device_info.get("firmware", "unknown"),
            "checks_performed": len(checks),
            "vulnerabilities_found": sum(1 for c in checks if c.get("vulnerable")),
            "critical_vulns": sum(1 for c in checks if c.get("severity") == "critical"),
            "check_results": checks,
            "overall_score": self._calculate_score(checks),
            "recommendations": self._generate_recommendations(checks),
        }
    
    async def assess_network(self, device_list: List[Dict]) -> Dict[str, Any]:
        """Assess all IoT devices on the network."""
        results = []
        for device in device_list:
            results.append(await self.assess_device(device))
        
        return {
            "total_devices": len(results),
            "vulnerable_devices": sum(1 for r in results if r["vulnerabilities_found"] > 0),
            "device_results": results,
            "network_risk_score": sum(r["overall_score"] for r in results) / max(len(results), 1),
        }
    
    def _run_checks(self, device: Dict) -> List[Dict]:
        """Run security checks on an IoT device."""
        checks = []
        
        # Default credentials check
        default_creds = ["admin/admin", "admin/password", "root/root", "admin/1234", "admin/admin123"]
        for host_cred in device.get("default_credentials", []):
            if host_cred in default_creds:
                checks.append({
                    "check": "default_credentials",
                    "vulnerable": True,
                    "severity": "critical",
                    "detail": f"Device using known default credentials: {host_cred}",
                    "remediation": "Change default credentials immediately",
                })
        
        # Open ports check
        insecure_ports = {23: "Telnet", 21: "FTP", 161: "SNMP"}
        for port, service in insecure_ports.items():
            if port in device.get("open_ports", []):
                checks.append({
                    "check": f"insecure_service_{service.lower()}",
                    "vulnerable": True,
                    "severity": "high",
                    "detail": f"Insecure service {service} running on port {port}",
                    "remediation": f"Disable {service} and use SSH/HTTPS instead",
                })
        
        # Firmware version check
        fw = device.get("firmware", "0.0.0")
        try:
            version_parts = [int(x) for x in fw.split(".")]
            if len(version_parts) >= 2 and version_parts[0] < 2:
                checks.append({
                    "check": "outdated_firmware",
                    "vulnerable": True,
                    "severity": "high",
                    "detail": f"Outdated firmware version {fw}",
                    "remediation": "Update to latest firmware version",
                })
        except (ValueError, IndexError):
            pass
        
        # Encryption check
        if not device.get("encryption_enabled", True):
            checks.append({
                "check": "no_encryption",
                "vulnerable": True,
                "severity": "critical",
                "detail": "Device communication is not encrypted",
                "remediation": "Enable TLS/SSL for all device communication",
            })
        
        return checks
    
    def _calculate_score(self, checks: List[Dict]) -> float:
        score = 100.0
        for c in checks:
            if c.get("vulnerable"):
                if c.get("severity") == "critical":
                    score -= 30
                elif c.get("severity") == "high":
                    score -= 15
                elif c.get("severity") == "medium":
                    score -= 5
        return max(score, 0)
    
    def _generate_recommendations(self, checks: List[Dict]) -> List[str]:
        recs = set()
        for c in checks:
            if c.get("vulnerable"):
                recs.add(c.get("remediation"))
        recs.add("Segment IoT devices on isolated VLAN")
        recs.add("Implement network-level IoT device monitoring")
        return list(recs)
