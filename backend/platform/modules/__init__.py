"""Layer 5: Security Modules - specialized security analysis modules."""
from .exploit_detection import ExploitDetectionModule
from .phishing_sim import PhishingSimulationModule
from .network_segmentation import NetworkSegmentationAnalyzer
from .iot_security import IoTSecurityModule
from .cloud_security import CloudSecurityModule
from .wireless import WirelessSecurityModule

__all__ = [
    "ExploitDetectionModule", "PhishingSimulationModule",
    "NetworkSegmentationAnalyzer", "IoTSecurityModule",
    "CloudSecurityModule", "WirelessSecurityModule",
]
