"""Compliance framework mapping models."""
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ComplianceFramework(str, Enum):
    NIST_CSF = "nist_csf"
    NIST_800_53 = "nist_800_53"
    ISO_27001 = "iso_27001"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOC_2 = "soc_2"
    CIS_CONTROLS = "cis_controls"


class ControlMapping(BaseModel):
    """Mapping between a finding and compliance controls."""
    finding_id: str
    framework: ComplianceFramework
    control_id: str
    control_name: str
    control_description: Optional[str] = None
    mapping_type: str = "direct"  # direct, partial, related
    evidence: Optional[str] = None
    status: str = "not_tested"  # compliant, non_compliant, not_tested, not_applicable
