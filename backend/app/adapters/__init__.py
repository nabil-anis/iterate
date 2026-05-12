"""Tool adapters - Layer 1: API Integration & Orchestration."""
from .base import BaseToolAdapter, ToolAdapterRegistry
from .pentestgpt import PentestGPTAdapter
from .burpsuite import BurpSuiteAdapter
from .metasploit import MetasploitAdapter
from .nessus import NessusAdapter
from .shodan_adapter import ShodanAdapter
from .censys_adapter import CensysAdapter
from .bbot_adapter import BBOTAdapter
from .nuclei_adapter import NucleiAdapter
from .stackhawk import StackHawkAdapter
from .pyrit_adapter import PyRITAdapter
from .nodezero import NodeZeroAdapter
from .openvas import OpenVASAdapter

__all__ = [
    "BaseToolAdapter", "ToolAdapterRegistry",
    "PentestGPTAdapter", "BurpSuiteAdapter", "MetasploitAdapter",
    "NessusAdapter", "ShodanAdapter", "CensysAdapter",
    "BBOTAdapter", "NucleiAdapter", "StackHawkAdapter",
    "PyRITAdapter", "NodeZeroAdapter", "OpenVASAdapter",
]
