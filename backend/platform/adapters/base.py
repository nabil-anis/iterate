"""Base tool adapter with common interface."""
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, Dict, Any, List, Type
from uuid import uuid4
import logging
import asyncio
from dataclasses import dataclass, field

from platform.models.scan import ScanTask, ScanResult, ScanStatus, ToolType

logger = logging.getLogger(__name__)


@dataclass
class ToolConnectionConfig:
    """Connection configuration for a tool."""
    host: str = "localhost"
    port: int = 0
    api_key: Optional[str] = None
    api_secret: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    use_ssl: bool = False
    timeout: int = 300
    max_retries: int = 3
    extra: Dict[str, Any] = field(default_factory=dict)


class BaseToolAdapter(ABC):
    """Abstract base class for all tool adapters."""
    
    tool_type: ToolType
    config: ToolConnectionConfig
    
    def __init__(self, config: Optional[ToolConnectionConfig] = None):
        self.config = config or ToolConnectionConfig()
        self._connection_pool: Dict[str, Any] = {}
        self._rate_limiter = None
        self._circuit_open = False
        self._failure_count = 0
        self._max_failures = 5
    
    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to the tool."""
        pass
    
    @abstractmethod
    async def disconnect(self) -> bool:
        """Close connection to the tool."""
        pass
    
    @abstractmethod
    async def execute_scan(self, task: ScanTask) -> ScanResult:
        """Execute a scan task using this tool."""
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the tool is available."""
        pass
    
    async def __aenter__(self):
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()
    
    def _generate_id(self) -> str:
        return str(uuid4())
    
    def _standardize_severity(self, raw_severity: str) -> str:
        """Convert tool-specific severity to standardized format."""
        mapping = {
            "critical": "critical", "crit": "critical", "4": "critical", "5": "critical",
            "high": "high", "h": "high", "3": "high",
            "medium": "medium", "med": "medium", "m": "medium", "2": "medium",
            "low": "low", "l": "low", "1": "low",
            "info": "info", "informational": "info", "note": "info", "0": "info",
        }
        return mapping.get(raw_severity.lower().strip(), "unknown")
    
    def _normalize_timestamp(self, ts: Any) -> str:
        """Normalize timestamps to ISO format."""
        if isinstance(ts, datetime):
            return ts.isoformat()
        if isinstance(ts, str):
            return ts
        return datetime.utcnow().isoformat()


class ToolAdapterRegistry:
    """Registry for all available tool adapters."""
    
    _adapters: Dict[ToolType, Type[BaseToolAdapter]] = {}
    _instances: Dict[ToolType, BaseToolAdapter] = {}
    
    @classmethod
    def register(cls, tool_type: ToolType, adapter_class: Type[BaseToolAdapter]):
        """Register a tool adapter class."""
        cls._adapters[tool_type] = adapter_class
        logger.info(f"Registered adapter: {tool_type.value} -> {adapter_class.__name__}")
    
    @classmethod
    def get_adapter(cls, tool_type: ToolType) -> Optional[BaseToolAdapter]:
        """Get or create an adapter instance."""
        if tool_type not in cls._instances:
            adapter_class = cls._adapters.get(tool_type)
            if not adapter_class:
                logger.error(f"No adapter registered for {tool_type.value}")
                return None
            cls._instances[tool_type] = adapter_class()
        return cls._instances[tool_type]
    
    @classmethod
    def get_available_tools(cls) -> List[ToolType]:
        return list(cls._adapters.keys())
    
    @classmethod
    async def health_check_all(cls) -> Dict[ToolType, bool]:
        results = {}
        for tool_type, adapter_class in cls._adapters.items():
            try:
                adapter = cls.get_adapter(tool_type)
                if adapter:
                    results[tool_type] = await adapter.health_check()
                else:
                    results[tool_type] = False
            except Exception:
                results[tool_type] = False
        return results
