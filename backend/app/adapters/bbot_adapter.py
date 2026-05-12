"""BBOT OSINT/Reconnaissance adapter."""
import asyncio
import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime

from .base import BaseToolAdapter, ToolConnectionConfig
from app.models.scan import ScanTask, ScanResult, ScanStatus, ToolType

logger = logging.getLogger(__name__)


class BBOTAdapter(BaseToolAdapter):
    """Adapter for BBOT - multipurpose OSINT scanner."""
    
    tool_type = ToolType.BBOT
    
    def __init__(self, config: Optional[ToolConnectionConfig] = None):
        super().__init__(config or ToolConnectionConfig(timeout=600))
        self._available = False
    
    async def connect(self) -> bool:
        try:
            from bbot.scanner import Scanner
            self._available = True
            return True
        except ImportError:
            logger.warning("BBOT not installed - using subprocess fallback")
            self._available = False
            return True
    
    async def disconnect(self) -> bool:
        return True
    
    async def health_check(self) -> bool:
        return self._available
    
    async def execute_scan(self, task: ScanTask) -> ScanResult:
        scan_id = self._generate_id()
        start_time = datetime.utcnow()
        events_collected: List[Dict] = []
        
        try:
            logger.info(f"BBOT: Scanning {task.target}")
            
            if self._available:
                # Use Python API
                from bbot.scanner import Scanner
                
                presets = task.metadata.get("presets", ["subdomain-enum"])
                scan = Scanner(task.target, presets=presets)
                
                async for event in scan.async_start():
                    events_collected.append({
                        "type": event.type,
                        "data": event.data,
                        "host": str(event.host) if event.host else None,
                        "timestamp": str(event.timestamp),
                    })
            else:
                # Use subprocess fallback
                import subprocess
                result = subprocess.run(
                    ["bbot", "-t", task.target, "-f", "subdomain-enum", "-o", "json"],
                    capture_output=True, text=True, timeout=self.config.timeout,
                )
                for line in result.stdout.strip().split("\n"):
                    if line:
                        try:
                            events_collected.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            return ScanResult(
                scan_id=scan_id, tool=self.tool_type, status=ScanStatus.COMPLETED,
                findings_count=len(events_collected),
                summary=f"BBOT scan completed: {len(events_collected)} events collected",
                raw_output=json.dumps(events_collected[:1000]),
                duration_seconds=duration,
                started_at=start_time, completed_at=datetime.utcnow(),
            )
        except Exception as e:
            logger.error(f"BBOT scan failed: {e}")
            return ScanResult(
                scan_id=scan_id, tool=self.tool_type, status=ScanStatus.FAILED,
                error=str(e), started_at=start_time, completed_at=datetime.utcnow(),
            )
