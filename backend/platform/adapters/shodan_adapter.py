"""Shodan adapter for internet reconnaissance."""
import shodan
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime

from .base import BaseToolAdapter, ToolConnectionConfig
from platform.models.scan import ScanTask, ScanResult, ScanStatus, ToolType
from platform.config import settings

logger = logging.getLogger(__name__)


class ShodanAdapter(BaseToolAdapter):
    """Adapter for Shodan search engine."""
    
    tool_type = ToolType.SHODAN
    
    def __init__(self, config: Optional[ToolConnectionConfig] = None):
        super().__init__(config or ToolConnectionConfig(
            api_key=settings.SHODAN_API_KEY,
            timeout=60,
        ))
        self._api: Optional[shodan.Shodan] = None
    
    async def connect(self) -> bool:
        try:
            self._api = shodan.Shodan(self.config.api_key or "")
            return True
        except Exception as e:
            logger.error(f"Shodan connect failed: {e}")
            return False
    
    async def disconnect(self) -> bool:
        self._api = None
        return True
    
    async def health_check(self) -> bool:
        if not self._api:
            return False
        try:
            info = self._api.info()
            return "credits" in info
        except Exception:
            return False
    
    async def execute_scan(self, task: ScanTask) -> ScanResult:
        scan_id = self._generate_id()
        start_time = datetime.utcnow()
        try:
            logger.info(f"Shodan: Searching {task.target}")
            
            results = {}
            
            if task.target_type in ("ip", "domain"):
                try:
                    host = self._api.host(task.target)
                    results["host"] = host
                except shodan.exception.APIError:
                    results["host"] = {"error": "No information available"}
            
            # Search for related
            search_results = self._api.search(f"hostname:{task.target}")
            results["search"] = search_results
            
            # Get DNS info
            try:
                dns = self._api.dns_resolve([task.target])
                results["dns"] = dns
            except Exception:
                pass
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            total = len(results.get("host", {}).get("data", [])) + \
                    len(results.get("search", {}).get("matches", []))
            
            return ScanResult(
                scan_id=scan_id,
                tool=self.tool_type,
                status=ScanStatus.COMPLETED,
                findings_count=total,
                summary=f"Shodan recon completed: {total} services found",
                raw_output=str(results),
                duration_seconds=duration,
                started_at=start_time,
                completed_at=datetime.utcnow(),
            )
        except Exception as e:
            logger.error(f"Shodan scan failed: {e}")
            return ScanResult(
                scan_id=scan_id, tool=self.tool_type, status=ScanStatus.FAILED,
                error=str(e), started_at=start_time, completed_at=datetime.utcnow(),
            )
