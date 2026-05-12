"""Burp Suite Professional adapter."""
import httpx
import json
import logging
from typing import Optional, Dict, Any
from datetime import datetime

from .base import BaseToolAdapter, ToolConnectionConfig
from app.models.scan import ScanTask, ScanResult, ScanStatus, ToolType
from app.config import settings

logger = logging.getLogger(__name__)


class BurpSuiteAdapter(BaseToolAdapter):
    """Adapter for Burp Suite Professional REST API."""
    
    tool_type = ToolType.BURPSUITE
    
    def __init__(self, config: Optional[ToolConnectionConfig] = None):
        super().__init__(config or ToolConnectionConfig(
            host=settings.BURP_API_URL,
            api_key=settings.BURP_API_KEY,
            timeout=600,
        ))
        self._client: Optional[httpx.AsyncClient] = None
        self._scan_id_map: Dict[str, str] = {}  # our_id -> burp_id
    
    async def connect(self) -> bool:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        self._client = httpx.AsyncClient(
            base_url=self.config.host,
            timeout=self.config.timeout,
            headers=headers,
            verify=False,
        )
        return True
    
    async def disconnect(self) -> bool:
        if self._client:
            await self._client.aclose()
            self._client = None
        return True
    
    async def health_check(self) -> bool:
        try:
            resp = await self._client.get("/health", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False
    
    async def execute_scan(self, task: ScanTask) -> ScanResult:
        scan_id = self._generate_id()
        start_time = datetime.utcnow()
        try:
            logger.info(f"BurpSuite: Scanning {task.target}")
            
            urls = [task.target]
            if task.target_type == "domain":
                urls = [f"https://{task.target}", f"http://{task.target}"]
            
            payload = {
                "urls": urls,
                "scope": {"include": [{"rule": f".*{task.target}.*"}]},
                "scan_configurations": [
                    {"name": "Crawl and Audit", "type": "named_configuration"}
                ],
            }
            
            resp = await self._client.post("/scan", json=payload)
            
            if resp.status_code == 201:
                burp_scan_id = resp.headers.get("Location", "").split("/")[-1]
                self._scan_id_map[scan_id] = burp_scan_id
                
                # Poll for completion
                status = await self._poll_scan(burp_scan_id)
                duration = (datetime.utcnow() - start_time).total_seconds()
                
                findings = await self._get_findings(burp_scan_id)
                
                return ScanResult(
                    scan_id=scan_id,
                    tool=self.tool_type,
                    status=ScanStatus.COMPLETED if status == "succeeded" else ScanStatus.FAILED,
                    findings_count=len(findings),
                    summary=f"BurpSuite scan completed with {len(findings)} findings",
                    raw_output=json.dumps(findings),
                    duration_seconds=duration,
                    started_at=start_time,
                    completed_at=datetime.utcnow(),
                )
            else:
                return ScanResult(
                    scan_id=scan_id,
                    tool=self.tool_type,
                    status=ScanStatus.FAILED,
                    error=f"HTTP {resp.status_code}",
                    started_at=start_time,
                    completed_at=datetime.utcnow(),
                )
        except Exception as e:
            logger.error(f"BurpSuite scan failed: {e}")
            return ScanResult(
                scan_id=scan_id,
                tool=self.tool_type,
                status=ScanStatus.FAILED,
                error=str(e),
                started_at=start_time,
                completed_at=datetime.utcnow(),
            )
    
    async def _poll_scan(self, burp_id: str, max_wait: int = 3600) -> str:
        """Poll Burp scan until completion."""
        for _ in range(max_wait // 10):
            try:
                resp = await self._client.get(f"/scan/{burp_id}")
                if resp.status_code == 200:
                    data = resp.json()
                    status = data.get("scan_status", "")
                    if status in ("succeeded", "failed", "cancelled"):
                        return status
            except Exception:
                pass
            await asyncio.sleep(10)
        return "timeout"
    
    async def _get_findings(self, burp_id: str) -> list:
        """Retrieve findings from completed scan."""
        try:
            resp = await self._client.get(f"/scan/{burp_id}/issues")
            if resp.status_code == 200:
                return resp.json().get("issues", [])
        except Exception:
            pass
        return []
