"""Nessus/Tenable vulnerability scanner adapter."""
import httpx
import hmac
import hashlib
import base64
import json
import time
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
import asyncio

from .base import BaseToolAdapter, ToolConnectionConfig
from app.models.scan import ScanTask, ScanResult, ScanStatus, ToolType
from app.config import settings

logger = logging.getLogger(__name__)


class NessusAdapter(BaseToolAdapter):
    """Adapter for Nessus/Tenable.io vulnerability scanner."""
    
    tool_type = ToolType.NESSUS
    
    def __init__(self, config: Optional[ToolConnectionConfig] = None):
        super().__init__(config or ToolConnectionConfig(
            host=settings.NESSUS_URL,
            api_key=settings.NESSUS_API_KEY,
            api_secret=settings.NESSUS_SECRET_KEY,
            use_ssl=True,
            timeout=1200,
        ))
        self._client: Optional[httpx.AsyncClient] = None
        self._token: Optional[str] = None
    
    async def connect(self) -> bool:
        self._client = httpx.AsyncClient(
            base_url=self.config.host,
            timeout=self.config.timeout,
            verify=False,
        )
        return await self._authenticate()
    
    async def _authenticate(self) -> bool:
        try:
            if self.config.api_key and self.config.api_secret:
                # API key auth (Tenable.io style)
                resp = await self._client.post("/session", json={
                    "access_key": self.config.api_key,
                    "secret_key": self.config.api_secret,
                })
            else:
                # Session-based auth
                resp = await self._client.post("/session", json={
                    "username": self.config.username or "admin",
                    "password": self.config.password or "admin",
                })
            
            if resp.status_code == 200:
                data = resp.json()
                self._token = data.get("token", "")
                self._client.headers.update({"X-Cookie": f"token={self._token}"})
                return True
        except Exception as e:
            logger.error(f"Nessus auth failed: {e}")
        return False
    
    async def disconnect(self) -> bool:
        if self._client and self._token:
            try:
                await self._client.delete("/session")
            except Exception:
                pass
        if self._client:
            await self._client.aclose()
            self._client = None
        return True
    
    async def health_check(self) -> bool:
        if not self._token:
            return False
        try:
            resp = await self._client.get("/server/status", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False
    
    async def execute_scan(self, task: ScanTask) -> ScanResult:
        scan_id = self._generate_id()
        start_time = datetime.utcnow()
        try:
            logger.info(f"Nessus: Scanning {task.target}")
            
            # Get or create scan policy
            policies = await self._client.get("/policies")
            policy_id = policies.json().get("policies", [{}])[0].get("id")
            
            # Create scan
            scan_data = {
                "uuid": policy_id,
                "settings": {
                    "name": f"scan_{scan_id[:8]}",
                    "description": f"Auto scan for {task.target}",
                    "text_targets": task.target,
                    "launch": "ON_DEMAND",
                }
            }
            create_resp = await self._client.post("/scans", json=scan_data)
            
            if create_resp.status_code != 200:
                return ScanResult(
                    scan_id=scan_id, tool=self.tool_type, status=ScanStatus.FAILED,
                    error=f"Failed to create scan: {create_resp.text}",
                    started_at=start_time, completed_at=datetime.utcnow(),
                )
            
            scan_info = create_resp.json()
            nessus_scan_id = scan_info["scan"]["id"]
            
            # Launch scan
            await self._client.post(f"/scans/{nessus_scan_id}/launch")
            
            # Poll for completion
            status = await self._poll_scan(nessus_scan_id)
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            if status == "completed":
                # Get results
                results = await self._client.get(f"/scans/{nessus_scan_id}")
                data = results.json()
                vulns = data.get("vulnerabilities", [])
                
                return ScanResult(
                    scan_id=scan_id, tool=self.tool_type, status=ScanStatus.COMPLETED,
                    findings_count=len(vulns),
                    summary=f"Nessus scan completed: {len(vulns)} vulnerabilities found",
                    raw_output=json.dumps(data),
                    duration_seconds=duration,
                    started_at=start_time, completed_at=datetime.utcnow(),
                )
            else:
                return ScanResult(
                    scan_id=scan_id, tool=self.tool_type, status=ScanStatus.FAILED,
                    error=f"Scan ended with status: {status}",
                    started_at=start_time, completed_at=datetime.utcnow(),
                )
        except Exception as e:
            logger.error(f"Nessus scan failed: {e}")
            return ScanResult(
                scan_id=scan_id, tool=self.tool_type, status=ScanStatus.FAILED,
                error=str(e), started_at=start_time, completed_at=datetime.utcnow(),
            )
    
    async def _poll_scan(self, scan_id: int, max_wait: int = 3600) -> str:
        """Poll Nessus scan until completion."""
        for _ in range(max_wait // 15):
            try:
                resp = await self._client.get(f"/scans/{scan_id}")
                if resp.status_code == 200:
                    info = resp.json().get("info", {})
                    status = info.get("status", "")
                    if status in ("completed", "failed", "cancelled", "aborted"):
                        return status
            except Exception:
                pass
            await asyncio.sleep(15)
        return "timeout"
