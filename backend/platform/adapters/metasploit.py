"""Metasploit Framework adapter via RPC API."""
import msgpack
import httpx
import logging
from typing import Optional, Dict, Any
from datetime import datetime

from .base import BaseToolAdapter, ToolConnectionConfig
from platform.models.scan import ScanTask, ScanResult, ScanStatus, ToolType
from platform.config import settings

logger = logging.getLogger(__name__)


class MetasploitAdapter(BaseToolAdapter):
    """Adapter for Metasploit RPC API."""
    
    tool_type = ToolType.METASPLOIT
    
    def __init__(self, config: Optional[ToolConnectionConfig] = None):
        super().__init__(config or ToolConnectionConfig(
            host=settings.METASPLOIT_HOST,
            port=settings.METASPLOIT_PORT,
            password=settings.METASPLOIT_PASS,
            timeout=600,
        ))
        self._client: Optional[httpx.AsyncClient] = None
        self._token: Optional[str] = None
    
    async def connect(self) -> bool:
        self._client = httpx.AsyncClient(
            timeout=self.config.timeout,
            verify=False,
        )
        # Authenticate
        try:
            resp = await self._client.post(
                f"http://{self.config.host}:{self.config.port}/api/1.0/auth",
                data=msgpack.packb({"username": "msf", "password": self.config.password or ""}),
                headers={"Content-Type": "binary/message-pack"},
            )
            if resp.status_code == 200:
                data = msgpack.unpackb(resp.content)
                self._token = data.get(b"token", b"").decode()
                return bool(self._token)
        except Exception as e:
            logger.error(f"Metasploit auth failed: {e}")
        return False
    
    async def disconnect(self) -> bool:
        if self._client:
            await self._client.aclose()
            self._client = None
        return True
    
    async def health_check(self) -> bool:
        if not self._token:
            return False
        try:
            resp = await self._client.post(
                f"http://{self.config.host}:{self.config.port}/api/1.0/core/version",
                data=msgpack.packb({"_token": self._token}),
                headers={"Content-Type": "binary/message-pack"},
                timeout=5,
            )
            return resp.status_code == 200
        except Exception:
            return False
    
    async def _rpc_call(self, method: str, **kwargs) -> Dict:
        """Make an RPC call to Metasploit."""
        params = {"_token": self._token, **kwargs}
        resp = await self._client.post(
            f"http://{self.config.host}:{self.config.port}/api/1.0/{method}",
            data=msgpack.packb(params),
            headers={"Content-Type": "binary/message-pack"},
        )
        if resp.status_code == 200:
            data = msgpack.unpackb(resp.content)
            return {k.decode() if isinstance(k, bytes) else k: 
                    v.decode() if isinstance(v, bytes) else v 
                    for k, v in data.items()}
        raise RuntimeError(f"RPC call failed: {resp.status_code}")
    
    async def execute_scan(self, task: ScanTask) -> ScanResult:
        scan_id = self._generate_id()
        start_time = datetime.utcnow()
        try:
            logger.info(f"Metasploit: Scanning {task.target}")
            
            # Create workspace
            ws_name = f"scan_{scan_id[:8]}"
            await self._rpc_call("pro/workspace_add", 
                                name=ws_name, 
                                description=f"Auto scan for {task.target}")
            
            # Run discovery scan
            result = await self._rpc_call("pro/discover", 
                                         workspace=ws_name,
                                         targets=[task.target],
                                         scan_type="nmap_scan")
            
            # Run vulnerability scan
            vuln_result = await self._rpc_call("pro/vuln_scan", 
                                              workspace=ws_name,
                                              targets=[task.target])
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            return ScanResult(
                scan_id=scan_id,
                tool=self.tool_type,
                status=ScanStatus.COMPLETED,
                findings_count=len(vuln_result.get("vulns", [])),
                summary=f"Metasploit scan of {task.target} completed",
                raw_output=str(vuln_result),
                duration_seconds=duration,
                started_at=start_time,
                completed_at=datetime.utcnow(),
            )
        except Exception as e:
            logger.error(f"Metasploit scan failed: {e}")
            return ScanResult(
                scan_id=scan_id,
                tool=self.tool_type,
                status=ScanStatus.FAILED,
                error=str(e),
                started_at=start_time,
                completed_at=datetime.utcnow(),
            )
