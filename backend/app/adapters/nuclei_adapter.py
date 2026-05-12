"""Nuclei vulnerability scanner adapter."""
import asyncio
import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime

from .base import BaseToolAdapter, ToolConnectionConfig
from app.models.scan import ScanTask, ScanResult, ScanStatus, ToolType

logger = logging.getLogger(__name__)


class NucleiAdapter(BaseToolAdapter):
    """Adapter for ProjectDiscovery Nuclei scanner."""
    
    tool_type = ToolType.NUCLEI
    
    def __init__(self, config: Optional[ToolConnectionConfig] = None):
        super().__init__(config or ToolConnectionConfig(timeout=600))
        self._use_sdk = False
    
    async def connect(self) -> bool:
        try:
            from nucleisdk import ScanEngine
            self._use_sdk = True
        except ImportError:
            self._use_sdk = False
        return True
    
    async def disconnect(self) -> bool:
        return True
    
    async def health_check(self) -> bool:
        try:
            import subprocess
            result = subprocess.run(["nuclei", "-version"], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    async def execute_scan(self, task: ScanTask) -> ScanResult:
        scan_id = self._generate_id()
        start_time = datetime.utcnow()
        results: List[Dict] = []
        
        try:
            logger.info(f"Nuclei: Scanning {task.target}")
            target = task.target if task.target.startswith("http") else f"https://{task.target}"
            
            severities = task.metadata.get("severities", "critical,high,medium,low")
            templates = task.metadata.get("templates", "")
            
            if self._use_sdk:
                from nucleisdk import ScanEngine
                async with ScanEngine(rate_limit=150, no_interactsh=True) as engine:
                    async for result in engine.scan(targets=[target]):
                        results.append({
                            "template_id": result.template_id,
                            "name": result.info.name if hasattr(result.info, 'name') else "",
                            "severity": result.severity,
                            "matched_at": result.matched_at,
                            "extracted_results": result.extracted_results,
                            "type": result.type if hasattr(result, 'type') else "",
                        })
            else:
                import subprocess
                cmd = ["nuclei", "-u", target, "-json", "-silent"]
                if templates:
                    cmd.extend(["-t", templates])
                cmd.extend(["-severity", severities])
                
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()
                
                for line in stdout.decode().strip().split("\n"):
                    if line.strip():
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            return ScanResult(
                scan_id=scan_id, tool=self.tool_type, status=ScanStatus.COMPLETED,
                findings_count=len(results),
                summary=f"Nuclei scan completed: {len(results)} findings detected",
                raw_output=json.dumps(results),
                duration_seconds=duration,
                started_at=start_time, completed_at=datetime.utcnow(),
            )
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
            return ScanResult(
                scan_id=scan_id, tool=self.tool_type, status=ScanStatus.FAILED,
                error=str(e), started_at=start_time, completed_at=datetime.utcnow(),
            )
