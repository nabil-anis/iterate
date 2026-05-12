"""SIEM integration for sending findings to external security monitoring platforms."""
import logging
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio

logger = logging.getLogger(__name__)


class SIEMIntegration:
    """Integration with external SIEM systems (Splunk, ELK, QRadar, etc.)."""
    
    def __init__(self):
        self._sinks: Dict[str, Dict] = {}
        self._send_queue: asyncio.Queue = asyncio.Queue()
        self._batch_size = 100
        self._flush_interval = 30  # seconds
        self._running = False
        self._stats: Dict[str, Any] = {
            "sent_total": 0,
            "failed_total": 0,
            "last_send": None,
        }
    
    async def register_sink(self, name: str, sink_type: str, config: Dict):
        """Register a SIEM sink destination."""
        self._sinks[name] = {
            "type": sink_type,  # splunk, elasticsearch, qradar, syslog
            "config": config,
            "healthy": True,
            "last_error": None,
        }
        logger.info(f"Registered SIEM sink: {name} ({sink_type})")
    
    async def send_finding(self, finding: Dict) -> bool:
        """Send a single finding to all registered SIEM sinks."""
        await self._send_queue.put(finding)
        return True
    
    async def send_findings_batch(self, findings: List[Dict]) -> Dict:
        """Send a batch of findings to all SIEM sinks."""
        results = {}
        for finding in findings:
            await self._send_queue.put(finding)
        
        results["queued"] = len(findings)
        return results
    
    async def flush(self) -> Dict:
        """Flush the send queue to all sinks."""
        batch = []
        while not self._send_queue.empty() and len(batch) < self._batch_size:
            try:
                finding = self._send_queue.get_nowait()
                batch.append(finding)
            except asyncio.QueueEmpty:
                break
        
        if not batch:
            return {"sent": 0, "sinks": len(self._sinks)}
        
        results = {}
        for sink_name, sink in self._sinks.items():
            try:
                sent = await self._send_to_sink(sink_name, sink, batch)
                results[sink_name] = {"sent": sent, "failed": 0}
                self._stats["sent_total"] += sent
            except Exception as e:
                logger.error(f"Failed to send to SIEM sink {sink_name}: {e}")
                results[sink_name] = {"sent": 0, "failed": len(batch), "error": str(e)}
                self._stats["failed_total"] += len(batch)
        
        self._stats["last_send"] = datetime.utcnow().isoformat()
        return {"sent": len(batch), "sink_results": results}
    
    async def _send_to_sink(self, name: str, sink: Dict, events: List[Dict]) -> int:
        """Send events to a specific SIEM sink."""
        sink_type = sink["type"]
        config = sink["config"]
        
        if sink_type == "splunk":
            return await self._send_splunk(config, events)
        elif sink_type == "elasticsearch":
            return await self._send_elasticsearch(config, events)
        elif sink_type == "qradar":
            return await self._send_qradar(config, events)
        elif sink_type == "syslog":
            return await self._send_syslog(config, events)
        elif sink_type == "webhook":
            return await self._send_webhook(config, events)
        else:
            raise ValueError(f"Unsupported SIEM type: {sink_type}")
    
    async def _send_splunk(self, config: Dict, events: List[Dict]) -> int:
        """Send events to Splunk HEC."""
        import httpx
        
        url = config.get("url", "").rstrip("/") + "/services/collector"
        token = config.get("token", "")
        
        payload = {
            "events": [
                {
                    "time": datetime.utcnow().timestamp(),
                    "host": event.get("target", "unknown"),
                    "source": "cybersecurity-platform",
                    "sourcetype": "security:finding",
                    "event": event,
                }
                for event in events
            ]
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                url,
                json=payload,
                headers={"Authorization": f"Splunk {token}"},
            )
            if response.status_code != 200:
                raise Exception(f"Splunk returned {response.status_code}: {response.text}")
        
        return len(events)
    
    async def _send_elasticsearch(self, config: Dict, events: List[Dict]) -> int:
        """Send events to Elasticsearch."""
        import httpx
        
        url = config.get("url", "").rstrip("/")
        index = config.get("index", "security-findings")
        api_key = config.get("api_key", "")
        
        # Prepare bulk payload
        bulk_lines = []
        for event in events:
            action = json.dumps({"index": {"_index": index}})
            doc = json.dumps({
                **event,
                "@timestamp": datetime.utcnow().isoformat(),
            })
            bulk_lines.append(action)
            bulk_lines.append(doc)
        
        bulk_payload = "\n".join(bulk_lines) + "\n"
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            headers = {"Content-Type": "application/x-ndjson"}
            if api_key:
                headers["Authorization"] = f"ApiKey {api_key}"
            
            response = await client.post(
                f"{url}/_bulk",
                content=bulk_payload,
                headers=headers,
            )
            if response.status_code != 200:
                raise Exception(f"Elasticsearch returned {response.status_code}")
        
        return len(events)
    
    async def _send_qradar(self, config: Dict, events: List[Dict]) -> int:
        """Send events to QRadar."""
        # QRadar integration placeholder
        logger.info(f"QRadar: Would send {len(events)} events to {config.get('url')}")
        return len(events)
    
    async def _
