"""Threat feed ingestion from multiple sources."""
import logging
import json
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from uuid import uuid4
import asyncio

from .ioc_manager import IOCManager, IOC

logger = logging.getLogger(__name__)


class ThreatFeedIngester:
    """Ingests threat intelligence from external feeds."""
    
    def __init__(self, ioc_manager: IOCManager):
        self.ioc_manager = ioc_manager
        self._feeds: Dict[str, Dict] = {}
        self._feed_handlers: Dict[str, Callable] = {}
        self._ingestion_history: List[Dict] = []
        
        # Register default feed handlers
        self._register_default_handlers()
    
    async def register_feed(self, name: str, url: str, feed_type: str,
                            interval_minutes: int = 60, api_key: Optional[str] = None):
        """Register a new threat feed source."""
        self._feeds[name] = {
            "name": name,
            "url": url,
            "type": feed_type,
            "interval": interval_minutes,
            "api_key": api_key,
            "last_ingested": None,
            "enabled": True,
        }
        logger.info(f"Registered feed: {name} ({feed_type})")
    
    async def ingest_all(self) -> Dict[str, Any]:
        """Ingest from all enabled feeds."""
        results = {}
        for feed_name, feed_config in self._feeds.items():
            if feed_config.get("enabled", True):
                try:
                    result = await self._ingest_feed(feed_name)
                    results[feed_name] = result
                except Exception as e:
                    logger.error(f"Failed to ingest feed {feed_name}: {e}")
                    results[feed_name] = {"status": "error", "error": str(e)}
        
        return {
            "feeds_ingested": len(results),
            "total_iocs": sum(r.get("iocs_added", 0) for r in results.values() if isinstance(r, dict)),
            "results": results,
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    async def ingest_single(self, feed_name: str) -> Dict:
        """Ingest from a single feed."""
        if feed_name not in self._feeds:
            return {"status": "error", "error": f"Feed '{feed_name}' not found"}
        return await self._ingest_feed(feed_name)
    
    async def _ingest_feed(self, feed_name: str) -> Dict:
        """Ingest from a specific feed."""
        feed = self._feeds[feed_name]
        logger.info(f"Ingesting feed: {feed_name}")
        
        handler = self._feed_handlers.get(feed["type"])
        if not handler:
            return {"status": "error", "error": f"No handler for feed type: {feed['type']}"}
        
        try:
            iocs = await handler(feed)
        except Exception as e:
            return {"status": "error", "error": str(e)}
        
        if not iocs:
            return {"status": "completed", "iocs_added": 0, "message": "No new IOCs found"}
        
        # Add IOCs to manager
        added = 0
        for ioc_data in iocs:
            try:
                ioc = IOC(**ioc_data)
                await self.ioc_manager.add_ioc(ioc)
                added += 1
            except Exception as e:
                logger.warning(f"Failed to add IOC from feed {feed_name}: {e}")
        
        feed["last_ingested"] = datetime.utcnow()
        
        self._ingestion_history.append({
            "feed": feed_name,
            "timestamp": datetime.utcnow().isoformat(),
            "iocs_added": added,
            "status": "completed",
        })
        
        # Trim history
        if len(self._ingestion_history) > 100:
            self._ingestion_history = self._ingestion_history[-100:]
        
        return {
            "status": "completed",
            "iocs_added": added,
            "total_in_feed": len(iocs),
            "last_ingested": feed["last_ingested"].isoformat(),
        }
    
    def _register_default_handlers(self):
        """Register default feed format handlers."""
        self._feed_handlers["alienvault_otx"] = self._handle_alienvault
        self._feed_handlers["abuseipdb"] = self._handle_abuseipdb
        self._feed_handlers["misp"] = self._handle_misp
        self._feed_handlers["stix_taxii"] = self._handle_stix
        self._feed_handlers["csv"] = self._handle_csv
        self._feed_handlers["json"] = self._handle_json
    
    async def _handle_alienvault(self, feed: Dict) -> List[Dict]:
        """Handle AlienVault OTX feed format."""
        import httpx
        async with httpx.AsyncClient(timeout=60.0) as client:
            headers = {"X-OTX-API-Key": feed.get("api_key", "")}
            response = await client.get(feed["url"], headers=headers)
            
            if response.status_code != 200:
                raise Exception(f"AlienVault OTX returned {response.status_code}")
            
            data = response.json()
            pulses = data.get("results", [])
            
            iocs = []
            for pulse in pulses:
                for indicator in pulse.get("indicators", []):
                    iocs.append({
                        "type": indicator.get("type", "unknown").lower(),
                        "value": indicator.get("indicator", ""),
                        "source": "AlienVault OTX",
                        "confidence": 0.7,
                        "severity": "medium",
                        "tags": pulse.get("tags", []) + [pulse.get("name", "").lower().replace(" ", "_")],
                        "description": pulse.get("description", ""),
                        "context": {"pulse_id": pulse.get("id"), "adversary": pulse.get("adversary", "")},
                    })
            
            return iocs
    
    async def _handle_abuseipdb(self, feed: Dict) -> List[Dict]:
        """Handle AbuseIPDB feed format."""
        import httpx
        async with httpx.AsyncClient(timeout=60.0) as client:
            headers = {"Key": feed.get("api_key", "")}
            params = {"confidenceMinimum": 50, "limit": 10000}
            response = await client.get(feed["url"], headers=headers, params=params)
            
            if response.status_code != 200:
                raise Exception(f"AbuseIPDB returned {response.status_code}")
            
            data = response.json()
            entries = data.get("data", [])
            
            iocs = []
            for entry in entries:
                confidence = entry.get("abuseConfidenceScore", 50) / 100.0
                iocs.append({
                    "type": "ipv4",
                    "value": entry.get("ipAddress", ""),
                    "source": "AbuseIPDB",
                    "confidence": confidence,
                    "severity": "high" if confidence >= 0.8 else "medium",
                    "tags": ["malicious_ip", "abuseipdb"],
                    "description": entry.get("domain", ""),
                    "context": {
                        "isp": entry.get("isp", ""),
                        "country": entry.get("countryCode", ""),
                        "total_reports": entry.get("totalReports", 0),
                    },
                })
            
            return iocs
    
    async def _handle_misp(self, feed: Dict) -> List[Dict]:
        """Handle MISP feed format."""
        # MISP integration placeholder
        logger.info(f"MISP feed {feed['name']} - using standard event format")
        return []
    
    async def _handle_stix(self, feed: Dict) -> List[Dict]:
        """Handle STIX/TAXII feed format."""
        # STIX integration placeholder
        logger.info(f"STIX feed {feed['name']} - using STIX 2.1 format")
        return []
    
    async def _handle_csv(self, feed: Dict) -> List[Dict]:
        """Handle CSV feed format."""
        import httpx
        import csv
        from io import StringIO
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.get(feed["url"])
            
            if response.status_code != 200:
                raise Exception(f"CSV feed returned {response.status_code}")
            
            content = response.text
            reader = csv.DictReader(StringIO(content))
            
            iocs = []
            for row in reader:
                ioc_type = row.get("type", row.get("indicator_type", "unknown")).lower()
                ioc_value = row.get("value", row.get("indicator", "")).strip()
                
                if ioc_value:
                    iocs.append({
                        "type": ioc_type,
                        "value": ioc_value,
                        "source": feed["name"],
                        "confidence": float(row.get("confidence", 0.5)),
                        "severity": row.get("severity", "medium"),
                        "tags": row.get("tags", "").split(",") if row.get("tags") else [],
                        "description": row.get("description", ""),
                    })
            
            return iocs
    
    async def _handle_json(self, feed: Dict) -> List[Dict]:
        """Handle JSON feed format."""
        import httpx
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.get(feed["url"])
            
            if response.status_code != 200:
                raise Exception(f"JSON feed returned {response.status_code}")
            
            data = response.json()
            
            # Support both array and object formats
            if isinstance(data, dict):
                items = data.get("indicators", data.get("iocs", data.get("data", [])))
            else:
                items = data
            
            iocs = []
            for item in items:
                if isinstance(item, dict):
                    ioc_value = item.get("value", item.get("indicator", ""))
                    ioc_type = item.get("type", item.get("indicator_type", "unknown"))
                    
                    if ioc_value:
                        iocs.append({
                            "type": ioc_type.lower(),
                            "value": str(ioc_value).strip(),
                            "source": feed["name"],
                            "confidence": float(item.get("confidence", 0.5)),
                            "severity": item.get("severity", "medium"),
                            "tags": item.get("tags", item.get("labels", [])),
                            "description": item.get("description", ""),
                            "context": item.get("context", {}),
                        })
            
            return iocs
