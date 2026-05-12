"""Indicator of Compromise (IoC) management."""
import logging
import re
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta
from uuid import uuid4
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class IOC:
    """Indicator of Compromise."""
    id: str
    type: str  # ipv4, ipv6, domain, url, hash_md5, hash_sha1, hash_sha256, email, file_path
    value: str
    source: str
    confidence: float = 0.5
    severity: str = "medium"
    tags: List[str] = field(default_factory=list)
    description: str = ""
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    expires: Optional[datetime] = None
    tlp: str = "AMBER"
    context: Dict[str, Any] = field(default_factory=dict)


class IOCManager:
    """Manages Indicators of Compromise."""
    
    def __init__(self):
        self._iocs: Dict[str, IOC] = {}
        self._type_index: Dict[str, Set[str]] = {}
        self._tag_index: Dict[str, Set[str]] = {}
        self._value_index: Dict[str, str] = {}  # normalized value -> IOC ID
    
    async def add_ioc(self, ioc: IOC) -> str:
        """Add a new IOC to the repository."""
        ioc_id = ioc.id or str(uuid4())
        ioc.id = ioc_id
        
        self._iocs[ioc_id] = ioc
        
        # Index by type
        if ioc.type not in self._type_index:
            self._type_index[ioc.type] = set()
        self._type_index[ioc.type].add(ioc_id)
        
        # Index by tags
        for tag in ioc.tags:
            tag_key = tag.lower()
            if tag_key not in self._tag_index:
                self._tag_index[tag_key] = set()
            self._tag_index[tag_key].add(ioc_id)
        
        # Index by normalized value
        norm_value = self._normalize_value(ioc.type, ioc.value)
        if norm_value:
            self._value_index[norm_value] = ioc_id
        
        logger.info(f"Added IOC {ioc_id}: [{ioc.type}] {ioc.value}")
        return ioc_id
    
    async def add_iocs_batch(self, iocs: List[IOC]) -> List[str]:
        """Add multiple IOCs at once."""
        return [await self.add_ioc(ioc) for ioc in iocs]
    
    async def lookup(self, ioc_type: str, value: str) -> Optional[IOC]:
        """Lookup an IOC by type and value."""
        norm_value = self._normalize_value(ioc_type, value)
        if not norm_value:
            return None
        
        ioc_id = self._value_index.get(norm_value)
        if ioc_id and ioc_id in self._iocs:
            ioc = self._iocs[ioc_id]
            ioc.last_seen = datetime.utcnow()
            return ioc
        
        return None
    
    async def lookup_batch(self, indicators: List[Dict]) -> List[Dict]:
        """Lookup multiple indicators at once."""
        results = []
        for ind in indicators:
            ioc = await self.lookup(ind.get("type", ""), ind.get("value", ""))
            results.append({
                "indicator": ind,
                "match": ioc.__dict__ if ioc else None,
                "found": ioc is not None,
            })
        return results
    
    async def search_by_type(self, ioc_type: str) -> List[IOC]:
        """Get all IOCs of a specific type."""
        ioc_ids = self._type_index.get(ioc_type, set())
        return [self._iocs[i] for i in ioc_ids if i in self._iocs]
    
    async def search_by_tag(self, tag: str) -> List[IOC]:
        """Get IOCs with a specific tag."""
        tag_key = tag.lower()
        ioc_ids = self._tag_index.get(tag_key, set())
        return [self._iocs[i] for i in ioc_ids if i in self._iocs]
    
    async def check_indicator(self, indicator: str) -> Dict[str, Any]:
        """Check if an indicator string matches any known IOCs."""
        results = []
        
        # Detect type from value format
        detected_type = self._detect_type(indicator)
        
        # Try exact match
        if detected_type:
            ioc = await self.lookup(detected_type, indicator)
            if ioc:
                results.append({
                    "matched": True,
                    "type": detected_type,
                    "ioc_id": ioc.id,
                    "confidence": ioc.confidence,
                    "source": ioc.source,
                    "malicious": ioc.confidence >= 0.7,
                })
        
        # Hash lookup (try all hash types)
        if re.match(r'^[a-f0-9]{32}$', indicator, re.IGNORECASE):
            results.extend(await self._check_hash_types(indicator))
        
        return {
            "indicator": indicator,
            "detected_type": detected_type,
            "matches": results,
            "total_matches": len(results),
            "malicious": any(r.get("malicious") for r in results),
        }
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get IOC repository statistics."""
        type_counts = {}
        for ioc in self._iocs.values():
            type_counts[ioc.type] = type_counts.get(ioc.type, 0) + 1
        
        return {
            "total_iocs": len(self._iocs),
            "by_type": type_counts,
            "unique_tags": len(self._tag_index),
            "high_confidence": sum(1 for i in self._iocs.values() if i.confidence >= 0.8),
        }
    
    def _normalize_value(self, ioc_type: str, value: str) -> Optional[str]:
        """Normalize an IOC value for consistent lookup."""
        value = value.strip()
        
        if ioc_type in ("hash_md5", "hash_sha1", "hash_sha256"):
            return value.lower()
        elif ioc_type in ("ipv4", "ipv6"):
            return value
        elif ioc_type == "domain":
            return value.lower().lstrip("*.")
        elif ioc_type == "url":
            return value.rstrip("/").lower()
        
        return value.lower()
    
    def _detect_type(self, indicator: str) -> Optional[str]:
        """Detect the type of an indicator from its format."""
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator):
            return "ipv4"
        if re.match(r'^[a-f0-9:]+$', indicator, re.IGNORECASE) and ":" in indicator:
            return "ipv6"
        if re.match(r'^[a-f0-9]{32}$', indicator, re.IGNORECASE):
            return "hash_md5"
        if re.match(r'^[a-f0-9]{40}$', indicator, re.IGNORECASE):
            return "hash_sha1"
        if re.match(r'^[a-f0-9]{64}$', indicator, re.IGNORECASE):
            return "hash_sha256"
        if "." in indicator and " " not in indicator and "/" not in indicator:
            return "domain"
        if indicator.startswith("http://") or indicator.startswith("https://"):
            return "url"
        if "@" in indicator and "." in indicator:
            return "email"
        
        return None
    
    async def _check_hash_types(self, hash_value: str) -> List[Dict]:
        """Check a hash against all hash type indices."""
        results = []
        for htype in ["hash_md5", "hash_sha1", "hash_sha256"]:
            ioc = await self.lookup(htype, hash_value)
            if ioc:
                results.append({
                    "matched": True,
                    "type": htype,
                    "ioc_id": ioc.id,
                    "confidence": ioc.confidence,
                    "source": ioc.source,
                    "malicious": ioc.confidence >= 0.7,
                })
        return results
