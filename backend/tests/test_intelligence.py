"""Tests for intelligence repository."""
import pytest
from datetime import datetime, timedelta
from uuid import uuid4

from app.intelligence.repository import IntelligenceRepository, ThreatIntel, IntelSeverity, IntelType
from app.intelligence.ioc_manager import IOCManager, IOC


@pytest.mark.asyncio
async def test_intel_repository():
    """Test intelligence repository operations."""
    repo = IntelligenceRepository()
    
    # Test ingestion
    intel = ThreatIntel(
        indicator="evil.com",
        indicator_type=IntelType.DOMAIN,
        source="test-feed",
        severity=IntelSeverity.HIGH,
        confidence=0.85,
        tags=["malware", "c2"],
    )
    
    intel_id = await repo.ingest_intel(intel)
    assert intel_id is not None
    
    # Test search by indicator
    results = await repo.search_by_indicator("domain", "evil.com")
    assert len(results) == 1
    assert results[0].indicator == "evil.com"
    
    # Test search by tag
    results = await repo.search_by_tag("malware")
    assert len(results) == 1


@pytest.mark.asyncio
async def test_ioc_manager():
    """Test IOC manager operations."""
    manager = IOCManager()
    
    # Test adding IOC
    ioc = IOC(
        id=str(uuid4()),
        type="ipv4",
        value="192.168.1.100",
        source="test",
        confidence=0.9,
        severity="high",
        tags=["malicious"],
    )
    
    ioc_id = await manager.add_ioc(ioc)
    assert ioc_id is not None
    
    # Test lookup
    found = await manager.lookup("ipv4", "192.168.1.100")
    assert found is not None
    assert found.value == "192.168.1.100"
    
    # Test check indicator
    result = await manager.check_indicator("192.168.1.100")
    assert result["malicious"] is True
    assert len(result["matches"]) > 0
    
    # Test nonexistent indicator
    result = await manager.check_indicator("1.2.3.4")
    assert result["malicious"] is False
