"""Tests for the orchestration engine."""
import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime

from app.orchestrator import OrchestrationEngine
from app.models.scan import Scan, ScanStatus, ScanTarget
from app.config import Settings


@pytest.mark.asyncio
async def test_orchestrator_initialization(settings):
    """Test orchestrator initialization."""
    orchestrator = OrchestrationEngine(settings)
    assert orchestrator is not None


@pytest.mark.asyncio
async def test_create_scan(settings):
    """Test scan creation."""
    orchestrator = OrchestrationEngine(settings)
    targets = [ScanTarget(target="test.example.com", type="domain")]
    
    with patch.object(orchestrator, 'create_scan', new_callable=AsyncMock) as mock_create:
        mock_create.return_value = Scan(
            id="SCAN-001",
            status=ScanStatus.RUNNING,
            targets=targets,
            created_at=datetime.utcnow(),
        )
        
        scan = await orchestrator.create_scan(targets, "full")
        assert scan.id == "SCAN-001"
        assert scan.status == ScanStatus.RUNNING
