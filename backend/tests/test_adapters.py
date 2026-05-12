"""Tests for tool adapters."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from app.adapters.base import BaseToolAdapter, ToolAdapterRegistry
from app.adapters.burpsuite import BurpSuiteAdapter
from app.adapters.pentestgpt import PentestGPTAdapter
from app.adapters.metasploit import MetasploitAdapter
from app.config import Settings


@pytest.mark.asyncio
async def test_adapter_registry():
    """Test tool adapter registry."""
    registry = ToolAdapterRegistry()
    
    # Test registration
    registry.register("test_adapter", PentestGPTAdapter)
    assert "test_adapter" in registry.get_registered_adapters()
    
    # Test double registration
    with pytest.raises(ValueError):
        registry.register("test_adapter", PentestGPTAdapter)
    
    # Test get adapter
    adapter_cls = registry.get_adapter("test_adapter")
    assert adapter_cls == PentestGPTAdapter
    
    # Test get nonexistent
    adapter_cls = registry.get_adapter("nonexistent")
    assert adapter_cls is None


@pytest.mark.asyncio
async def test_pentestgpt_adapter(settings):
    """Test PentestGPT adapter."""
    adapter = PentestGPTAdapter(settings)
    
    # Mock health check
    with patch.object(adapter, '_check_health', new_callable=AsyncMock) as mock_health:
        mock_health.return_value = True
        health = await adapter.health_check()
        assert health is True


@pytest.mark.asyncio
async def test_burpsuite_adapter(settings, mock_httpx_client):
    """Test BurpSuite adapter."""
    adapter = BurpSuiteAdapter(settings)
    
    # Mock health check response
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {}
    mock_httpx_client.get.return_value = mock_response
    
    health = await adapter.health_check()
    assert health is True


@pytest.mark.asyncio
async def test_metasploit_adapter(settings):
    """Test Metasploit adapter initialization."""
    adapter = MetasploitAdapter(settings)
    assert adapter.host == "127.0.0.1"
    assert adapter.port == 55553


@pytest.mark.asyncio
async def test_adapter_execute_scan(settings):
    """Test executing a scan through adapter."""
    adapter = PentestGPTAdapter(settings)
    target = "test.example.com"
    
    with patch.object(adapter, 'execute_scan', new_callable=AsyncMock) as mock_execute:
        mock_execute.return_value = {"status": "completed", "findings": []}
        result = await adapter.execute_scan(target)
        assert result["status"] == "completed"
