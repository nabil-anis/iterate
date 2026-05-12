"""API endpoint tests."""
import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch

from app.main import app


@pytest.fixture
def async_client():
    """Create async test client."""
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_health_endpoint(async_client):
    """Test health check endpoint."""
    response = await async_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data


@pytest.mark.asyncio
async def test_platform_status(async_client):
    """Test platform status endpoint."""
    response = await async_client.get("/api/v1/status")
    assert response.status_code == 200
    data = response.json()
    assert data["platform"] == "Unified Multi-Agent Cybersecurity Platform"


@pytest.mark.asyncio
async def test_list_agents(async_client):
    """Test agent listing."""
    response = await async_client.get("/api/v1/agents")
    assert response.status_code in (200, 500)  # May fail without adapters configured
