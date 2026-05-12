"""Test configuration and fixtures."""
import pytest
import asyncio
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock, patch

from platform.config import Settings


@pytest.fixture
def settings():
    """Provide test settings."""
    return Settings(
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        REDIS_URL="redis://localhost:6379/0",
        JWT_SECRET="test-secret",
        ENVIRONMENT="test",
    )


@pytest.fixture
def mock_httpx_client():
    """Mock httpx async client for adapter tests."""
    with patch('httpx.AsyncClient') as mock:
        client = AsyncMock()
        mock.return_value = client
        yield client


@pytest.fixture
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
