"""Tests for the analysis engine."""
import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime

from app.analysis import UnifiedAnalysisEngine
from app.models.finding import Finding, FindingSeverity, FindingStatus


@pytest.fixture
def analysis_engine():
    """Create analysis engine for testing."""
    return UnifiedAnalysisEngine()


@pytest.mark.asyncio
async def test_correlate_findings(analysis_engine):
    """Test finding correlation."""
    findings = [
        Finding(
            id="F001",
            title="SQL Injection",
            description="SQL injection in login form",
            severity=FindingSeverity.CRITICAL,
            target="app.example.com",
            type="sql_injection",
            timestamp=datetime.utcnow(),
        ),
        Finding(
            id="F002",
            title="XSS Vulnerability",
            description="Cross-site scripting in search",
            severity=FindingSeverity.HIGH,
            target="app.example.com",
            type="xss",
            timestamp=datetime.utcnow(),
        ),
    ]
    
    correlated = await analysis_engine.correlate(findings)
    assert "correlations" in correlated


@pytest.mark.asyncio
async def test_prioritize_findings(analysis_engine):
    """Test finding prioritization."""
    findings = [
        Finding(id="F001", title="Critical SQLi", severity=FindingSeverity.CRITICAL, 
                target="a.com", type="sqli", timestamp=datetime.utcnow()),
        Finding(id="F002", title="Info Header", severity=FindingSeverity.INFO,
                target="b.com", type="info", timestamp=datetime.utcnow()),
    ]
    
    prioritized = await analysis_engine.prioritize(findings)
    assert len(prioritized) == 2
    assert prioritized[0].severity == FindingSeverity.CRITICAL


@pytest.mark.asyncio
async def test_empty_findings(analysis_engine):
    """Test with no findings."""
    result = await analysis_engine.correlate([])
    assert result == {"correlations": [], "summary": "No findings to correlate"}
