"""Tests for LLM client."""

import os
import pytest
from unittest.mock import AsyncMock, patch

from core.llm_client import LLMClient, LLMConfig


@pytest.fixture
def mock_config():
    """Mock LLM configuration."""
    return LLMConfig(
        api_key="test_key",
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        temperature=0.3,
    )


@pytest.fixture
def llm_client(mock_config):
    """Create LLM client with mock config."""
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test_key"}):
        return LLMClient(config=mock_config)


@pytest.mark.asyncio
async def test_llm_client_initialization(llm_client):
    """Test LLM client initialization."""
    assert llm_client.config.api_key == "test_key"
    assert llm_client.config.model == "claude-sonnet-4-20250514"


@pytest.mark.asyncio
async def test_generate_with_mock(llm_client):
    """Test text generation with mocked API."""
    with patch.object(llm_client.async_client.messages, "create") as mock_create:
        mock_response = AsyncMock()
        mock_response.content = [AsyncMock(text="Test response")]
        mock_create.return_value = mock_response

        result = await llm_client.generate("Test prompt")
        assert result == "Test response"
        mock_create.assert_called_once()


@pytest.mark.asyncio
async def test_get_stats(llm_client):
    """Test getting client statistics."""
    stats = llm_client.get_stats()
    assert "request_count" in stats
    assert "model" in stats
    assert stats["model"] == "claude-sonnet-4-20250514"

