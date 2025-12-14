"""
LLM Client for Anthropic Claude API integration.
Handles API calls, retry logic, rate limiting, and streaming.
"""

import asyncio
import logging
import os
import time
from typing import Any, AsyncIterator, Dict, List, Optional

from anthropic import Anthropic, AsyncAnthropic
from anthropic.types import Message, MessageParam
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class LLMConfig(BaseModel):
    """Configuration for LLM client."""

    api_key: str = Field(..., description="Anthropic API key")
    model: str = Field(default="claude-sonnet-4-20250514", description="Model name")
    max_tokens: int = Field(default=4096, description="Maximum tokens to generate")
    temperature: float = Field(default=0.3, description="Temperature for generation")
    timeout: int = Field(default=60, description="Request timeout in seconds")
    retry_attempts: int = Field(default=3, description="Number of retry attempts")
    retry_delay: int = Field(default=2, description="Delay between retries in seconds")


class LLMClient:
    """Client for interacting with Anthropic Claude API."""

    def __init__(self, config: Optional[LLMConfig] = None):
        """
        Initialize LLM client.

        Args:
            config: LLM configuration. If None, loads from environment.
        """
        if config is None:
            config = LLMConfig(
                api_key=os.getenv("ANTHROPIC_API_KEY", ""),
                model=os.getenv("LLM_MODEL", "claude-sonnet-4-20250514"),
                max_tokens=int(os.getenv("LLM_MAX_TOKENS", "4096")),
                temperature=float(os.getenv("LLM_TEMPERATURE", "0.3")),
                timeout=int(os.getenv("LLM_TIMEOUT", "60")),
                retry_attempts=int(os.getenv("LLM_RETRY_ATTEMPTS", "3")),
                retry_delay=int(os.getenv("LLM_RETRY_DELAY", "2")),
            )

        if not config.api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable is required")

        self.config = config
        self.client = Anthropic(api_key=config.api_key, timeout=config.timeout)
        self.async_client = AsyncAnthropic(
            api_key=config.api_key, timeout=config.timeout
        )
        self._request_count = 0
        self._last_request_time = 0.0

    def _calculate_tokens(self, text: str) -> int:
        """
        Estimate token count (rough approximation).

        Args:
            text: Input text

        Returns:
            Estimated token count
        """
        # Rough approximation: 1 token ≈ 4 characters
        return len(text) // 4

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        stream: bool = False,
    ) -> str:
        """
        Generate text using Claude API.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            max_tokens: Override max tokens
            temperature: Override temperature
            stream: Whether to stream the response

        Returns:
            Generated text
        """
        if stream:
            return await self.generate_stream(
                prompt=prompt,
                system_prompt=system_prompt,
                max_tokens=max_tokens,
                temperature=temperature,
            )

        max_tokens = max_tokens or self.config.max_tokens
        temperature = temperature or self.config.temperature

        messages: List[MessageParam] = [{"role": "user", "content": prompt}]

        for attempt in range(self.config.retry_attempts):
            try:
                response = await self.async_client.messages.create(
                    model=self.config.model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    system=system_prompt,
                    messages=messages,
                )

                self._request_count += 1
                self._last_request_time = time.time()

                if response.content and len(response.content) > 0:
                    content = response.content[0]
                    if hasattr(content, "text"):
                        return content.text
                    return str(content)

                return ""

            except Exception as e:
                logger.warning(
                    f"LLM API call failed (attempt {attempt + 1}/{self.config.retry_attempts}): {str(e)}"
                )
                if attempt < self.config.retry_attempts - 1:
                    await asyncio.sleep(self.config.retry_delay * (attempt + 1))
                else:
                    logger.error(f"LLM API call failed after {self.config.retry_attempts} attempts")
                    raise

    async def generate_stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> str:
        """
        Generate text with streaming.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            max_tokens: Override max tokens
            temperature: Override temperature

        Returns:
            Complete generated text
        """
        max_tokens = max_tokens or self.config.max_tokens
        temperature = temperature or self.config.temperature

        messages: List[MessageParam] = [{"role": "user", "content": prompt}]

        full_text = ""
        try:
            async with self.async_client.messages.stream(
                model=self.config.model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system_prompt,
                messages=messages,
            ) as stream:
                async for text in stream.text_stream:
                    full_text += text

            self._request_count += 1
            self._last_request_time = time.time()
            return full_text

        except Exception as e:
            logger.error(f"LLM streaming failed: {str(e)}")
            raise

    async def generate_with_tools(
        self,
        prompt: str,
        tools: List[Dict[str, Any]],
        system_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate response with tool calling support.

        Args:
            prompt: User prompt
            tools: List of tool definitions
            system_prompt: Optional system prompt

        Returns:
            Response with potential tool calls
        """
        messages: List[MessageParam] = [{"role": "user", "content": prompt}]

        try:
            response = await self.async_client.messages.create(
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                system=system_prompt,
                messages=messages,
                tools=tools,
            )

            self._request_count += 1
            self._last_request_time = time.time()

            result = {
                "content": "",
                "tool_calls": [],
            }

            if response.content:
                for content_block in response.content:
                    if hasattr(content_block, "text"):
                        result["content"] += content_block.text
                    elif hasattr(content_block, "name"):
                        result["tool_calls"].append(
                            {
                                "name": content_block.name,
                                "input": getattr(content_block, "input", {}),
                            }
                        )

            return result

        except Exception as e:
            logger.error(f"LLM tool calling failed: {str(e)}")
            raise

    def get_stats(self) -> Dict[str, Any]:
        """
        Get client statistics.

        Returns:
            Dictionary with stats
        """
        return {
            "request_count": self._request_count,
            "last_request_time": self._last_request_time,
            "model": self.config.model,
        }

