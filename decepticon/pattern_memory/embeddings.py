"""Embedding provider wrapper — OpenAI / Anthropic / local."""

from __future__ import annotations

import hashlib
import os
import struct
from typing import Protocol


class EmbeddingProvider(Protocol):
    async def embed(self, text: str) -> list[float]:
        pass


class HashFallbackEmbeddings:
    """Deterministic fallback: SHA-256 of text -> 384 floats in [-1,1].

    Zero-dependency — used for tests and when no API key is set.
    """

    def __init__(self, dim: int = 384):
        self.dim = dim

    async def embed(self, text: str) -> list[float]:
        # Chain hashes to extend into dim floats
        buf = b""
        seed = hashlib.sha256(text.encode("utf-8")).digest()
        while len(buf) < self.dim * 4:
            seed = hashlib.sha256(seed).digest()
            buf += seed
        raw = struct.unpack(f"<{self.dim}I", buf[: self.dim * 4])
        # Normalize to [-1,1]
        return [((x / 2**32) * 2.0) - 1.0 for x in raw]


class OpenAIEmbeddings:
    def __init__(self, model: str = "text-embedding-3-small", api_key: str | None = None):
        self.model = model
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")

    async def embed(self, text: str) -> list[float]:
        if not self.api_key:
            # Gracefully degrade
            return await HashFallbackEmbeddings().embed(text)
        import httpx  # local import to keep load cheap

        async with httpx.AsyncClient(timeout=30.0) as c:
            r = await c.post(
                "https://api.openai.com/v1/embeddings",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={"model": self.model, "input": text},
            )
            r.raise_for_status()
            return list(r.json()["data"][0]["embedding"])


class AnthropicEmbeddings:
    """Anthropic has no native embeddings API; fall back to hash."""

    def __init__(self, model: str = "voyage-3", api_key: str | None = None):
        self.model = model
        self.api_key = api_key or os.getenv("VOYAGE_API_KEY", "")

    async def embed(self, text: str) -> list[float]:
        if not self.api_key:
            return await HashFallbackEmbeddings().embed(text)
        import httpx

        async with httpx.AsyncClient(timeout=30.0) as c:
            r = await c.post(
                "https://api.voyageai.com/v1/embeddings",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={"model": self.model, "input": text},
            )
            if r.status_code >= 400:
                return await HashFallbackEmbeddings().embed(text)
            return list(r.json()["data"][0]["embedding"])


def default_provider() -> EmbeddingProvider:
    if os.getenv("OPENAI_API_KEY"):
        return OpenAIEmbeddings()
    if os.getenv("VOYAGE_API_KEY"):
        return AnthropicEmbeddings()
    return HashFallbackEmbeddings()


__all__ = [
    "AnthropicEmbeddings",
    "EmbeddingProvider",
    "HashFallbackEmbeddings",
    "OpenAIEmbeddings",
    "default_provider",
]
