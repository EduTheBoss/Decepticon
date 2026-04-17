"""Pattern memory: persistent attack-pattern recall across engagements."""

from decepticon.pattern_memory.embeddings import (
    AnthropicEmbeddings,
    EmbeddingProvider,
    HashFallbackEmbeddings,
    OpenAIEmbeddings,
    default_provider,
)
from decepticon.pattern_memory.store import PatternStore

__all__ = [
    "AnthropicEmbeddings",
    "EmbeddingProvider",
    "HashFallbackEmbeddings",
    "OpenAIEmbeddings",
    "PatternStore",
    "default_provider",
]
