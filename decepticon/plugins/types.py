"""Plugin contract."""

from __future__ import annotations

from abc import ABC
from typing import Any


class Plugin(ABC):
    """Base class for Decepticon plugins.

    All hooks have default no-op implementations; override only what you need.
    """

    name: str = "unnamed"
    version: str = "0.0.0"

    def on_load(self) -> None:  # noqa: D401
        """Called once when the plugin is loaded."""

    def on_engagement_start(self, ctx: dict[str, Any]) -> None:
        """Called at the start of each engagement."""

    def on_finding(self, finding: Any) -> None:
        """Called for each new classified finding."""

    def on_engagement_complete(self, ctx: dict[str, Any]) -> None:
        """Called when an engagement finishes."""

    def provides_tools(self) -> list[Any]:
        """Return any LangChain-compatible tools this plugin exposes."""
        return []


__all__ = ["Plugin"]
