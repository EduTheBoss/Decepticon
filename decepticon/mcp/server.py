"""Decepticon MCP server — stdio transport via the official ``mcp`` SDK."""

from __future__ import annotations

import json
import sys
from typing import Any

from decepticon.core.logging import get_logger
from decepticon.mcp import tools as dec_tools

log = get_logger("mcp.server")


def _build_app():
    """Build the MCP server app. Imported lazily so ``mcp`` isn't required for the rest of the package."""
    try:
        from mcp.server import Server  # type: ignore
        from mcp.types import TextContent, Tool  # type: ignore
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("mcp Python SDK not installed; add `mcp>=1.0.0` to pyproject") from e

    app: Any = Server("decepticon")

    def _as_text(v: Any) -> list:
        return [TextContent(type="text", text=json.dumps(v, indent=2, default=str))]

    @app.list_tools()  # type: ignore[misc]
    async def _list_tools() -> list:  # noqa: ANN202
        return [
            Tool(
                name="start_engagement",
                description="Start a new autonomous penetration test engagement.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "objective": {"type": "string"},
                        "scope": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["target"],
                },
            ),
            Tool(
                name="get_findings",
                description="Retrieve findings from the workspace (optionally filtered by engagement).",
                inputSchema={
                    "type": "object",
                    "properties": {"engagement_id": {"type": "string"}},
                },
            ),
            Tool(
                name="get_status",
                description="Get the status of a running engagement.",
                inputSchema={
                    "type": "object",
                    "properties": {"engagement_id": {"type": "string"}},
                    "required": ["engagement_id"],
                },
            ),
            Tool(
                name="emergency_stop",
                description="Run LIFO cleanup ledger and abort any running campaign.",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="list_skills",
                description="List installed Decepticon skills (soundwave etc.).",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="list_playbooks",
                description="List available playbooks from ./playbooks/.",
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="run_playbook",
                description="Execute a named playbook against a target.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "target": {"type": "string"},
                        "variables": {"type": "object"},
                    },
                    "required": ["name", "target"],
                },
            ),
        ]

    @app.call_tool()  # type: ignore[misc]
    async def _call_tool(name: str, arguments: dict[str, Any]) -> list:  # noqa: ANN202
        log.info("mcp.tool_call", extra={"name": name, "args": list(arguments)})
        try:
            if name == "start_engagement":
                return _as_text(await dec_tools.start_engagement(**arguments))
            if name == "get_findings":
                return _as_text(await dec_tools.get_findings(**arguments))
            if name == "get_status":
                return _as_text(await dec_tools.get_status(**arguments))
            if name == "emergency_stop":
                return _as_text(await dec_tools.emergency_stop_tool())
            if name == "list_skills":
                return _as_text(await dec_tools.list_skills())
            if name == "list_playbooks":
                return _as_text(await dec_tools.list_playbooks_tool())
            if name == "run_playbook":
                return _as_text(await dec_tools.run_playbook(**arguments))
        except Exception as e:  # noqa: BLE001
            log.error("mcp.tool_error", extra={"name": name, "err": str(e)})
            return _as_text({"error": str(e)})
        return _as_text({"error": f"unknown tool: {name}"})

    return app


def main() -> None:
    """stdio entry point — ``python -m decepticon.mcp.server``."""
    try:
        import anyio  # type: ignore
        from mcp.server.stdio import stdio_server  # type: ignore
    except ImportError:  # pragma: no cover
        print("mcp Python SDK not installed; pip install mcp", file=sys.stderr)
        sys.exit(2)

    app = _build_app()

    async def _serve() -> None:
        async with stdio_server() as (read, write):
            await app.run(read, write, app.create_initialization_options())

    anyio.run(_serve)


__all__ = ["main"]
