"""ScopeMiddleware — deny-by-default bash gate.

Intercepts ``bash`` tool calls and runs the command string through a
``ScopeValidator``. Out-of-scope calls return a ToolMessage without ever
reaching the sandbox. Mirrors the middleware pattern used by
``decepticon.middleware.safe_command``.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage
from langgraph.prebuilt.tool_node import ToolCallRequest
from langgraph.types import Command

from decepticon.core.logging import get_logger
from decepticon.scope.validator import ScopeValidator

log = get_logger("scope.middleware")


class ScopeMiddleware(AgentMiddleware):
    """Block bash tool calls whose extracted targets are out of scope."""

    def __init__(self, validator: ScopeValidator, *, tool_names: tuple[str, ...] = ("bash",)):
        super().__init__()
        self.validator = validator
        self.tool_names = tool_names

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[Any]],
    ) -> Any:
        tool_name = getattr(request.tool_call, "name", None)
        if tool_name not in self.tool_names:
            return await handler(request)

        args = getattr(request.tool_call, "args", {}) or {}
        command = args.get("command") or args.get("cmd") or ""
        if not isinstance(command, str) or not command.strip():
            return await handler(request)

        result = self.validator.validate(command)
        if result.allowed:
            return await handler(request)

        log.warning(
            "scope.middleware.block",
            extra={"command": command[:200], "reason": result.reason, "target": result.target},
        )
        return Command(
            update={
                "messages": [
                    ToolMessage(
                        content=f"SCOPE DENIED: {result.reason}",
                        tool_call_id=getattr(request.tool_call, "id", ""),
                        name=tool_name,
                        status="error",
                    )
                ]
            }
        )


__all__ = ["ScopeMiddleware"]
