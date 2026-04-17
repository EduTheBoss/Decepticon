"""Playbook runner — templates vars, resolves deps, invokes agents per phase."""

from __future__ import annotations

from string import Template
from typing import Any, Awaitable, Callable

from decepticon.core.logging import get_logger
from decepticon.playbooks.schema import Phase, Playbook, ToolSpec

log = get_logger("playbooks.runner")


AgentInvoker = Callable[[str, str, dict[str, Any]], Awaitable[Any]]
"""Signature: (agent_name, phase_name, context) -> result."""


class PlaybookRunner:
    def __init__(self, *, invoker: AgentInvoker | None = None):
        self.invoker = invoker

    # ── Variable resolution ──────────────────────────────────────────

    @staticmethod
    def resolve_variables(pb: Playbook, user_vars: dict[str, str]) -> dict[str, str]:
        resolved: dict[str, str] = {}
        for key, var in pb.variables.items():
            if key in user_vars:
                resolved[key] = user_vars[key]
            elif var.default:
                resolved[key] = var.default
            elif var.required:
                raise ValueError(f"playbook var {key!r} is required but not provided")
            else:
                resolved[key] = ""
        # Also pass through any user var not declared
        for k, v in user_vars.items():
            resolved.setdefault(k, v)
        return resolved

    @staticmethod
    def _substitute(obj: Any, vars: dict[str, str]) -> Any:
        if isinstance(obj, str):
            return Template(obj).safe_substitute(vars)
        if isinstance(obj, list):
            return [PlaybookRunner._substitute(x, vars) for x in obj]
        if isinstance(obj, dict):
            return {k: PlaybookRunner._substitute(v, vars) for k, v in obj.items()}
        return obj

    # ── Topo sort for depends_on ─────────────────────────────────────

    @staticmethod
    def _topo(phases: list[Phase]) -> list[Phase]:
        by_name = {p.name: p for p in phases}
        order: list[Phase] = []
        seen: set[str] = set()
        temp: set[str] = set()

        def visit(p: Phase) -> None:
            if p.name in seen:
                return
            if p.name in temp:
                raise ValueError(f"playbook phase cycle at {p.name!r}")
            temp.add(p.name)
            for dep in p.depends_on:
                if dep in by_name:
                    visit(by_name[dep])
            temp.discard(p.name)
            seen.add(p.name)
            order.append(p)

        for p in phases:
            visit(p)
        return order

    # ── Execution ────────────────────────────────────────────────────

    async def run(
        self,
        pb: Playbook,
        target: str,
        user_vars: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        user_vars = dict(user_vars or {})
        user_vars.setdefault("target", target)
        user_vars.setdefault("target_domain", target)
        vars = self.resolve_variables(pb, user_vars)

        ordered = self._topo(pb.phases)
        results: list[dict[str, Any]] = []

        for phase in ordered:
            ctx = {
                "target": target,
                "vars": vars,
                "tools": [self._substitute(t.model_dump(), vars) for t in phase.tools],
                "post_analysis": self._substitute(phase.post_analysis, vars),
                "strategy": phase.strategy,
                "conditions": phase.conditions,
            }
            log.info("playbook.phase.start", extra={"playbook": pb.name, "phase": phase.name})
            phase_result: dict[str, Any] = {"phase": phase.name, "agents": []}

            # Fall back to tool-name-implied agents when no explicit agent listed
            agents = phase.agents or self._implied_agents(phase.tools)

            if self.invoker:
                for agent in agents:
                    out = await self.invoker(agent, phase.name, ctx)
                    phase_result["agents"].append({"agent": agent, "out": out})
            else:
                phase_result["agents"] = [{"agent": a, "out": "dry-run"} for a in agents]
            results.append(phase_result)
            log.info("playbook.phase.done", extra={"playbook": pb.name, "phase": phase.name})
        return results

    @staticmethod
    def _implied_agents(tools: list[ToolSpec]) -> list[str]:
        # Map common tool names to DEC agent roles
        mapping = {
            "subfinder": "recon",
            "httpx": "recon",
            "katana": "recon",
            "gau": "recon",
            "dnsx": "recon",
            "naabu": "recon",
            "nuclei": "exploit",
            "sqlmap": "exploit",
            "ffuf": "exploit",
            "kerbrute": "postexploit",
            "impacket": "postexploit",
            "bloodhound": "postexploit",
        }
        agents: list[str] = []
        for t in tools:
            a = t.agent or mapping.get(t.name, "")
            if a and a not in agents:
                agents.append(a)
        return agents or ["exploit"]


__all__ = ["PlaybookRunner", "AgentInvoker"]
