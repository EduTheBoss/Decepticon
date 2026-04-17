"""CTF solver — builds a CTF-specific OPPLAN and auto-submits flags."""

from __future__ import annotations

import re
from typing import Awaitable, Callable

from pydantic import BaseModel, Field

from decepticon.core.logging import get_logger
from decepticon.ctf.platforms import CTFAdapter, Machine

log = get_logger("ctf.solver")


FLAG_PATTERNS = (
    re.compile(r"HTB\{[^}]+\}"),
    re.compile(r"THM\{[^}]+\}"),
    re.compile(r"flag\{[^}]+\}"),
    re.compile(r"[a-f0-9]{32}"),  # md5-style user.txt / root.txt
)


class Flag(BaseModel):
    type: str  # user | root | flag
    value: str
    source: str = ""


class CTFResult(BaseModel):
    machine: Machine
    flags: list[Flag] = Field(default_factory=list)
    narrative: str = ""
    success: bool = False


class CTFSolver:
    """Drive an engagement against a CTF machine.

    ``agent_runner`` is an async callable ``(objective: str, target: str) -> str``
    that returns the merged stdout of the agent session. The solver scans
    the output for flag patterns and auto-submits to the platform.
    """

    def __init__(
        self,
        adapter: CTFAdapter,
        *,
        agent_runner: Callable[[str, str], Awaitable[str]] | None = None,
    ):
        self.adapter = adapter
        self.agent_runner = agent_runner

    @staticmethod
    def build_objective(machine: Machine) -> str:
        return (
            f"CTF: Capture user.txt and root.txt on {machine.name} ({machine.os}, "
            f"{machine.difficulty}). Focus on enumeration -> initial foothold -> "
            "privilege escalation. Check SUID binaries, cron jobs, writable "
            "scripts, kernel exploits, password reuse. Report each flag found."
        )

    @staticmethod
    def extract_flags(text: str) -> list[Flag]:
        flags: list[Flag] = []
        seen: set[str] = set()
        for pat in FLAG_PATTERNS:
            for m in pat.finditer(text):
                v = m.group(0)
                if v in seen:
                    continue
                seen.add(v)
                ftype = (
                    "user"
                    if "user" in text[max(0, m.start() - 100) : m.start()].lower()
                    else "flag"
                )
                if "root" in text[max(0, m.start() - 100) : m.start()].lower():
                    ftype = "root"
                flags.append(Flag(type=ftype, value=v))
        return flags

    async def solve_machine(self, machine: Machine | str) -> CTFResult:
        if isinstance(machine, str):
            machine = Machine(id=machine, name=machine, platform=self.adapter.platform)
        ip = await self.adapter.spawn(machine.id)
        if ip:
            machine.ip = ip
        objective = self.build_objective(machine)
        log.info("ctf.solve_start", extra={"machine": machine.name, "ip": ip})

        output = ""
        if self.agent_runner:
            output = await self.agent_runner(objective, machine.ip or machine.name)
        flags = self.extract_flags(output)

        # Auto-submit
        for f in flags:
            ok = False
            try:
                ok = await self.adapter.submit_flag(machine.id, f.value)
            except Exception as e:  # noqa: BLE001
                log.warning("ctf.submit_error", extra={"flag": f.value, "err": str(e)})
            log.info("ctf.submit", extra={"flag": f.value, "ok": ok})

        result = CTFResult(
            machine=machine,
            flags=flags,
            narrative=output[:8000],
            success=bool(flags),
        )
        return result


__all__ = ["CTFResult", "CTFSolver", "Flag", "FLAG_PATTERNS"]
