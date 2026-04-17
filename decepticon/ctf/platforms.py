"""CTF platform adapters: HackTheBox, TryHackMe, VulnHub."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod

import httpx
from pydantic import BaseModel


class Machine(BaseModel):
    id: str
    name: str
    os: str = ""
    difficulty: str = ""
    ip: str = ""
    platform: str = ""


class CTFAdapter(ABC):
    platform: str = "unknown"

    @abstractmethod
    async def list_machines(self) -> list[Machine]:
        pass

    @abstractmethod
    async def spawn(self, machine_id: str) -> str:
        pass

    @abstractmethod
    async def submit_flag(self, machine_id: str, flag: str) -> bool:
        pass


class HackTheBoxAdapter(CTFAdapter):
    platform = "htb"
    BASE = "https://labs.hackthebox.com/api/v4"

    def __init__(self, api_token: str | None = None):
        self.token = api_token or os.getenv("HTB_API_TOKEN", "")

    def _headers(self) -> dict[str, str]:
        if not self.token:
            raise RuntimeError("HTB API token required")
        return {"Authorization": f"Bearer {self.token}", "User-Agent": "decepticon/1.0"}

    async def list_machines(self) -> list[Machine]:
        async with httpx.AsyncClient(timeout=30.0, headers=self._headers()) as c:
            r = await c.get(f"{self.BASE}/machine/list")
            r.raise_for_status()
            info = r.json().get("info", [])
        out: list[Machine] = []
        for m in info:
            out.append(
                Machine(
                    id=str(m.get("id")),
                    name=str(m.get("name", "")),
                    os=str(m.get("os", "")),
                    difficulty=str(m.get("difficultyText", "")),
                    platform="htb",
                )
            )
        return out

    async def spawn(self, machine_id: str) -> str:
        async with httpx.AsyncClient(timeout=60.0, headers=self._headers()) as c:
            r = await c.post(f"{self.BASE}/machine/play/{machine_id}")
            r.raise_for_status()
            return str(r.json().get("info", {}).get("ip", ""))

    async def submit_flag(self, machine_id: str, flag: str) -> bool:
        async with httpx.AsyncClient(timeout=30.0, headers=self._headers()) as c:
            r = await c.post(
                f"{self.BASE}/flag/own", json={"id": machine_id, "flag": flag, "difficulty": 50}
            )
            if r.status_code >= 400:
                return False
            msg = r.json().get("message", "").lower()
            return "correct" in msg or "success" in msg


class TryHackMeAdapter(CTFAdapter):
    platform = "thm"
    BASE = "https://tryhackme.com/api"

    def __init__(self, session_cookie: str | None = None):
        self.cookie = session_cookie or os.getenv("THM_SESSION_COOKIE", "")

    def _headers(self) -> dict[str, str]:
        h = {"User-Agent": "decepticon/1.0", "Accept": "application/json"}
        if self.cookie:
            h["Cookie"] = f"connect.sid={self.cookie}"
        return h

    async def list_machines(self) -> list[Machine]:
        async with httpx.AsyncClient(timeout=30.0, headers=self._headers()) as c:
            r = await c.get(f"{self.BASE}/rooms/public")
            if r.status_code >= 400:
                return []
            data = r.json() if isinstance(r.json(), list) else []
        return [
            Machine(id=str(x.get("code", "")), name=str(x.get("title", "")), platform="thm")
            for x in data
        ]

    async def spawn(self, machine_id: str) -> str:
        async with httpx.AsyncClient(timeout=60.0, headers=self._headers()) as c:
            r = await c.post(f"{self.BASE}/vpn/startMachine/{machine_id}")
            if r.status_code >= 400:
                return ""
            return str(r.json().get("ip", ""))

    async def submit_flag(self, machine_id: str, flag: str) -> bool:
        async with httpx.AsyncClient(timeout=30.0, headers=self._headers()) as c:
            r = await c.post(f"{self.BASE}/room/{machine_id}/answer", json={"answer": flag})
            return 200 <= r.status_code < 300


class VulnHubAdapter(CTFAdapter):
    """VulnHub is metadata-only — machines run locally."""

    platform = "vulnhub"

    async def list_machines(self) -> list[Machine]:
        return []

    async def spawn(self, machine_id: str) -> str:
        return ""

    async def submit_flag(self, machine_id: str, flag: str) -> bool:  # noqa: ARG002
        # VulnHub has no submission API; accept any non-empty flag.
        return bool(flag)


__all__ = [
    "CTFAdapter",
    "HackTheBoxAdapter",
    "Machine",
    "TryHackMeAdapter",
    "VulnHubAdapter",
]
