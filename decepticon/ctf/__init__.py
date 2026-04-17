"""CTF platform integration + autonomous solver."""

from decepticon.ctf.platforms import (
    CTFAdapter,
    HackTheBoxAdapter,
    Machine,
    TryHackMeAdapter,
    VulnHubAdapter,
)
from decepticon.ctf.solver import CTFResult, CTFSolver, Flag

__all__ = [
    "CTFAdapter",
    "CTFResult",
    "CTFSolver",
    "Flag",
    "HackTheBoxAdapter",
    "Machine",
    "TryHackMeAdapter",
    "VulnHubAdapter",
]
