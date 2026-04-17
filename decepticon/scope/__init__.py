"""Scope validation — deny-by-default target gating."""

from decepticon.scope.middleware import ScopeMiddleware
from decepticon.scope.validator import (
    ScopeAction,
    ScopeKind,
    ScopeResult,
    ScopeRule,
    ScopeValidator,
)

__all__ = [
    "ScopeAction",
    "ScopeKind",
    "ScopeMiddleware",
    "ScopeResult",
    "ScopeRule",
    "ScopeValidator",
]
