"""Playbook schema — YAML-driven multi-phase attack recipes."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Author(BaseModel):
    name: str = ""
    github: str = ""
    email: str = ""


class PlaybookVar(BaseModel):
    type: str = "string"
    required: bool = False
    default: str = ""
    description: str = ""


class ToolSpec(BaseModel):
    name: str
    options: dict = Field(default_factory=dict)
    command: str = ""  # raw command for custom scripts
    agent: str = ""  # override: which agent runs this tool


class Phase(BaseModel):
    name: str
    description: str = ""
    agents: list[str] = Field(default_factory=list)
    tools: list[ToolSpec] = Field(default_factory=list)
    post_analysis: str = ""
    depends_on: list[str] = Field(default_factory=list)
    conditions: list[str] = Field(default_factory=list)
    strategy: str = ""


class Playbook(BaseModel):
    name: str
    description: str = ""
    author: Author = Field(default_factory=Author)
    version: str = "1.0.0"
    tags: list[str] = Field(default_factory=list)
    variables: dict[str, PlaybookVar] = Field(default_factory=dict)
    phases: list[Phase] = Field(default_factory=list)
    include: list[str] = Field(default_factory=list)


__all__ = ["Author", "Phase", "Playbook", "PlaybookVar", "ToolSpec"]
