"""Playbook loader — parse YAML into Playbook models."""

from __future__ import annotations

from pathlib import Path

import yaml

from decepticon.core.logging import get_logger
from decepticon.playbooks.schema import Playbook

log = get_logger("playbooks.loader")


class PlaybookLoader:
    @staticmethod
    def load(path: str | Path) -> Playbook:
        p = Path(path)
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise ValueError(f"playbook {p}: root must be a mapping")
        pb = Playbook.model_validate(raw)
        if not pb.name:
            raise ValueError(f"playbook {p}: name required")
        if not pb.phases:
            raise ValueError(f"playbook {p}: at least one phase required")
        return pb


def list_playbooks(dir_path: str | Path) -> list[Playbook]:
    d = Path(dir_path)
    out: list[Playbook] = []
    if not d.exists():
        return out
    for f in sorted(d.glob("*.yaml")):
        try:
            out.append(PlaybookLoader.load(f))
        except Exception as e:
            log.warning("playbook.load_failed", extra={"path": str(f), "err": str(e)})
    for f in sorted(d.glob("*.yml")):
        try:
            out.append(PlaybookLoader.load(f))
        except Exception as e:
            log.warning("playbook.load_failed", extra={"path": str(f), "err": str(e)})
    return out


__all__ = ["PlaybookLoader", "list_playbooks"]
