"""Plugin discovery and loading."""

from __future__ import annotations

import importlib
import importlib.util
import sys
from importlib.metadata import entry_points
from pathlib import Path

from decepticon.core.logging import get_logger
from decepticon.plugins.types import Plugin

log = get_logger("plugins.loader")


_USER_DIR = Path.home() / ".decepticon" / "plugins"


class PluginLoader:
    def __init__(self):
        self.plugins: list[Plugin] = []

    def _load_file(self, path: Path) -> None:
        mod_name = f"decepticon_user_plugin_{path.stem}"
        spec = importlib.util.spec_from_file_location(mod_name, path)
        if spec is None or spec.loader is None:
            return
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        try:
            spec.loader.exec_module(mod)
        except Exception as e:  # noqa: BLE001
            log.error("plugin.exec_failed", extra={"path": str(path), "err": str(e)})
            return
        for attr in vars(mod).values():
            if isinstance(attr, type) and issubclass(attr, Plugin) and attr is not Plugin:
                try:
                    inst = attr()
                    inst.on_load()
                    self.plugins.append(inst)
                    log.info("plugin.loaded", extra={"name": inst.name, "version": inst.version})
                except Exception as e:  # noqa: BLE001
                    log.error("plugin.init_failed", extra={"cls": attr.__name__, "err": str(e)})

    def discover_user(self, directory: Path | None = None) -> None:
        d = directory or _USER_DIR
        if not d.exists():
            return
        for path in sorted(d.glob("*.py")):
            if path.name.startswith("_"):
                continue
            self._load_file(path)

    def discover_entry_points(self, group: str = "decepticon.plugins") -> None:
        try:
            eps = entry_points(group=group)
        except TypeError:
            # older importlib.metadata
            eps = entry_points().get(group, [])  # type: ignore[assignment]
        for ep in eps:
            try:
                cls = ep.load()
                if isinstance(cls, type) and issubclass(cls, Plugin):
                    inst = cls()
                    inst.on_load()
                    self.plugins.append(inst)
                    log.info("plugin.entrypoint.loaded", extra={"ep": ep.name, "name": inst.name})
            except Exception as e:  # noqa: BLE001
                log.error("plugin.entrypoint.failed", extra={"ep": str(ep), "err": str(e)})

    def discover_all(self, *, user_dir: Path | None = None) -> list[Plugin]:
        self.discover_user(user_dir)
        self.discover_entry_points()
        return self.plugins

    def dispatch(self, hook: str, *args, **kwargs) -> list:
        out = []
        for p in self.plugins:
            fn = getattr(p, hook, None)
            if callable(fn):
                try:
                    out.append(fn(*args, **kwargs))
                except Exception as e:  # noqa: BLE001
                    log.error(
                        "plugin.hook_failed", extra={"name": p.name, "hook": hook, "err": str(e)}
                    )
        return out


__all__ = ["PluginLoader"]
