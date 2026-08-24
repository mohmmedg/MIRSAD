"""Safe extension registry.

Plugins are registered in-process by application code. Arbitrary files are
never auto-imported from a writable directory.
"""
from dataclasses import dataclass
from typing import Callable, Any

@dataclass(frozen=True)
class Plugin:
    name: str
    version: str
    kind: str
    runner: Callable[..., Any]

class PluginRegistry:
    def __init__(self): self._plugins: dict[str, Plugin] = {}
    def register(self, plugin: Plugin):
        if plugin.name in self._plugins: raise ValueError(f"Plugin already registered: {plugin.name}")
        self._plugins[plugin.name]=plugin
    def list(self): return [{"name":p.name,"version":p.version,"kind":p.kind} for p in self._plugins.values()]
    def get(self,name): return self._plugins.get(name)

registry=PluginRegistry()
