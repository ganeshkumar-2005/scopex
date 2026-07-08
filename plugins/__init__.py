"""
ScopeX Advanced Plugin System
Nessus-style plugin architecture for deep vulnerability scanning.
Supports dynamic plugin auto-discovery.
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil
from pathlib import Path
from typing import Any, Dict, List

from .base_plugin import BasePlugin

PLUGIN_REGISTRY: Dict[str, Dict[str, Any]] = {}


def discover_plugins() -> None:
    """
    Dynamically discover all plugins in the plugins directory.
    Loads any class inheriting from BasePlugin and registers it.
    """
    global PLUGIN_REGISTRY
    PLUGIN_REGISTRY.clear()

    package_dir = str(Path(__file__).parent)
    for _, module_name, _ in pkgutil.iter_modules([package_dir]):
        if module_name in ("base_plugin", "runner"):
            continue
        try:
            # Import dynamically
            module = importlib.import_module(f"plugins.{module_name}")
            for _, obj in inspect.getmembers(module):
                if (
                    inspect.isclass(obj)
                    and issubclass(obj, BasePlugin)
                    and obj is not BasePlugin
                ):
                    # Use class PLUGIN_SHORT_KEY, fall back to module_name
                    short_key = getattr(obj, "PLUGIN_SHORT_KEY", module_name)
                    
                    PLUGIN_REGISTRY[short_key] = {
                        "class": obj,
                        "name": getattr(obj, "PLUGIN_NAME", obj.__name__),
                        "description": getattr(obj, "DESCRIPTION", obj.__doc__ or "").strip(),
                        "family": getattr(obj, "PLUGIN_FAMILY", "General"),
                    }
        except Exception as e:
            # Suppress import issues during scanning to keep it robust
            from loguru import logger
            logger.warning(f"Failed to dynamically import plugin {module_name}: {e}")


# Automatically discover on package import
discover_plugins()


def get_plugin(name: str, target: str, **kwargs) -> BasePlugin:
    """Instantiates and returns a plugin by registry name."""
    if name not in PLUGIN_REGISTRY:
        raise ValueError(
            f"Unknown plugin: '{name}'. Available: {list(PLUGIN_REGISTRY.keys())}"
        )
    return PLUGIN_REGISTRY[name]["class"](target, **kwargs)


def list_plugins() -> List[Dict[str, str]]:
    """Returns list of all registered plugins with metadata."""
    return [
        {
            "id": k,
            "name": v["name"],
            "description": v["description"],
            "family": v["family"],
        }
        for k, v in PLUGIN_REGISTRY.items()
    ]


__all__ = [
    "BasePlugin",
    "PLUGIN_REGISTRY",
    "get_plugin",
    "list_plugins",
    "discover_plugins",
]
