"""Resolve the active Smithproxy configuration without guessing its format."""
from __future__ import annotations

from pathlib import Path


CONFIG_NAMES = ("smithproxy.cftar", "smithproxy.cfg")


def active_config(state: Path, *, required: bool = False) -> Path | None:
    found = [state / name for name in CONFIG_NAMES if (state / name).is_file()]
    if len(found) > 1:
        raise RuntimeError(
            "Workspace obsahuje současně smithproxy.cftar i smithproxy.cfg; "
            "aktivní konfigurace není jednoznačná."
        )
    if found:
        return found[0]
    if required:
        raise RuntimeError("Workspace neobsahuje smithproxy.cftar ani smithproxy.cfg.")
    return None


def is_initialized(state: Path) -> bool:
    return active_config(state) is not None
