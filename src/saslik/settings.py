from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path


SETTINGS = {
    "ipinfo_token": {
        "label": "ipinfo.io API token",
        "description": "Geolokační enrichment v CZ PCAP Vieweru.",
        "secret": True,
    },
    "restart_smithproxy": {"label": "Smithproxy", "secret": False, "default": True},
    "restart_spider": {"label": "Spider", "secret": False, "default": True},
    "restart_sift": {"label": "Sift", "secret": False, "default": True},
    "restart_pcap_viewer": {"label": "PCAP Viewer", "secret": False, "default": True},
    "restart_pcap_storage": {"label": "Capture storage", "secret": False, "default": True},
    "debug_build": {"label": "Debug build", "secret": False, "default": False},
    "collect_coredumps": {"label": "Uložit core dump", "secret": False, "default": True},
    "collect_backtraces": {"label": "Vygenerovat backtrace", "secret": False, "default": True},
}


def settings_path(lab: Path) -> Path:
    return lab / "state/workspace-settings.json"


def load_settings(lab: Path) -> dict[str, object]:
    path = settings_path(lab)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(value, dict):
        return {}
    return {key: value[key] for key in SETTINGS if key in value}


def public_settings(lab: Path) -> dict[str, dict[str, object]]:
    values = load_settings(lab)
    result = {}
    for key, definition in SETTINGS.items():
        item = {"label": definition["label"], "secret": definition["secret"]}
        if definition["secret"]:
            item.update(description=definition.get("description", ""),
                        configured=bool(values.get(key)))
        else:
            item["value"] = values.get(key, definition.get("default", False)) is True
        result[key] = item
    return result


def update_settings(lab: Path, changes: dict[str, object]) -> None:
    unknown = set(changes) - set(SETTINGS)
    if unknown:
        raise ValueError(f"Neznámé nastavení: {', '.join(sorted(unknown))}")
    values = load_settings(lab)
    for key, raw_value in changes.items():
        if SETTINGS[key]["secret"]:
            value = str(raw_value).strip() if raw_value is not None else ""
            if "\n" in value or "\r" in value or "\0" in value:
                raise ValueError(f"Neplatná hodnota nastavení: {key}")
            if value:
                values[key] = value
            else:
                values.pop(key, None)
        else:
            if type(raw_value) is not bool:
                raise ValueError(f"Nastavení {SETTINGS[key]['label']} musí být ano/ne.")
            values[key] = raw_value
    path = settings_path(lab)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".workspace-settings-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(values, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def provision_settings(lab: Path, changes: dict[str, object]) -> None:
    """Set previously missing secrets without exposing an update primitive."""
    current = load_settings(lab)
    unknown = set(changes) - set(SETTINGS)
    if unknown:
        raise ValueError(f"Neznámé nastavení: {', '.join(sorted(unknown))}")
    for key, raw_value in changes.items():
        if SETTINGS[key]["secret"]:
            if current.get(key):
                raise ValueError(f"Nastavení {SETTINGS[key]['label']} už je uložené.")
            value = str(raw_value).strip() if raw_value is not None else ""
            if not value:
                raise ValueError(f"Hodnota {SETTINGS[key]['label']} nesmí být prázdná.")
    update_settings(lab, changes)


def component_environment(lab: Path, component: str) -> tuple[str, ...]:
    values = load_settings(lab)
    if component != "pcap-viewer" or not values.get("ipinfo_token"):
        return ()
    return (f"IPINFO_TOKEN={values['ipinfo_token']}",)


def component_restart_on_failure(lab: Path, component: str) -> bool:
    key = f"restart_{component.replace('-', '_')}"
    definition = SETTINGS.get(key)
    if not definition:
        return False
    value = load_settings(lab).get(key, definition.get("default", False))
    return value is True


def setting_value(lab: Path, key: str) -> object:
    definition = SETTINGS[key]
    return load_settings(lab).get(key, definition.get("default"))
