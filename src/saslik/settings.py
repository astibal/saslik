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
}


def settings_path(lab: Path) -> Path:
    return lab / "state/workspace-settings.json"


def load_settings(lab: Path) -> dict[str, str]:
    path = settings_path(lab)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(value, dict):
        return {}
    return {key: str(value[key]) for key in SETTINGS if value.get(key)}


def public_settings(lab: Path) -> dict[str, dict[str, object]]:
    values = load_settings(lab)
    return {key: {"label": definition["label"],
                  "description": definition["description"],
                  "secret": definition["secret"],
                  "configured": bool(values.get(key))}
            for key, definition in SETTINGS.items()}


def update_settings(lab: Path, changes: dict[str, object]) -> None:
    unknown = set(changes) - set(SETTINGS)
    if unknown:
        raise ValueError(f"Neznámé nastavení: {', '.join(sorted(unknown))}")
    values = load_settings(lab)
    for key, raw_value in changes.items():
        value = str(raw_value).strip() if raw_value is not None else ""
        if "\n" in value or "\r" in value or "\0" in value:
            raise ValueError(f"Neplatná hodnota nastavení: {key}")
        if value:
            values[key] = value
        else:
            values.pop(key, None)
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
