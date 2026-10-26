from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path


SETTINGS = {
    "source_tuntom": {"label": "Tuntom source", "secret": False, "default": "src", "choices": ("src",)},
    "ref_tuntom": {"label": "Tuntom branch / ref", "secret": False, "default": "main"},
    "ipinfo_token": {
        "label": "ipinfo.io API token",
        "description": "Geolokační enrichment v CZ PCAP Vieweru.",
        "secret": True,
    },
    "license_issuer_key": {
        "label": "Licenční veřejný klíč",
        "description": "Ed25519 public key vydavatele licencí.",
        "secret": True,
        "multiline": True,
    },
    "restart_smithproxy": {"label": "Smithproxy", "secret": False, "default": True},
    "restart_spider": {"label": "Spider", "secret": False, "default": True},
    "restart_sift": {"label": "Sift", "secret": False, "default": True},
    "restart_pcap_viewer": {"label": "PCAP Viewer", "secret": False, "default": True},
    "restart_pcap_storage": {"label": "Capture storage", "secret": False, "default": True},
    "restart_lored": {"label": "Lored", "secret": False, "default": True},
    "debug_build": {"label": "Debug build", "secret": False, "default": False},
    "collect_coredumps": {"label": "Uložit core dump", "secret": False, "default": True},
    "collect_backtraces": {"label": "Vygenerovat backtrace", "secret": False, "default": True},
    "source_smithproxy": {"label": "Smithproxy source", "secret": False, "default": "src", "choices": ("src", "bin")},
    "ref_smithproxy": {"label": "Smithproxy branch / ref", "secret": False, "default": "master"},
    "source_spider": {"label": "Spider source", "secret": False, "default": "src", "choices": ("src", "bin")},
    "ref_spider": {"label": "Spider branch / ref", "secret": False, "default": "prefixed-run"},
    "source_sift": {"label": "Sift source", "secret": False, "default": "src", "choices": ("src", "bin")},
    "ref_sift": {"label": "Sift branch / ref", "secret": False, "default": "main"},
    "source_pcap_viewer": {"label": "PCAP Viewer source", "secret": False, "default": "src", "choices": ("src", "bin")},
    "ref_pcap_viewer": {"label": "PCAP Viewer branch / ref", "secret": False, "default": "prefixed-run"},
    "source_lored": {"label": "Lored source", "secret": False, "default": "src", "choices": ("src", "bin")},
    "ref_lored": {"label": "Lored branch / ref", "secret": False, "default": "main"},
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
            item["value"] = values.get(key, definition.get("default", False))
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
            if "\0" in value or (not SETTINGS[key].get("multiline") and
                                   ("\n" in value or "\r" in value)):
                raise ValueError(f"Neplatná hodnota nastavení: {key}")
            if len(value) > 64 * 1024:
                raise ValueError(f"Nastavení je příliš dlouhé: {key}")
            if value:
                values[key] = value
            else:
                values.pop(key, None)
        elif "choices" in SETTINGS[key]:
            value = str(raw_value).strip()
            if value not in SETTINGS[key]["choices"]:
                raise ValueError(f"Neplatná hodnota nastavení: {key}")
            values[key] = value
        elif isinstance(SETTINGS[key].get("default"), str):
            value = str(raw_value).strip()
            if not value or len(value) > 200 or any(character in value for character in "\r\n\0"):
                raise ValueError(f"Neplatná hodnota nastavení: {key}")
            if key.startswith("ref_") and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", value):
                raise ValueError(f"Neplatný Git ref: {value}")
            values[key] = value
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
