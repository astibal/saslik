from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path


DEFAULT_TARGET = "example.com"
DEFAULT_INTERVAL = 15
MIN_INTERVAL = 15
MAX_INTERVAL = 3600
HOSTNAME = re.compile(
    r"(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?")


def data_root_for_lab(lab: Path) -> Path:
    if lab.parent.name == "instances":
        return lab.parent.parent
    if lab.name == "lab":
        return lab.parent
    return lab / "state"


def settings_path(root: Path) -> Path:
    return root / "probe-settings.json"


def validate(target: object, enabled: object, interval: object) -> dict[str, object]:
    hostname = str(target).strip().rstrip(".").lower()
    if not HOSTNAME.fullmatch(hostname):
        raise ValueError("Testovací hostname není platné DNS jméno.")
    if not isinstance(enabled, bool):
        raise ValueError("Přepínač pravidelného testování není platný.")
    try:
        seconds = int(interval)
    except (TypeError, ValueError) as exc:
        raise ValueError("Interval testování musí být celé číslo.") from exc
    if not MIN_INTERVAL <= seconds <= MAX_INTERVAL:
        raise ValueError(
            f"Interval testování musí být {MIN_INTERVAL}–{MAX_INTERVAL} sekund.")
    return {"target": hostname, "enabled": enabled, "interval": seconds}


def load(root: Path) -> dict[str, object]:
    try:
        value = json.loads(settings_path(root).read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError
        return validate(value.get("target", DEFAULT_TARGET),
                        value.get("enabled", True),
                        value.get("interval", DEFAULT_INTERVAL))
    except (OSError, json.JSONDecodeError, ValueError):
        return {"target": DEFAULT_TARGET, "enabled": True,
                "interval": DEFAULT_INTERVAL}


def save(root: Path, target: object, enabled: object,
         interval: object) -> dict[str, object]:
    value = validate(target, enabled, interval)
    root.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".probe-settings.", dir=root)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, settings_path(root))
    finally:
        Path(temporary).unlink(missing_ok=True)
    return value
