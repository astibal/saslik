from __future__ import annotations

import os
import secrets
from pathlib import Path


SECRET_NAME = "smithproxy-gui.gateway-secret"


def ensure_gateway_secret(runtime_dir: Path) -> str:
    """Return the stable secret shared only by nginx and smithproxy-gui."""
    runtime_dir.mkdir(parents=True, exist_ok=True)
    path = runtime_dir / SECRET_NAME
    try:
        value = path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        candidate = secrets.token_urlsafe(32)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            value = path.read_text(encoding="ascii").strip()
        else:
            with os.fdopen(descriptor, "w", encoding="ascii") as stream:
                stream.write(candidate + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            value = candidate
    if not 32 <= len(value) <= 256 or any(
            character.isspace() or ord(character) < 0x21 or ord(character) > 0x7e
            for character in value):
        raise RuntimeError(f"Neplatny Smithproxy GUI gateway secret: {path}")
    os.chmod(path, 0o600)
    return value
