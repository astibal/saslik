from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path, PurePosixPath


LOCKED_PATHS = {
    "state/smithproxy.cfg",
    "state/state.env",
    "state/smithproxy-gui.env",
    "state/identity-name",
    "state/workspace-settings.json",
    "state/binary-bundle.json",
}
LOCKED_TREES = ("state/certs",)
SECRET_PATHS = {"state/state.env", "state/smithproxy-gui.env"}


def relative_path(value: str) -> Path:
    candidate = PurePosixPath(value or ".")
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("Cesta musí zůstat uvnitř workspace.")
    parts = tuple(part for part in candidate.parts if part not in {"", "."})
    return Path(*parts) if parts else Path()


def target_path(lab: Path, value: str, *, allow_missing: bool = False) -> tuple[Path, Path]:
    relative = relative_path(value)
    if lab.is_symlink():
        raise ValueError("Kořen workspace nesmí být symbolický odkaz.")
    target = lab / relative
    current = lab
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Symbolické odkazy nejsou ve Files přístupné.")
        if not current.exists():
            break
    if not allow_missing and not target.exists():
        raise FileNotFoundError(f"Soubor neexistuje: {relative}")
    return target, relative


def is_locked(value: Path) -> bool:
    name = value.as_posix()
    if name in LOCKED_PATHS or any(name == root or name.startswith(root + "/")
                                   for root in LOCKED_TREES):
        return True
    prefix = name + "/" if name else ""
    return any(item.startswith(prefix) for item in LOCKED_PATHS) or any(
        root.startswith(prefix) for root in LOCKED_TREES)


def is_secret(value: Path) -> bool:
    return value.as_posix() in SECRET_PATHS


def list_directory(lab: Path, value: str = "") -> dict[str, object]:
    target, relative = target_path(lab, value)
    if not target.is_dir():
        raise ValueError("Cesta není adresář.")
    entries = []
    for path in sorted(target.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower())):
        child = relative / path.name
        symlink = path.is_symlink()
        entries.append({
            "name": path.name,
            "path": child.as_posix(),
            "directory": path.is_dir() and not symlink,
            "symlink": symlink,
            "locked": is_locked(child),
            "size": path.stat(follow_symlinks=False).st_size if not path.is_dir() else None,
        })
    stat = target.stat()
    return {"path": relative.as_posix(), "entries": entries,
            "revision": f"{stat.st_mtime_ns}:{len(entries)}"}


def file_revision(lab: Path, value: str) -> str:
    target, _ = target_path(lab, value)
    if not target.is_file():
        raise ValueError("Cesta není běžný soubor.")
    stat = target.stat()
    return f"{stat.st_mtime_ns}:{stat.st_size}"


def read_file(lab: Path, value: str, limit: int = 2 * 1024 * 1024) -> bytes:
    target, relative = target_path(lab, value)
    if is_secret(relative):
        raise PermissionError("Secret soubor nelze číst přes Files API.")
    if not target.is_file():
        raise ValueError("Cesta není běžný soubor.")
    if target.stat().st_size > limit:
        raise ValueError("Soubor je pro editor příliš velký; použij Stažení.")
    return target.read_bytes()


def write_file(lab: Path, value: str, content: bytes) -> None:
    target, _ = target_path(lab, value, allow_missing=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)


def make_directory(lab: Path, value: str) -> None:
    target, _ = target_path(lab, value, allow_missing=True)
    target.mkdir(parents=False, exist_ok=False)


def delete_path(lab: Path, value: str, *, override_locked: bool = False) -> None:
    target, relative = target_path(lab, value)
    if not relative.parts:
        raise ValueError("Kořen workspace nelze smazat.")
    if is_locked(relative) and not override_locked:
        raise PermissionError("Soubor je chráněný; zapni override zámku.")
    if target.is_dir():
        shutil.rmtree(target)
    else:
        target.unlink()
