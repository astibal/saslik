from __future__ import annotations

import gzip
import io
import os
import pwd
import shutil
import subprocess
import sys
import tarfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, TextIO


PROCESS_LOG_LIMIT = 8 * 1024 * 1024
COMPONENT_LOG_LIMIT = 16 * 1024 * 1024
LOG_BACKUPS = 4
MAINTENANCE_INTERVAL = 60.0


def _shift_archives(path: Path, backups: int) -> None:
    Path(f"{path}.{backups}.gz").unlink(missing_ok=True)
    for index in range(backups - 1, 0, -1):
        source = Path(f"{path}.{index}.gz")
        if source.exists():
            source.replace(Path(f"{path}.{index + 1}.gz"))


def rotate_copytruncate(path: Path, *, limit: int = COMPONENT_LOG_LIMIT,
                        backups: int = LOG_BACKUPS) -> bool:
    """Compress an oversized open log and truncate it without replacing its inode."""
    try:
        if path.stat().st_size <= limit:
            return False
    except FileNotFoundError:
        return False
    _shift_archives(path, backups)
    temporary = Path(f"{path}.1.gz.tmp")
    try:
        with path.open("rb") as source, gzip.open(temporary, "wb", compresslevel=6) as target:
            shutil.copyfileobj(source, target, length=1024 * 1024)
        temporary.replace(Path(f"{path}.1.gz"))
        # systemd's append: target remains the same inode, so running services
        # continue logging normally after the truncation.
        with path.open("r+b") as stream:
            stream.truncate(0)
    finally:
        temporary.unlink(missing_ok=True)
    return True


def component_logs(root: Path) -> list[Path]:
    candidates = [root / "lab/state"]
    instances = root / "instances"
    if instances.is_dir():
        candidates.extend(path / "state" for path in instances.iterdir() if path.is_dir())
    return sorted(log for state in candidates if state.is_dir() for log in state.glob("*.log"))


def maintain_component_logs(root: Path) -> list[Path]:
    rotated = []
    for path in component_logs(root):
        try:
            if rotate_copytruncate(path):
                rotated.append(path)
        except PermissionError:
            continue
    return rotated


def repair_log_ownership(root: Path, owner_uid: int) -> list[Path]:
    """Hand root-created service logs back to the unprivileged Saslik owner."""
    if os.geteuid() != 0:
        raise PermissionError("Log ownership repair requires the privileged guardian")
    owner_gid = pwd.getpwuid(owner_uid).pw_gid
    repaired = []
    states = [root / "lab/state"]
    instances = root / "instances"
    if instances.is_dir():
        states.extend(path / "state" for path in instances.iterdir() if path.is_dir())
    for state in states:
        if not state.is_dir():
            continue
        for path in state.glob("*.log*"):
            if not path.is_file() or path.is_symlink():
                continue
            status = path.stat()
            if status.st_uid != owner_uid or status.st_gid != owner_gid:
                os.chown(path, owner_uid, owner_gid)
                repaired.append(path)
    return repaired


def _logpack_files(root: Path, lab: Path) -> list[tuple[Path, Path]]:
    result: list[tuple[Path, Path]] = []
    for path in sorted((*root.glob("saslik.log*"), *root.glob("skewer-api.log*"))):
        if path.is_file() and not path.is_symlink():
            result.append((path, Path("saslik") / path.name))
    state = lab / "state"
    for path in sorted(state.glob("*.log*")) if state.is_dir() else ():
        if path.is_file() and not path.is_symlink():
            result.append((path, Path("workspace") / path.name))
    crashes = state / "crashes"
    for path in sorted(crashes.rglob("*.log*")) if crashes.is_dir() else ():
        if path.is_file() and not path.is_symlink():
            result.append((path, Path("crashes") / path.relative_to(crashes)))
    return result


def _add_bytes(bundle: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mtime = int(time.time())
    info.mode = 0o600
    bundle.addfile(info, io.BytesIO(data))


def _journal(unit: str) -> bytes:
    try:
        result = subprocess.run(
            ["journalctl", "--no-pager", "--output=short-iso", "--lines=20000",
             f"--unit={unit}"],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=15,
        )
        return result.stdout
    except (OSError, subprocess.SubprocessError) as exc:
        return f"journalctl unavailable: {exc}\n".encode()


def save_logpack(root: Path, lab: Path, instance: str, destination: Path) -> int:
    """Bundle bounded diagnostic logs without workspace secrets or core dumps."""
    unit_instance = "".join(character if character.isalnum() else "-"
                            for character in instance)
    files = _logpack_files(root, lab)
    manifest = (
        f"Saslik logpack\nworkspace={instance}\ncreated={int(time.time())}\n"
        f"process_limit={PROCESS_LOG_LIMIT}\ncomponent_limit={COMPONENT_LOG_LIMIT}\n"
        f"backups={LOG_BACKUPS}\nfiles={len(files)}\n"
    ).encode()
    with tarfile.open(destination, "w:gz") as bundle:
        _add_bytes(bundle, "manifest.txt", manifest)
        for source, archive in files:
            bundle.add(source, arcname=str(archive), recursive=False)
        _add_bytes(bundle, "journal/workspace.log",
                   _journal(f"saslik-{unit_instance}-*"))
        _add_bytes(bundle, "journal/guardian.log", _journal("saslik-guardian-*"))
    return len(files) + 3


class LogMaintenance:
    def __init__(self, root: Path, interval: float = MAINTENANCE_INTERVAL) -> None:
        self.root = root
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self, *, run_immediately: bool = True) -> "LogMaintenance":
        if run_immediately:
            self.run_once()
        self._thread = threading.Thread(target=self._run, name="saslik-log-maintenance",
                                        daemon=True)
        self._thread.start()
        return self

    def run_once(self) -> None:
        try:
            maintain_component_logs(self.root)
        except OSError as exc:
            print(f"Saslik log maintenance: {exc}", file=sys.stderr)

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self.run_once()

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)


class RotatingLog:
    def __init__(self, path: Path, limit: int, backups: int) -> None:
        self.path = path
        self.limit = limit
        self.backups = backups
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = path.open("a", encoding="utf-8", buffering=1)

    def write(self, value: str) -> int:
        with self._lock:
            if self._stream.tell() + len(value.encode("utf-8")) > self.limit:
                self._rotate()
            return self._stream.write(value)

    def flush(self) -> None:
        with self._lock:
            self._stream.flush()

    def _rotate(self) -> None:
        self._stream.close()
        Path(f"{self.path}.{self.backups}").unlink(missing_ok=True)
        for index in range(self.backups - 1, 0, -1):
            source = Path(f"{self.path}.{index}")
            if source.exists():
                source.replace(Path(f"{self.path}.{index + 1}"))
        if self.path.exists():
            self.path.replace(Path(f"{self.path}.1"))
        self._stream = self.path.open("a", encoding="utf-8", buffering=1)

    def close(self) -> None:
        with self._lock:
            self._stream.close()


class _Tee:
    def __init__(self, original: TextIO, log: RotatingLog) -> None:
        self.original = original
        self.log = log

    @property
    def encoding(self) -> str:
        return self.original.encoding or "utf-8"

    def isatty(self) -> bool:
        return self.original.isatty()

    def fileno(self) -> int:
        return self.original.fileno()

    def write(self, value: str) -> int:
        written = self.original.write(value)
        self.log.write(value)
        return written

    def flush(self) -> None:
        self.original.flush()
        self.log.flush()


@contextmanager
def process_log(root: Path) -> Iterator[Path]:
    """Tee Saslik stdout/stderr to a bounded persistent process log."""
    path = root / "saslik.log"
    stdout, stderr = sys.stdout, sys.stderr
    log = RotatingLog(path, PROCESS_LOG_LIMIT, LOG_BACKUPS)
    stdout_tee = _Tee(stdout, log)
    stderr_tee = _Tee(stderr, log)
    sys.stdout, sys.stderr = stdout_tee, stderr_tee
    try:
        yield path
    finally:
        sys.stdout, sys.stderr = stdout, stderr
        log.close()
