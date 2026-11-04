from __future__ import annotations

import argparse
import fcntl
import json
import os
import shutil
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


DAY = 24 * 60 * 60
DEFAULT_CACHE_LIMIT = 10 * 1024**3


@dataclass(frozen=True)
class CachePolicy:
    staging_ttl: int = 2 * DAY
    reusable_ttl: int = 7 * DAY
    size_limit: int = DEFAULT_CACHE_LIMIT


@dataclass
class CacheReport:
    removed_entries: int = 0
    reclaimed_bytes: int = 0
    busy: bool = False


def _tree_size(path: Path) -> int:
    if path.is_file() and not path.is_symlink():
        return path.stat().st_size
    return sum(item.stat().st_size for item in path.rglob("*")
               if item.is_file() and not item.is_symlink())


def _last_used(path: Path) -> float:
    marker = path / ".cache-entry.json" if path.is_dir() else path
    try:
        if marker.name == ".cache-entry.json":
            value = json.loads(marker.read_text(encoding="utf-8"))
            return float(value.get("last_used", marker.stat().st_mtime))
        status = marker.stat()
        return max(status.st_atime, status.st_mtime)
    except (FileNotFoundError, OSError, ValueError, TypeError, json.JSONDecodeError):
        return 0.0


def mark_entry(path: Path, kind: str, *, now: float | None = None) -> None:
    """Mark a manifest-backed cache directory as successfully used."""
    path.mkdir(parents=True, exist_ok=True)
    marker = path / ".cache-entry.json"
    temporary = marker.with_suffix(".tmp")
    temporary.write_text(json.dumps({"format": 1, "kind": kind,
                                     "last_used": time.time() if now is None else now},
                                    sort_keys=True) + "\n",
                         encoding="utf-8")
    temporary.replace(marker)


@contextmanager
def cache_lock(root: Path, *, blocking: bool = False) -> Iterator[bool]:
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink():
        raise ValueError("Build cache root must not be a symlink")
    stream = (root / ".lock").open("a+")
    flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
    try:
        try:
            fcntl.flock(stream, flags)
        except BlockingIOError:
            yield False
            return
        yield True
    finally:
        stream.close()


def _entries(root: Path) -> list[tuple[Path, float]]:
    result: list[tuple[Path, float]] = []
    for group in ("staging", "bootstrap"):
        directory = root / group
        if directory.is_dir() and not directory.is_symlink():
            result.extend((item, _last_used(item)) for item in directory.iterdir()
                          if not item.is_symlink())
    archives = root / "apt/archives"
    if archives.is_dir() and not archives.is_symlink():
        result.extend((item, _last_used(item)) for item in archives.glob("*.deb")
                      if item.is_file() and not item.is_symlink())
    return result


def _remove(path: Path, report: CacheReport, dry_run: bool) -> None:
    size = _tree_size(path)
    report.removed_entries += 1
    report.reclaimed_bytes += size
    if dry_run:
        return
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


def prune_build_cache(root: Path, *, policy: CachePolicy = CachePolicy(),
                      dry_run: bool = False, now: float | None = None,
                      blocking: bool = False) -> CacheReport:
    root = Path(root)
    report = CacheReport()
    if not root.exists():
        return report
    timestamp = time.time() if now is None else now
    with cache_lock(root, blocking=blocking) as acquired:
        if not acquired:
            report.busy = True
            return report
        entries = _entries(root)
        expired: set[Path] = set()
        for path, used in entries:
            ttl = policy.staging_ttl if path.parent.name == "staging" else policy.reusable_ttl
            if timestamp - used > ttl:
                expired.add(path)
        for path in sorted(expired, key=str):
            _remove(path, report, dry_run)
        remaining = [(path, used) for path, used in entries if path not in expired]
        total = sum(_tree_size(path) for path, _ in remaining)
        for path, _used in sorted(remaining, key=lambda item: item[1]):
            if total <= policy.size_limit:
                break
            size = _tree_size(path)
            _remove(path, report, dry_run)
            total -= size
    return report


def clean_build_cache(root: Path, *, dry_run: bool = False) -> CacheReport:
    root = Path(root)
    report = CacheReport()
    if not root.exists():
        return report
    with cache_lock(root, blocking=False) as acquired:
        if not acquired:
            report.busy = True
            return report
        for group in ("staging", "bootstrap", "apt"):
            path = root / group
            if path.exists() and not path.is_symlink():
                _remove(path, report, dry_run)
    return report


def _human_size(value: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.1f} {unit}"
        value /= 1024
    raise AssertionError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Saslik build cache maintenance")
    parser.add_argument("action", choices=("prune", "clean", "touch"))
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--max-gib", type=float, default=10.0)
    parser.add_argument("--kind", choices=("bootstrap", "staging"), default="bootstrap")
    arguments = parser.parse_args(argv)
    if arguments.action == "touch":
        mark_entry(arguments.cache, arguments.kind)
        return 0
    policy = CachePolicy(size_limit=max(0, int(arguments.max_gib * 1024**3)))
    report = (prune_build_cache(arguments.cache, policy=policy, dry_run=arguments.dry_run)
              if arguments.action == "prune" else
              clean_build_cache(arguments.cache, dry_run=arguments.dry_run))
    if report.busy:
        print("Saslik build cache: build právě cache používá; úklid přeskočen.")
        return 0
    mode = " (dry-run)" if arguments.dry_run else ""
    print(f"Saslik build cache{mode}: {report.removed_entries} položek, "
          f"{_human_size(report.reclaimed_bytes)}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
