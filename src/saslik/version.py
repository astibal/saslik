from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.request
from importlib import metadata
from pathlib import Path
from urllib.parse import unquote, urlparse


def _run_git(root: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.setdefault("GIT_TERMINAL_PROMPT", "0")
    environment.setdefault("GIT_SSH_COMMAND", "ssh -oBatchMode=yes")
    return subprocess.run(
        ["git", "-C", str(root), *arguments], check=check, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, timeout=20,
    )


def _source_root(distribution: metadata.Distribution | None) -> Path | None:
    if distribution:
        try:
            direct = json.loads(distribution.read_text("direct_url.json") or "{}")
        except (json.JSONDecodeError, OSError):
            direct = {}
        if direct.get("dir_info", {}).get("editable") and str(direct.get("url", "")).startswith("file:"):
            path = Path(unquote(urlparse(direct["url"]).path)).resolve()
            if (path / ".git").exists():
                return path
    for parent in Path(__file__).resolve().parents:
        if (parent / ".git").exists():
            return parent
    return None


def _git_status(root: Path, version: str) -> dict[str, str]:
    branch = _run_git(root, "branch", "--show-current").stdout.strip()
    if not branch:
        return {"state": "detached", "detail": f"source · {version} · detached HEAD",
                "mode": "source", "version": version}
    if _run_git(root, "status", "--porcelain").stdout.strip():
        return {"state": "dirty", "detail": f"source · {branch} · lokální změny",
                "mode": "source", "version": version}
    tracking = "refs/saslik/self-status"
    _run_git(root, "fetch", "--quiet", "--no-write-fetch-head", "origin",
             f"+refs/heads/{branch}:{tracking}")
    head = _run_git(root, "rev-parse", "HEAD").stdout.strip()
    remote = _run_git(root, "rev-parse", tracking).stdout.strip()
    if head == remote:
        state, label = "current", "aktuální"
    elif _run_git(root, "merge-base", "--is-ancestor", "HEAD", tracking,
                  check=False).returncode == 0:
        state, label = "behind", "je dostupná novější verze"
    elif _run_git(root, "merge-base", "--is-ancestor", tracking, "HEAD",
                  check=False).returncode == 0:
        state, label = "ahead", "lokálně napřed"
    else:
        state, label = "diverged", "větev se rozešla"
    return {"state": state, "detail": f"source · {branch} · {label}",
            "mode": "source", "version": version}


def _version_key(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", value)[:4])


def _package_status(version: str) -> dict[str, str]:
    request = urllib.request.Request(
        "https://pypi.org/pypi/saslik/json", headers={"User-Agent": f"saslik/{version}"})
    with urllib.request.urlopen(request, timeout=15) as response:
        latest = str(json.load(response)["info"]["version"])
    behind = _version_key(version) < _version_key(latest)
    return {
        "state": "behind" if behind else "current",
        "detail": f"pip · {version}" + (f" → {latest}" if behind else " · aktuální"),
        "mode": "pip", "version": version, "latest": latest,
    }


def saslik_version_status() -> dict[str, str]:
    try:
        distribution = metadata.distribution("saslik")
        version = distribution.version
    except metadata.PackageNotFoundError:
        distribution = None
        version = "development"
    root = _source_root(distribution)
    return _git_status(root, version) if root else _package_status(version)
