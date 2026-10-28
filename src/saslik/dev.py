from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path


PROJECTS = {
    "smithproxy": "src/smithproxy",
    "socle": "src/smithproxy/socle",
    "spider": "src/smithproxy-spider",
    "sift": "src/sift",
    "lored": "src/lored",
    "pcap-viewer": "src/capture-zone-viewer",
    "smithproxy-gui": "src/smithproxy-gui",
}
MAX_PATCH_BYTES = 1024 * 1024
_PATCH_LOCK = threading.Lock()
_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def normalize_text_patch(patch: str) -> str:
    """Restore blank context markers commonly lost by clipboard transport."""
    patch = patch.replace("\r\n", "\n").replace("\r", "\n")
    trailing_newline = patch.endswith("\n")
    lines = patch.splitlines()
    in_hunk = False
    normalized = []
    for line in lines:
        if line.startswith("@@ "):
            in_hunk = True
        elif line.startswith("diff --git ") or line.startswith("--- "):
            in_hunk = False
        if in_hunk and line == "":
            normalized.append(" ")
        else:
            normalized.append(line)
    return "\n".join(normalized) + ("\n" if trailing_newline else "")


def project_root(lab: Path, project: str) -> Path:
    if project not in PROJECTS:
        raise ValueError(f"Neznámý projekt: {project}")
    lab_root = lab.resolve()
    root = (lab_root / PROJECTS[project]).resolve()
    try:
        root.relative_to(lab_root)
    except ValueError as exc:
        raise RuntimeError("Zdrojový checkout vede mimo workspace.") from exc
    if not (root / ".git").exists():
        raise RuntimeError(f"Zdrojový checkout projektu {project} neexistuje.")
    return root


def _validated_patch(patch: str) -> str:
    patch = normalize_text_patch(patch)
    payload = patch.encode("utf-8")
    if not payload.strip():
        raise ValueError("Patch je prázdný.")
    if len(payload) > MAX_PATCH_BYTES:
        raise ValueError("Patch je větší než 1 MiB.")
    if b"\0" in payload:
        raise ValueError("Patch obsahuje neplatná binární data.")
    _validate_hunks(patch)
    return patch


def _validate_hunks(patch: str) -> None:
    """Report truncated textual hunks before git emits a vague error."""
    lines = patch.splitlines()
    index = 0
    while index < len(lines):
        match = _HUNK_HEADER.match(lines[index])
        if not match:
            index += 1
            continue
        header_line = index + 1
        expected_old = int(match.group(2) or 1)
        expected_new = int(match.group(4) or 1)
        old_count = new_count = 0
        index += 1
        while index < len(lines) and not lines[index].startswith(("@@ ", "diff --git ")):
            line = lines[index]
            if line.startswith("\\ No newline at end of file"):
                index += 1
                continue
            if not line or line[0] not in " +-":
                raise ValueError(
                    f"Neplatný diff řádek {index + 1}: chybí prefix mezera, + nebo -.")
            if line[0] != "+":
                old_count += 1
            if line[0] != "-":
                new_count += 1
            index += 1
        if old_count != expected_old or new_count != expected_new:
            raise ValueError(
                f"Neúplný hunk na řádku {header_line}: hlavička očekává "
                f"{expected_old}/{expected_new} řádků, patch obsahuje "
                f"{old_count}/{new_count}.")


def _git_apply(root: Path, patch: str, *, reverse: bool = False,
               check_only: bool = False) -> None:
    environment = os.environ.copy()
    environment.setdefault("GIT_TERMINAL_PROMPT", "0")
    command = ["git", "-C", str(root), "apply", "--recount", "--whitespace=nowarn"]
    if reverse:
        command.append("--reverse")
    try:
        checked = subprocess.run(
            [*command, "--check", "-"], input=patch, text=True, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Kontrola patche překročila časový limit.") from exc
    if checked.returncode:
        raise RuntimeError(checked.stderr.strip() or "Patch neprošel bezpečnostní kontrolou.")
    if check_only:
        return
    try:
        applied = subprocess.run(
            [*command, "-"], input=patch, text=True, env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Aplikace patche překročila časový limit.") from exc
    if applied.returncode:
        raise RuntimeError(applied.stderr.strip() or "Patch se nepodařilo aplikovat.")


def apply_text_patch(lab: Path, project: str, patch: str) -> None:
    patch = _validated_patch(patch)
    _git_apply(project_root(lab, project), patch)


def _store_root(lab: Path) -> Path:
    return lab.resolve() / "state/dev-patches"


def _load_records(lab: Path) -> list[dict[str, str]]:
    try:
        value = json.loads((_store_root(lab) / "index.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _save_records(lab: Path, records: list[dict[str, str]]) -> None:
    root = _store_root(lab)
    root.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".index-", dir=root)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(records, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, root / "index.json")
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def list_patches(lab: Path) -> list[dict[str, str]]:
    return list(reversed(_load_records(lab)))


def apply_named_patch(lab: Path, project: str, patch: str, name: str = "") -> dict[str, str]:
    patch = _validated_patch(patch)
    name = name.strip()
    if len(name) > 120 or any(ord(character) < 32 for character in name):
        raise ValueError("Název patche není platný.")
    with _PATCH_LOCK:
        _git_apply(project_root(lab, project), patch)
        created = datetime.now(timezone.utc).isoformat(timespec="seconds")
        record = {"id": secrets.token_hex(8), "name": name or f"{project} patch",
                  "project": project, "state": "applied", "created_at": created}
        root = _store_root(lab)
        root.mkdir(parents=True, exist_ok=True)
        path = root / f"{record['id']}.patch"
        path.write_text(patch, encoding="utf-8")
        path.chmod(0o600)
        records = _load_records(lab)
        records.append(record)
        _save_records(lab, records)
        return record


def remember_applied_patch(lab: Path, project: str, patch: str,
                           name: str = "") -> dict[str, str]:
    """Record a patch already present in the tree after verifying its reverse."""
    patch = _validated_patch(patch)
    name = name.strip()
    if len(name) > 120 or any(ord(character) < 32 for character in name):
        raise ValueError("Název patche není platný.")
    with _PATCH_LOCK:
        _git_apply(project_root(lab, project), patch, reverse=True, check_only=True)
        created = datetime.now(timezone.utc).isoformat(timespec="seconds")
        record = {"id": secrets.token_hex(8), "name": name or f"{project} patch",
                  "project": project, "state": "applied", "created_at": created,
                  "imported": "true"}
        root = _store_root(lab)
        root.mkdir(parents=True, exist_ok=True)
        path = root / f"{record['id']}.patch"
        path.write_text(patch, encoding="utf-8")
        path.chmod(0o600)
        records = _load_records(lab)
        records.append(record)
        _save_records(lab, records)
        return record


def revert_patch(lab: Path, patch_id: str) -> dict[str, str]:
    with _PATCH_LOCK:
        records = _load_records(lab)
        record = next((item for item in records if item.get("id") == patch_id), None)
        if not record or not patch_id.isalnum():
            raise ValueError("Patch v historii neexistuje.")
        if record.get("state") != "applied":
            raise ValueError("Patch už byl vrácený.")
        patch = (_store_root(lab) / f"{patch_id}.patch").read_text(encoding="utf-8")
        _git_apply(project_root(lab, record["project"]), patch, reverse=True)
        record["state"] = "reverted"
        record["reverted_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        _save_records(lab, records)
        return record


def reapply_patch(lab: Path, patch_id: str) -> dict[str, str]:
    with _PATCH_LOCK:
        records = _load_records(lab)
        record = next((item for item in records if item.get("id") == patch_id), None)
        if not record or not patch_id.isalnum():
            raise ValueError("Patch v historii neexistuje.")
        if record.get("state") != "reverted":
            raise ValueError("Patch už je aplikovaný.")
        patch = (_store_root(lab) / f"{patch_id}.patch").read_text(encoding="utf-8")
        _git_apply(project_root(lab, record["project"]), patch)
        record["state"] = "applied"
        record["reapplied_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        record.pop("reverted_at", None)
        _save_records(lab, records)
        return record


def revert_all_patches(lab: Path) -> int:
    # Each item acquires the journal lock itself. Revert newest first so
    # stacked patches are unwound in the opposite order they were applied.
    applied = [record["id"] for record in list_patches(lab)
               if record.get("state") == "applied"]
    for patch_id in applied:
        revert_patch(lab, patch_id)
    return len(applied)


def clear_patch_history(lab: Path) -> int:
    with _PATCH_LOCK:
        records = _load_records(lab)
        shutil.rmtree(_store_root(lab), ignore_errors=True)
        return len(records)
