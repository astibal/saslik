"""Persistent, low-priority Takeaway export jobs."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from .instance import validate_instance_name


JOB_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
STEPS = (
    "preflight", "snapshot", "runtime-data", "seal", "runtime",
    "squashfs", "package", "manifest", "publish", "done",
)
RETENTION_SECONDS = 7 * 24 * 60 * 60


def source_checkout() -> Path:
    configured = os.environ.get("SASLIK_SOURCE_DIR", "")
    candidates = [Path(configured)] if configured else []
    candidates.extend((Path(__file__).resolve().parents[2], Path("/opt/saslik/source")))
    for candidate in candidates:
        if (candidate / "scripts/build-takeaway-linux.sh").is_file():
            return candidate.resolve()
    raise RuntimeError("Zdrojový strom Saslíku pro Takeaway není dostupný.")


def jobs_root(data_root: Path) -> Path:
    return data_root / "exports/takeaways"


def work_root(data_root: Path) -> Path:
    return data_root / "tmp/takeaway-builds"


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        ownership = path.stat()
    except FileNotFoundError:
        ownership = None
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        if ownership is not None and os.geteuid() == 0:
            os.chown(temporary, ownership.st_uid, ownership.st_gid)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _read(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def create_job(data_root: Path, workspaces: list[str]) -> dict:
    names = list(dict.fromkeys(str(item) for item in workspaces))
    try:
        names = [validate_instance_name(name) for name in names]
    except ValueError as exc:
        raise ValueError("Vyber alespoň jeden platný workspace.") from exc
    if not names:
        raise ValueError("Vyber alespoň jeden platný workspace.")
    job_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8]
    directory = jobs_root(data_root) / job_id
    state = {
        "id": job_id, "state": "queued", "step": 1, "step_name": STEPS[0],
        "step_count": len(STEPS), "workspaces": names,
        "created_at": time.time(), "updated_at": time.time(),
        "acknowledged": False, "artifact": "", "error": "",
    }
    _atomic_json(directory / "state.json", state)
    return state


def update_job(data_root: Path, job_id: str, **changes: object) -> dict:
    if not JOB_NAME.fullmatch(job_id):
        raise ValueError("Neplatné Takeaway job ID.")
    path = jobs_root(data_root) / job_id / "state.json"
    state = _read(path)
    if not state:
        raise FileNotFoundError(job_id)
    state.update(changes)
    state["updated_at"] = time.time()
    _atomic_json(path, state)
    return state


def list_jobs(data_root: Path) -> list[dict]:
    root = jobs_root(data_root)
    if not root.is_dir():
        return []
    result = [_read(path) for path in root.glob("*/state.json")]
    return sorted((item for item in result if item.get("id")),
                  key=lambda item: float(item.get("created_at", 0)), reverse=True)


def delete_job(data_root: Path, job_id: str) -> None:
    state = next((item for item in list_jobs(data_root) if item["id"] == job_id), None)
    if state is None:
        raise FileNotFoundError(job_id)
    if state.get("state") in {"queued", "running"}:
        raise RuntimeError("Probíhající Takeaway nelze smazat.")
    shutil.rmtree(jobs_root(data_root) / job_id)


def prune_jobs(data_root: Path, *, now: float | None = None,
               max_age: float = RETENTION_SECONDS) -> list[str]:
    cutoff = (time.time() if now is None else now) - max_age
    removed = []
    for state in list_jobs(data_root):
        if state.get("state") in {"queued", "running"}:
            continue
        if float(state.get("updated_at", state.get("created_at", 0))) >= cutoff:
            continue
        shutil.rmtree(jobs_root(data_root) / state["id"], ignore_errors=True)
        removed.append(state["id"])
    return removed


def prune_workdirs(data_root: Path, *, now: float | None = None,
                   max_age: float = RETENTION_SECONDS) -> list[str]:
    """Remove abandoned builder staging trees; active builds are far younger."""
    root = work_root(data_root)
    if not root.is_dir():
        return []
    cutoff = (time.time() if now is None else now) - max_age
    removed = []
    for path in root.glob("saslik-takeaway.*"):
        try:
            if not path.is_dir() or path.is_symlink() or path.stat().st_mtime >= cutoff:
                continue
            shutil.rmtree(path)
            removed.append(path.name)
        except FileNotFoundError:
            continue
    return removed


def job_path(data_root: Path, job_id: str, name: str) -> Path:
    if not JOB_NAME.fullmatch(job_id) or name not in {"build.log", "state.json"}:
        raise ValueError("Neplatná Takeaway cesta.")
    return jobs_root(data_root) / job_id / name


def disk_preflight(data_root: Path, source: Path | None = None) -> dict:
    source = source or source_checkout()
    rootfs = source / "build/appliance/rootfs"
    data_root.mkdir(parents=True, exist_ok=True)
    usage = shutil.disk_usage(data_root)
    if not rootfs.is_dir():
        return {"ok": False, "errors": ["Nejdřív sestav appliance rootfs."],
                "warnings": [], "required_bytes": 0, "free_bytes": usage.free}
    # A conservative estimate: immutable rootfs plus selected state staging and
    # package overhead. Captures are excluded by the builder.
    rootfs_bytes = sum(path.stat().st_size for path in rootfs.rglob("*")
                       if path.is_file() and not path.is_symlink())
    required = rootfs_bytes * 2 + 5 * 1024**3
    warnings = []
    errors = []
    if usage.free < required:
        errors.append("Na cílovém filesystemu není dost volného místa.")
    elif usage.free < required + 2 * 1024**3:
        warnings.append("Rezerva místa je menší než doporučené 2 GiB.")
    dirty = subprocess.run(["git", "-C", str(source), "status", "--porcelain"],
                           check=False, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL).stdout.strip()
    if dirty:
        warnings.append("Zdrojový strom Saslíku obsahuje lokální změny.")
    upstream = subprocess.run(["git", "-C", str(source), "rev-parse", "--abbrev-ref",
                               "--symbolic-full-name", "@{upstream}"], check=False,
                              text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL).stdout.strip()
    if upstream:
        ahead = subprocess.run(["git", "-C", str(source), "rev-list", "--count",
                                f"{upstream}..HEAD"], check=False, text=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL).stdout.strip()
        if ahead.isdigit() and int(ahead):
            warnings.append(f"Zdroj Saslíku obsahuje {ahead} nepushnutých commitů.")
    else:
        warnings.append("Zdroj Saslíku nemá dohledatelný upstream branch.")
    return {"ok": not errors, "errors": errors, "warnings": warnings,
            "required_bytes": required, "free_bytes": usage.free,
            "source": str(source), "rootfs": str(rootfs)}


def unit_name(job_id: str) -> str:
    if not JOB_NAME.fullmatch(job_id):
        raise ValueError("Neplatné Takeaway job ID.")
    return f"saslik-takeaway-{job_id}.service"


def start_unit(data_root: Path, job_id: str, owner_uid: int) -> None:
    state = next((item for item in list_jobs(data_root) if item["id"] == job_id), None)
    if not state:
        raise RuntimeError("Takeaway job neexistuje.")
    command = [
        "systemd-run", "--quiet", "--collect", "--service-type=exec",
        f"--unit={unit_name(job_id)}", "--slice=saslik-takeaway.slice",
        "--property=Restart=no", "--property=KillMode=control-group",
        "--property=Nice=15", "--property=CPUWeight=10", "--property=IOWeight=10",
        "--property=IOSchedulingClass=idle", "--property=IOSchedulingPriority=7",
        "--property=OOMScoreAdjust=500",
        os.sys.executable, "-m", "saslik.takeaway_jobs", "run",
        "--data-root", str(data_root), "--job", job_id, "--owner-uid", str(owner_uid),
    ]
    subprocess.run(command, check=True)


def cancel_unit(data_root: Path, job_id: str) -> None:
    subprocess.run(["systemctl", "stop", unit_name(job_id)], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    state = next((item for item in list_jobs(data_root) if item["id"] == job_id), {})
    if state.get("state") in {"queued", "running"}:
        update_job(data_root, job_id, state="cancelled", acknowledged=True,
                   error="Zrušeno uživatelem.")


def run_job(data_root: Path, job_id: str, owner_uid: int) -> None:
    source = source_checkout()
    state = update_job(data_root, job_id, state="running", step=2, step_name=STEPS[1])
    directory = jobs_root(data_root) / job_id
    artifact = directory / "saslik-takeaway-linux-amd64.tar.zst"
    command = [
        str(source / "scripts/build-takeaway-linux.sh"),
        "--rootfs", str(source / "build/appliance/rootfs"),
        "--source-data", str(data_root), "--source", str(source),
        "--output", str(artifact), "--work-root", str(work_root(data_root)),
    ]
    for workspace in state["workspaces"]:
        command.extend(("--workspace", workspace))
    log_path = directory / "build.log"
    try:
        with log_path.open("w", encoding="utf-8") as log:
            completed = subprocess.run(command, check=False, text=True,
                                       stdout=log, stderr=subprocess.STDOUT)
        if completed.returncode:
            raise RuntimeError(f"Builder skončil s kódem {completed.returncode}.")
        os.chown(artifact, owner_uid, -1)
        os.chown(log_path, owner_uid, -1)
        digest = subprocess.run(["sha256sum", str(artifact)], check=True, text=True,
                                stdout=subprocess.PIPE).stdout.split()[0]
        update_job(data_root, job_id, state="done", step=len(STEPS),
                   step_name=STEPS[-1], artifact=artifact.name,
                   artifact_sha256=digest, artifact_bytes=artifact.stat().st_size)
    except Exception as exc:
        update_job(data_root, job_id, state="failed", error=str(exc))
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="saslik-takeaway-job")
    parser.add_argument("action", choices=("run",))
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--job", required=True)
    parser.add_argument("--owner-uid", type=int, required=True)
    args = parser.parse_args(argv)
    run_job(args.data_root.resolve(), args.job, args.owner_uid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
