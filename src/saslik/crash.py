from __future__ import annotations

import argparse
import json
import os
import subprocess
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path


def _latest_for_unit(unit: str) -> dict[str, object] | None:
    result = subprocess.run(
        ["coredumpctl", "--no-pager", "--json=short", "--reverse", "list",
         f"COREDUMP_UNIT={unit}"],
        check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    for line in result.stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def collect(lab: Path, component: str, unit: str) -> Path | None:
    if os.environ.get("SERVICE_RESULT") in {"success", "skip"}:
        return None
    record = None
    for _ in range(15):
        record = _latest_for_unit(unit)
        if record:
            break
        time.sleep(0.2)
    if not record:
        return None
    pid = str(record.get("COREDUMP_PID") or record.get("PID") or "")
    if not pid.isdigit():
        return None
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = lab / "state/crashes"
    directory.mkdir(parents=True, exist_ok=True)
    owner = lab.stat()
    os.chown(directory, owner.st_uid, owner.st_gid)
    destination = directory / f"{timestamp}-{component}-{pid}.txt"
    info = subprocess.run(["coredumpctl", "--no-pager", "info", pid], check=False,
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    trace = subprocess.run(
        ["coredumpctl", "--no-pager", "debug", pid,
         "--debugger-arguments=-batch -ex thread apply all bt full"],
        check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=90,
    )
    destination.write_text(
        f"Saslik crash report: {component}\nUnit: {unit}\nPID: {pid}\n\n"
        f"--- coredump info ---\n{info.stdout}\n--- backtrace ---\n{trace.stdout}",
        encoding="utf-8",
    )
    destination.chmod(0o600)
    os.chown(destination, owner.st_uid, owner.st_gid)
    return destination


def reports(lab: Path) -> list[Path]:
    directory = lab / "state/crashes"
    if not directory.is_dir():
        return []
    return [path for path in sorted(directory.glob("*.txt")) if path.is_file()]


def clear_reports(lab: Path) -> int:
    paths = reports(lab)
    for path in paths:
        path.unlink()
    return len(paths)


def save_bundle(lab: Path, destination: Path) -> int:
    paths = reports(lab)
    with tarfile.open(destination, "w:gz") as bundle:
        for path in paths:
            bundle.add(path, arcname=path.name, recursive=False)
    return len(paths)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="saslik-crash")
    parser.add_argument("action", choices=("collect",))
    parser.add_argument("--lab", required=True, type=Path)
    parser.add_argument("--component", required=True)
    parser.add_argument("--unit", required=True)
    args = parser.parse_args(argv)
    try:
        collect(args.lab, args.component, args.unit)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"saslik-crash: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
