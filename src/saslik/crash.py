from __future__ import annotations

import argparse
import json
import os
import select
import shutil
import signal as signals
import socket
import subprocess
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path

from .settings import setting_value


def _run(command: list[str], *, timeout: int = 90) -> str:
    try:
        result = subprocess.run(command, check=False, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=timeout)
        return result.stdout
    except (OSError, subprocess.SubprocessError) as exc:
        return f"Command failed: {exc}\n"


def _record_for_pid(pid: int) -> dict[str, object] | None:
    output = _run(["coredumpctl", "--no-pager", "--json=short", "list", str(pid)], timeout=10)
    for line in reversed(output.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and str(value.get("COREDUMP_PID") or value.get("PID")) == str(pid):
            return value
    return None


def _latest_for_unit(unit: str) -> dict[str, object] | None:
    output = _run(["coredumpctl", "--no-pager", "--json=short", "list",
                   f"COREDUMP_UNIT={unit}"], timeout=10)
    for line in reversed(output.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _copy_if_present(source: Path, destination: Path) -> None:
    if source.is_file():
        shutil.copy2(source, destination)


def collect(lab: Path, component: str, unit: str, pid: int | None = None,
            debug_output: bytes = b"", forced: bool = False) -> Path | None:
    if not forced and os.environ.get("SERVICE_RESULT") in {"success", "skip"}:
        return None
    if not forced and (lab / "state/crashes/.diagnostic-in-progress").exists():
        return None
    environment_pid = os.environ.get("MAINPID", "")
    if pid is None and environment_pid.isdigit() and int(environment_pid) > 0:
        pid = int(environment_pid)
    record = None
    for _ in range(25):
        record = _record_for_pid(pid) if pid else _latest_for_unit(unit)
        if record:
            break
        time.sleep(0.2)
    record_pid = int(record.get("COREDUMP_PID") or record.get("PID") or 0) if record else 0
    pid = pid or record_pid or int(os.environ.get("MAINPID", "0") or 0)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = lab / "state/crashes"
    directory.mkdir(parents=True, exist_ok=True)
    owner = lab.stat()
    prefix = f"{timestamp}-{component}-{pid or 'unknown'}"
    destination = directory / f"{prefix}.txt"
    if record and pid:
        coredump_info = _run(["coredumpctl", "--no-pager", "info", str(pid)])
    else:
        coredump_info = ("No matching coredump was found. SIGKILL never produces a core dump; "
                         "also check kernel.core_pattern and systemd-coredump limits.\n")
    trace = "Backtrace collection is disabled.\n"
    if record and pid and setting_value(lab, "collect_backtraces") is True:
        trace = _run(["coredumpctl", "--no-pager", "debug", str(pid),
                      "--debugger-arguments=-batch -ex thread apply all bt full"])
    journal = _run(["journalctl", "--no-pager", "-u", unit, "-n", "1000"])
    destination.write_text(
        f"Saslik crash report: {component}\nUnit: {unit}\nPID: {pid or 'unknown'}\n"
        f"Forced diagnostic: {'yes' if forced else 'no'}\n"
        f"Service result: {os.environ.get('SERVICE_RESULT', 'unknown')}\n\n"
        f"--- coredump info ---\n{coredump_info}\n--- backtrace ---\n{trace}",
        encoding="utf-8",
    )
    (directory / f"{prefix}.journal.log").write_text(journal, encoding="utf-8")
    if debug_output:
        (directory / f"{prefix}.cli-debug.log").write_bytes(debug_output)
    _copy_if_present(lab / "state/smithproxy.log", directory / f"{prefix}.service.log")
    _copy_if_present(lab / "state/messages.default.log.crashlog.log",
                     directory / f"{prefix}.native-crash.log")
    if record and pid and setting_value(lab, "collect_coredumps") is True:
        _run(["coredumpctl", "--no-pager", "dump", str(pid),
              f"--output={directory / f'{prefix}.core'}"])
    for path in directory.glob(f"{prefix}.*"):
        path.chmod(0o600)
        os.chown(path, owner.st_uid, owner.st_gid)
    os.chown(directory, owner.st_uid, owner.st_gid)
    return destination


def diagnose_smithproxy(lab: Path, instance: str, signal_number: int) -> Path:
    if signal_number not in {signals.SIGKILL, signals.SIGSEGV}:
        raise ValueError("Only SIGKILL and SIGSEGV are supported.")
    from .runtime import WorkspaceRuntime
    unit = WorkspaceRuntime.for_workspace(lab, instance).unit_name("smithproxy")
    show = _run(["systemctl", "show", unit, "--property=MainPID", "--value"], timeout=10).strip()
    if not show.isdigit() or int(show) <= 0:
        raise RuntimeError("Smithproxy is not running.")
    pid = int(show)
    marker = lab / "state/crashes/.diagnostic-in-progress"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()
    captured = bytearray()
    try:
        with socket.create_connection(("127.0.0.1", 55000), timeout=3) as stream:
            stream.setblocking(False)
            stream.sendall(b"debug set all 8\r\ndebug term 8\r\n")
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                readable, _, _ = select.select([stream], [], [], min(0.2, deadline - time.monotonic()))
                if not readable:
                    continue
                try:
                    chunk = stream.recv(65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    break
                captured.extend(chunk)
        subprocess.run(["systemctl", "kill", "--kill-whom=main",
                        f"--signal={signal_number}", unit], check=True)
        report = collect(lab, "smithproxy", unit, pid=pid,
                         debug_output=bytes(captured), forced=True)
    finally:
        marker.unlink(missing_ok=True)
    if report is None:
        raise RuntimeError("Crash report was not created.")
    return report


def reports(lab: Path) -> list[Path]:
    directory = lab / "state/crashes"
    return [path for path in sorted(directory.glob("*.txt")) if path.is_file()] if directory.is_dir() else []


def _report_files(lab: Path) -> list[Path]:
    directory = lab / "state/crashes"
    if not directory.is_dir():
        return []
    prefixes = {path.stem for path in reports(lab)}
    return [path for path in sorted(directory.iterdir())
            if path.is_file() and any(path.name == prefix or path.name.startswith(prefix + ".")
                                      for prefix in prefixes)]


def clear_reports(lab: Path) -> int:
    count = len(reports(lab))
    for path in _report_files(lab):
        path.unlink()
    return count


def save_bundle(lab: Path, destination: Path) -> int:
    paths = _report_files(lab)
    with tarfile.open(destination, "w:gz") as bundle:
        for path in paths:
            bundle.add(path, arcname=path.name, recursive=False)
    return len(reports(lab))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="saslik-crash")
    parser.add_argument("action", choices=("collect",))
    parser.add_argument("--lab", required=True, type=Path)
    parser.add_argument("--component", required=True)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--pid", type=int)
    args = parser.parse_args(argv)
    try:
        collect(args.lab, args.component, args.unit, args.pid)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"saslik-crash: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
