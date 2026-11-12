"""Launch the workspace GRE collector with validated component settings."""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .runtime import WorkspaceRuntime
from .settings import gretom_settings


def collector_arguments(binary: Path, session: Path, interface: str,
                        values: dict[str, object], prefix: str) -> list[str]:
    device = interface if values["gretom_interface"] == "auto" else str(values["gretom_interface"])
    command = [str(binary), "-d", device, "-D", str(session), "-p", prefix]
    for key, option in (("gretom_rotate_seconds", "-t"), ("gretom_rotate_mib", "-s"),
                        ("gretom_rotate_packets", "-c")):
        command.extend((option, str(values[key])))
    for key, option in (("gretom_midnight", "-M"), ("gretom_rotation_time", "-R"),
                        ("gretom_verbose", "-v")):
        if values[key]:
            command.append(option)
    return command



def launch(lab: Path, instance: str, interface: str) -> None:
    lab = lab.resolve()
    binary = lab / "build/gretom/gretom"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError("GRE Tom ještě není sestavený. Aktualizuj komponentu GRE Tom.")
    values = gretom_settings(lab)
    workspace = WorkspaceRuntime.for_workspace(lab, instance)
    captures = lab / "state/gretom"
    captures.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    session = Path(tempfile.mkdtemp(prefix=f"run-{stamp}-", dir=captures))
    # Include the workspace and run ID even when storage flattens directories.
    prefix = f"{values['gretom_prefix']}-ws{workspace.workspace_id:03d}-{session.name}"
    command = collector_arguments(binary, session, interface, values, prefix)
    print(f"GRE Tom: arguments={command[1:]} output={session}", flush=True)
    os.execv(str(binary), command)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", type=Path, required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--interface", required=True)
    args = parser.parse_args(argv)
    try:
        launch(args.lab, args.instance, args.interface)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"saslik-gretom: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
