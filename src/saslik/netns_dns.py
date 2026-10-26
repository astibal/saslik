from __future__ import annotations

import os
from pathlib import Path

from .runtime import WorkspaceRuntime


def _paths(runtime: WorkspaceRuntime) -> tuple[Path, Path]:
    directory = Path("/etc/netns") / runtime.namespace
    return directory, directory / "resolv.conf"


def up(lab: Path, nameserver: str, runtime: WorkspaceRuntime) -> None:
    state = lab / "state"
    state.mkdir(parents=True, exist_ok=True)
    marker = state / "netns-resolv.managed"
    backup = state / "netns-resolv.before"
    directory, resolv = _paths(runtime)
    if not marker.exists():
        if resolv.exists():
            backup.write_bytes(resolv.read_bytes())
        marker.write_text("1\n", encoding="ascii")
    directory.mkdir(parents=True, exist_ok=True)
    resolv.write_text(f"# managed by Saslik\nnameserver {nameserver}\n", encoding="ascii")
    print(f"Namespace DNS: {nameserver}")


def down(lab: Path, runtime: WorkspaceRuntime) -> None:
    state = lab / "state"
    marker = state / "netns-resolv.managed"
    backup = state / "netns-resolv.before"
    if not marker.exists():
        return
    directory, resolv = _paths(runtime)
    if backup.exists():
        resolv.write_bytes(backup.read_bytes())
        backup.unlink()
    else:
        try:
            if resolv.read_text(encoding="ascii").startswith("# managed by Saslik\n"):
                resolv.unlink()
        except FileNotFoundError:
            pass
        try:
            directory.rmdir()
        except OSError:
            pass
    marker.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="saslik-netns-dns")
    parser.add_argument("action", choices=("up", "down"))
    parser.add_argument("lab", type=Path)
    parser.add_argument("--instance", default="default")
    parser.add_argument("--nameserver", default="1.1.1.1")
    args = parser.parse_args(argv)
    try:
        runtime = WorkspaceRuntime.for_workspace(args.lab, args.instance)
        up(args.lab, args.nameserver, runtime) if args.action == "up" else down(args.lab, runtime)
    except OSError as exc:
        print(f"saslik-netns-dns: {exc}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
