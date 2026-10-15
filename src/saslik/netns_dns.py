from __future__ import annotations

import os
from pathlib import Path


NAMESPACE = "sxp-test"
NETNS_DIR = Path("/etc/netns") / NAMESPACE
RESOLV = NETNS_DIR / "resolv.conf"


def up(lab: Path, nameserver: str) -> None:
    state = lab / "state"
    state.mkdir(parents=True, exist_ok=True)
    marker = state / "netns-resolv.managed"
    backup = state / "netns-resolv.before"
    if not marker.exists():
        if RESOLV.exists():
            backup.write_bytes(RESOLV.read_bytes())
        marker.write_text("1\n", encoding="ascii")
    NETNS_DIR.mkdir(parents=True, exist_ok=True)
    RESOLV.write_text(f"# managed by Saslik\nnameserver {nameserver}\n", encoding="ascii")
    print(f"Namespace DNS: {nameserver}")


def down(lab: Path) -> None:
    state = lab / "state"
    marker = state / "netns-resolv.managed"
    backup = state / "netns-resolv.before"
    if not marker.exists():
        return
    if backup.exists():
        RESOLV.write_bytes(backup.read_bytes())
        backup.unlink()
    else:
        try:
            if RESOLV.read_text(encoding="ascii").startswith("# managed by Saslik\n"):
                RESOLV.unlink()
        except FileNotFoundError:
            pass
        try:
            NETNS_DIR.rmdir()
        except OSError:
            pass
    marker.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="saslik-netns-dns")
    parser.add_argument("action", choices=("up", "down"))
    parser.add_argument("lab", type=Path)
    parser.add_argument("--nameserver", default="1.1.1.1")
    args = parser.parse_args(argv)
    try:
        up(args.lab, args.nameserver) if args.action == "up" else down(args.lab)
    except OSError as exc:
        print(f"saslik-netns-dns: {exc}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
