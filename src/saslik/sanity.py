from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from .runtime import WorkspaceRuntime


LEGACY_PORTS = {15173, 15174, 18080, 18081, 33128, 55000, 55580}


def _capture(command: list[str]) -> str:
    result = subprocess.run(command, check=False, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return result.stdout.strip()


def _processes(lab: Path, runtime: WorkspaceRuntime) -> list[str]:
    needles = (
        str(lab / "build/smithproxy/smithproxy"),
        str(lab / "build/spider/smithproxy-spider"),
        str(lab / "build/sift/siftd"),
        str(lab / "build/lore/lored/lored"),
        str(lab / "runtime/pcap-viewer-venv/bin/capture-viewer"),
        str(lab / "runtime/pcap-viewer-venv/bin/capture-storage"),
        str(lab / "build/smithproxy-gui/smithproxy-gui"),
        "TCP4-LISTEN:55580", "TCP4-LISTEN:33128", "TCP4-LISTEN:55000",
        "OPENSSL-LISTEN:15173", "OPENSSL-LISTEN:15174",
        *(f"TCP4-LISTEN:{port}" for port in runtime.public_ports.values()),
    )
    found: list[str] = []
    for process in Path("/proc").glob("[0-9]*"):
        try:
            command = process.joinpath("cmdline").read_bytes().replace(
                b"\0", b" ").decode("utf-8").strip()
            if command and any(needle in command for needle in needles):
                found.append(f"PID {process.name}: {command}")
        except (OSError, UnicodeDecodeError):
            pass
    return sorted(found)


def collect(lab: Path, runtime: WorkspaceRuntime) -> list[tuple[str, list[str]]]:
    groups: list[tuple[str, list[str]]] = []
    units = [line for line in _capture([
        "systemctl", "list-units", "--all", "--plain", "--no-legend",
        f"{runtime.prefix}-*.service", runtime.slice_name,
    ]).splitlines() if "guardian" not in line and "control.slice" not in line]
    groups.append(("systemd", units))
    groups.append(("processes", _processes(lab, runtime)))

    sockets = []
    for line in _capture(["ss", "-H", "-ltnup"]).splitlines():
        fields = line.split()
        ports = LEGACY_PORTS | set(runtime.public_ports.values())
        if any(f":{port}" in line for port in ports):
            sockets.append(line)
    groups.append(("ports", sockets))

    namespaces = [line for line in _capture(["ip", "netns", "list"]).splitlines()
                  if line.split() and line.split()[0] in {
                      runtime.namespace, runtime.probe_namespace}]
    groups.append(("namespaces", namespaces))
    interfaces = [name for name in {runtime.host_interface}
                  if Path("/sys/class/net", name).exists()]
    groups.append(("interfaces", sorted(interfaces)))

    kernel = []
    nft = _capture(["nft", "list", "tables"])
    kernel.extend(line for line in nft.splitlines() if runtime.nft_prefix in line)
    kernel.extend(line for line in _capture(["ip", "rule", "show"]).splitlines()
                  if runtime.rule_preference in line or runtime.route_table in line
                  or runtime.route_mark in line)
    route = _capture(["ip", "route", "show", "table", runtime.route_table])
    if route:
        kernel.extend(f"table {runtime.route_table}: {line}" for line in route.splitlines())
    groups.append(("routing", kernel))

    state = lab / "state"
    artifact_names = {
        "service.pid", "smithproxy.pid", "spider.pid", "sift.pid",
        "frontend.pid", "pcap-viewer.pid", "cli-forward.pid",
        "expose-api.pid", "expose-proxy.pid", "expose-socks.pid", "expose-cli.pid",
        "pasta.pid", "pasta.ip_forward.before", "ip_forward.before",
        "netns-resolv.managed",
    }
    artifacts = [str(path) for path in state.iterdir()
                 if path.name in artifact_names] if state.is_dir() else []
    artifacts.extend(str(path) for path in (lab / "src").glob("*/.git/index.lock"))
    pasta_mount = Path("/run/user/0/saslik") / runtime.namespace
    if pasta_mount.exists():
        artifacts.append(str(pasta_mount))
    groups.append(("files and mounts", sorted(artifacts)))
    return groups


def report(lab: Path, runtime: WorkspaceRuntime) -> int:
    print("=== SASLIK PRE-START SANITY CHECK ===")
    groups = collect(lab, runtime)
    total = 0
    for title, values in groups:
        if not values:
            continue
        total += len(values)
        print(f"[{title}] {len(values)}")
        for value in values:
            print(f"  - {value}")
    if total:
        print(f"Nalezeno {total} runtime artefaktů; následuje řízený cleanup.")
    else:
        print("Runtime je čistý; nebyly nalezeny žádné artefakty předchozího běhu.")
    print("=== END SANITY CHECK ===")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="saslik-sanity")
    parser.add_argument("action", choices=("report",))
    parser.add_argument("lab", type=Path)
    parser.add_argument("--instance", default="default")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("saslik-sanity musí běžet přes sudo.", file=sys.stderr)
        return 1
    return report(args.lab, WorkspaceRuntime.for_instance(args.instance))


if __name__ == "__main__":
    raise SystemExit(main())
