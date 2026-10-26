from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from .runtime import WorkspaceRuntime


NS_IF = "eth0"
PROBE_NS_IF = "probe-in"
IP_FORWARD = Path("/proc/sys/net/ipv4/ip_forward")
IP_FORWARD_STATE = Path("/run/saslik/ip_forward.before")


def _run(command: list[str], *, tolerate: bool = False,
         input_text: str | None = None) -> None:
    result = subprocess.run(command, input=input_text, text=True, check=False,
                            stdout=subprocess.DEVNULL if tolerate else None,
                            stderr=subprocess.DEVNULL if tolerate else None)
    if result.returncode and not tolerate:
        raise RuntimeError(f"Příkaz selhal ({result.returncode}): {' '.join(command)}")


def down(lab: Path, runtime: WorkspaceRuntime) -> None:
    _run(["nft", "delete", "table", "ip", runtime.network_nft_table], tolerate=True)
    # Remove exact legacy runner rules once during migration. Never flush a
    # global table owned by another application.
    for port in ("55580", "33128", "55000"):
        _run(["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp",
              "--dport", port, "-j", "DNAT", "--to-destination",
              f"{runtime.namespace_address}:{port}"], tolerate=True)
    _run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s",
          f"{runtime.namespace_address}/32", "-j", "MASQUERADE"], tolerate=True)
    _run(["iptables", "-D", "FORWARD", "-i", runtime.host_interface, "-j", "ACCEPT"], tolerate=True)
    _run(["iptables", "-D", "FORWARD", "-o", runtime.host_interface, "-m", "conntrack",
          "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"], tolerate=True)
    _run(["ip", "netns", "del", runtime.probe_namespace], tolerate=True)
    _run(["ip", "netns", "del", runtime.namespace], tolerate=True)
    _run(["ip", "link", "del", runtime.host_interface], tolerate=True)
    # IPv4 forwarding is host-global, unlike the workspace resources above.
    # Restore it only after the final Saslik workspace has disappeared.
    other_interfaces = any(
        Path("/sys/class/net").glob("ws[0-9][0-9][0-9]h")
    )
    if not other_interfaces and IP_FORWARD_STATE.is_file():
        IP_FORWARD.write_text(
            IP_FORWARD_STATE.read_text(encoding="ascii").strip() + "\n",
            encoding="ascii",
        )
        IP_FORWARD_STATE.unlink()

    # Remove obsolete per-workspace snapshots left by pre-multi-workspace
    # versions. They must not restore a host-global setting independently.
    (lab / "state/ip_forward.before").unlink(missing_ok=True)


def up(lab: Path, runtime: WorkspaceRuntime) -> None:
    state = lab / "state"
    state.mkdir(parents=True, exist_ok=True)
    down(lab, runtime)
    if not IP_FORWARD_STATE.exists():
        IP_FORWARD_STATE.parent.mkdir(parents=True, exist_ok=True)
        IP_FORWARD_STATE.write_text(
            IP_FORWARD.read_text(encoding="ascii"), encoding="ascii"
        )
    try:
        _run(["ip", "netns", "add", runtime.namespace])
        _run(["ip", "link", "add", runtime.host_interface, "type", "veth", "peer", "name",
              NS_IF, "netns", runtime.namespace])
        _run(["ip", "addr", "add", f"{runtime.host_address}/30", "dev", runtime.host_interface])
        _run(["ip", "link", "set", runtime.host_interface, "up"])
        _run(["ip", "-n", runtime.namespace, "link", "set", "lo", "up"])
        _run(["ip", "-n", runtime.namespace, "addr", "add", f"{runtime.namespace_address}/30", "dev", NS_IF])
        _run(["ip", "-n", runtime.namespace, "link", "set", NS_IF, "up"])
        _run(["ip", "-n", runtime.namespace, "route", "add", "default", "via", runtime.host_address])
        _run(["ip", "netns", "add", runtime.probe_namespace])
        _run(["ip", "link", "add", runtime.probe_host_interface, "type", "veth",
              "peer", "name", runtime.probe_peer_interface])
        _run(["ip", "link", "set", runtime.probe_host_interface,
              "netns", runtime.namespace])
        _run(["ip", "link", "set", runtime.probe_peer_interface,
              "netns", runtime.probe_namespace])
        _run(["ip", "-n", runtime.namespace, "link", "set",
              runtime.probe_host_interface, "name", PROBE_NS_IF])
        _run(["ip", "-n", runtime.probe_namespace, "link", "set",
              runtime.probe_peer_interface, "name", "eth0"])
        _run(["ip", "-n", runtime.namespace, "addr", "add", f"{runtime.probe_gateway}/30", "dev", PROBE_NS_IF])
        _run(["ip", "-n", runtime.namespace, "link", "set", PROBE_NS_IF, "up"])
        _run(["ip", "-n", runtime.probe_namespace, "link", "set", "lo", "up"])
        _run(["ip", "-n", runtime.probe_namespace, "addr", "add", f"{runtime.probe_address}/30", "dev", "eth0"])
        _run(["ip", "-n", runtime.probe_namespace, "link", "set", "eth0", "up"])
        _run(["ip", "-n", runtime.probe_namespace, "route", "add", "default", "via", runtime.probe_gateway])
        _run(["ip", "netns", "exec", runtime.namespace, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1"])
        IP_FORWARD.write_text("1\n", encoding="ascii")
        _run(["nft", "-f", "-"], input_text=f"""
table ip {runtime.network_nft_table} {{
  chain forward {{
    type filter hook forward priority filter; policy accept;
    iifname \"{runtime.host_interface}\" accept
    oifname \"{runtime.host_interface}\" ct state established,related accept
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr {runtime.namespace_address}/32 masquerade
  }}
}}
""")
    except Exception:
        down(lab, runtime)
        raise
    print(f"Namespace {runtime.namespace}: {runtime.host_address} <-> {runtime.namespace_address}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="saslik-network")
    parser.add_argument("action", choices=("up", "down"))
    parser.add_argument("lab", type=Path)
    parser.add_argument("--instance", default="default")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("saslik-network musí běžet přes sudo.", file=sys.stderr)
        return 1
    try:
        runtime = WorkspaceRuntime.for_workspace(args.lab, args.instance)
        up(args.lab, runtime) if args.action == "up" else down(args.lab, runtime)
    except (OSError, RuntimeError) as exc:
        print(f"saslik-network: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
