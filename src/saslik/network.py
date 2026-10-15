from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


NAMESPACE = "sxp-test"
HOST_IF = "sxp-test0"
NS_IF = "eth0"
HOST_ADDR = "10.254.77.1"
NS_ADDR = "10.254.77.2"
PROBE_NAMESPACE = "saslik-probe"
PROBE_NS_IF = "probe-in"
PROBE_ADDR = "10.254.78.2"
PROBE_GATEWAY = "10.254.78.1"
NFT_TABLE = "saslik_lab"
IP_FORWARD = Path("/proc/sys/net/ipv4/ip_forward")


def _run(command: list[str], *, tolerate: bool = False,
         input_text: str | None = None) -> None:
    result = subprocess.run(command, input=input_text, text=True, check=False,
                            stdout=subprocess.DEVNULL if tolerate else None,
                            stderr=subprocess.DEVNULL if tolerate else None)
    if result.returncode and not tolerate:
        raise RuntimeError(f"Příkaz selhal ({result.returncode}): {' '.join(command)}")


def down(lab: Path) -> None:
    _run(["nft", "delete", "table", "ip", NFT_TABLE], tolerate=True)
    # Remove exact legacy runner rules once during migration. Never flush a
    # global table owned by another application.
    for port in ("55580", "33128", "55000"):
        _run(["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp",
              "--dport", port, "-j", "DNAT", "--to-destination",
              f"{NS_ADDR}:{port}"], tolerate=True)
    _run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s",
          f"{NS_ADDR}/32", "-j", "MASQUERADE"], tolerate=True)
    _run(["iptables", "-D", "FORWARD", "-i", HOST_IF, "-j", "ACCEPT"], tolerate=True)
    _run(["iptables", "-D", "FORWARD", "-o", HOST_IF, "-m", "conntrack",
          "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"], tolerate=True)
    _run(["ip", "netns", "del", PROBE_NAMESPACE], tolerate=True)
    _run(["ip", "netns", "del", NAMESPACE], tolerate=True)
    _run(["ip", "link", "del", HOST_IF], tolerate=True)
    snapshot = lab / "state/ip_forward.before"
    if snapshot.is_file():
        IP_FORWARD.write_text(snapshot.read_text(encoding="ascii").strip() + "\n",
                              encoding="ascii")
        snapshot.unlink()


def up(lab: Path) -> None:
    state = lab / "state"
    state.mkdir(parents=True, exist_ok=True)
    down(lab)
    snapshot = state / "ip_forward.before"
    if not snapshot.exists():
        snapshot.write_text(IP_FORWARD.read_text(encoding="ascii"), encoding="ascii")
    try:
        _run(["ip", "netns", "add", NAMESPACE])
        _run(["ip", "link", "add", HOST_IF, "type", "veth", "peer", "name",
              NS_IF, "netns", NAMESPACE])
        _run(["ip", "addr", "add", f"{HOST_ADDR}/30", "dev", HOST_IF])
        _run(["ip", "link", "set", HOST_IF, "up"])
        _run(["ip", "-n", NAMESPACE, "link", "set", "lo", "up"])
        _run(["ip", "-n", NAMESPACE, "addr", "add", f"{NS_ADDR}/30", "dev", NS_IF])
        _run(["ip", "-n", NAMESPACE, "link", "set", NS_IF, "up"])
        _run(["ip", "-n", NAMESPACE, "route", "add", "default", "via", HOST_ADDR])
        _run(["ip", "netns", "add", PROBE_NAMESPACE])
        _run(["ip", "link", "add", "sxp-probe0", "type", "veth", "peer", "name", "sxp-probe1"])
        _run(["ip", "link", "set", "sxp-probe0", "netns", NAMESPACE])
        _run(["ip", "link", "set", "sxp-probe1", "netns", PROBE_NAMESPACE])
        _run(["ip", "-n", NAMESPACE, "link", "set", "sxp-probe0", "name", PROBE_NS_IF])
        _run(["ip", "-n", PROBE_NAMESPACE, "link", "set", "sxp-probe1", "name", "eth0"])
        _run(["ip", "-n", NAMESPACE, "addr", "add", f"{PROBE_GATEWAY}/30", "dev", PROBE_NS_IF])
        _run(["ip", "-n", NAMESPACE, "link", "set", PROBE_NS_IF, "up"])
        _run(["ip", "-n", PROBE_NAMESPACE, "link", "set", "lo", "up"])
        _run(["ip", "-n", PROBE_NAMESPACE, "addr", "add", f"{PROBE_ADDR}/30", "dev", "eth0"])
        _run(["ip", "-n", PROBE_NAMESPACE, "link", "set", "eth0", "up"])
        _run(["ip", "-n", PROBE_NAMESPACE, "route", "add", "default", "via", PROBE_GATEWAY])
        _run(["ip", "netns", "exec", NAMESPACE, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1"])
        IP_FORWARD.write_text("1\n", encoding="ascii")
        _run(["nft", "-f", "-"], input_text=f"""
table ip {NFT_TABLE} {{
  chain forward {{
    type filter hook forward priority filter; policy accept;
    iifname \"{HOST_IF}\" accept
    oifname \"{HOST_IF}\" ct state established,related accept
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr {NS_ADDR}/32 masquerade
  }}
}}
""")
    except Exception:
        down(lab)
        raise
    print(f"Namespace {NAMESPACE}: {HOST_ADDR} <-> {NS_ADDR}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="saslik-network")
    parser.add_argument("action", choices=("up", "down"))
    parser.add_argument("lab", type=Path)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("saslik-network musí běžet přes sudo.", file=sys.stderr)
        return 1
    try:
        up(args.lab) if args.action == "up" else down(args.lab)
    except (OSError, RuntimeError) as exc:
        print(f"saslik-network: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
