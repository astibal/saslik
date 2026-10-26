from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

from .instance import Instance
from .runtime import WorkspaceRuntime


PROBE_IF = "probe-in"


def _run(command: list[str], *, input_text: str | None = None, tolerate: bool = False,
         capture: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command, input=input_text, text=True, check=False,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture or tolerate else None,
    )
    if result.returncode and not tolerate:
        detail = (result.stderr or "").strip()
        raise RuntimeError(detail or f"Příkaz selhal ({result.returncode}): {' '.join(command)}")
    return result


def apply_starting_template(lab: Path, template: str = "spider-sift") -> bool:
    """Seed a newly created config. Never call this for a running lab."""
    path = lab / "state/smithproxy.cfg"
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    updated = text
    replacements = {
        r"(\baccept_tproxy\s*=\s*)false": r"\1true",
        r"(\bplaintext_workers\s*=\s*)0": r"\g<1>1",
        r"(\bssl_workers\s*=\s*)0": r"\g<1>1",
        r"(\budp_workers\s*=\s*)0": r"\g<1>1",
        r"(\bdtls_workers\s*=\s*)0": r"\g<1>1",
        # Public sites occasionally staple an unverifiable OCSP response.
        # A disposable inspection lab should log that condition, not replace
        # an otherwise valid page with Smithproxy's TLS warning response.
        r"(\bocsp_mode\s*=\s*)1": r"\g<1>0",
        r"(\bocsp_stapling\s*=\s*)true": r"\g<1>false",
        r"(\bocsp_stapling_mode\s*=\s*)1": r"\g<1>0",
    }
    for pattern, replacement in replacements.items():
        updated = re.sub(pattern, replacement, updated, count=1, flags=re.IGNORECASE)
    template_values = {
        "spider-sift": ("true", "true", "true"),
        "spider": ("true", "false", "true"),
        "proxy": ("false", "false", "false"),
    }
    if template not in template_values:
        raise RuntimeError(f"Neznámá počáteční šablona: {template}")
    webhook, sift, content_webhook = template_values[template]
    webhook_match = re.search(r"(\bwebhook\s*=\s*\{)(.*?)(\n\s*\}(?:;)?)", updated, re.I | re.S)
    if webhook_match:
        body = webhook_match.group(2)
        if not re.search(r"\bsift\s*=", body, re.I):
            body += f"\n        sift = {sift};"
        if not re.search(r"\bsift_url\s*=", body, re.I):
            body += '\n        sift_url = "http://127.0.0.1:18081/webhook";'
        updated = updated[:webhook_match.start(2)] + body + updated[webhook_match.end(2):]
    updated = re.sub(r"(\bwebhook\s*=\s*\{.*?\benabled\s*=\s*)(true|false)",
                     rf"\g<1>{webhook}", updated, count=1, flags=re.I | re.S)
    updated = re.sub(r"(\bwebhook\s*=\s*\{.*?\bsift\s*=\s*)(true|false)",
                     rf"\g<1>{sift}", updated, count=1, flags=re.I | re.S)
    updated = re.sub(r"(\bcontent_profiles\s*=\s*\{.*?\bdefault\s*=\s*\{.*?\bwebhook_enable\s*=\s*)(true|false)",
                     rf"\g<1>{content_webhook}", updated, count=1, flags=re.I | re.S)
    if updated != text:
        path.write_text(updated, encoding="utf-8")
        return True
    return False


def _nft(script: str, runtime: WorkspaceRuntime, *, namespace: bool = False) -> None:
    command = ["nft", "-f", "-"]
    if namespace:
        command = ["ip", "netns", "exec", runtime.namespace, *command]
    _run(command, input_text=script)


def namespace_down(runtime: WorkspaceRuntime) -> None:
    _run(["ip", "netns", "exec", runtime.namespace, "nft", "delete", "table", "inet",
          runtime.namespace_nft_table], tolerate=True)
    _run(["ip", "-n", runtime.namespace, "rule", "del", "pref", "100", "fwmark", "1/1", "lookup", "100"], tolerate=True)
    _run(["ip", "-n", runtime.namespace, "route", "del", "local", "0.0.0.0/0", "dev", "lo",
          "table", "100"], tolerate=True)


def routing_down(runtime: WorkspaceRuntime) -> None:
    _run(["nft", "delete", "table", "inet", runtime.host_nft_table], tolerate=True)
    _run(["ip", "rule", "del", "pref", runtime.rule_preference, "fwmark",
          f"{runtime.route_mark}/0xffff", "lookup", runtime.route_table], tolerate=True)
    _run(["ip", "route", "del", "table", runtime.route_table, "default", "via",
          runtime.namespace_address, "dev", runtime.host_interface], tolerate=True)
    namespace_down(runtime)


def _host_ipv4_addresses(runtime: WorkspaceRuntime) -> list[str]:
    result = _run(["ip", "-o", "-4", "addr", "show", "scope", "global"], capture=True)
    addresses: list[str] = []
    for line in result.stdout.splitlines():
        match = re.search(r"\binet\s+([0-9.]+)/", line)
        if match and match.group(1) not in {runtime.host_address, runtime.namespace_address}:
            addresses.append(match.group(1))
    return sorted(set(addresses))


def namespace_up(runtime: WorkspaceRuntime) -> None:
    if not Path(f"/run/netns/{runtime.namespace}").exists():
        raise RuntimeError(f"Saslik workspace neběží: chybí namespace {runtime.namespace}.")
    namespace_down(runtime)
    _run(["ip", "-n", runtime.namespace, "rule", "add", "pref", "100", "fwmark", "1/1", "lookup", "100"])
    _run(["ip", "-n", runtime.namespace, "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "100"])
    for address in _host_ipv4_addresses(runtime):
        _run(["ip", "-n", runtime.namespace, "route", "replace", f"{address}/32", "via",
              runtime.host_address, "dev", "eth0"])
    _nft(f"""
table inet {runtime.namespace_nft_table} {{
  set tunnel_interfaces {{ type ifname; }}
  chain proxy_ingress {{
    fib daddr type local return
    fib daddr type broadcast return
    fib daddr type multicast return
    tcp dport 443 counter tproxy to :50443 meta mark set 1 accept
    udp dport 443 counter tproxy to :443 meta mark set 1 accept
    meta l4proto tcp counter tproxy to :50080 meta mark set 1 accept
    meta l4proto udp counter tproxy to :50080 meta mark set 1 accept
  }}
  chain prerouting {{
    type filter hook prerouting priority mangle; policy accept;
    meta l4proto tcp socket transparent 1 meta mark set 1 accept
    iifname {{ "eth0", "{PROBE_IF}" }} jump proxy_ingress
    iifname @tunnel_interfaces jump proxy_ingress
  }}
}}
""", runtime, namespace=True)


def routing_up(uid: int, runtime: WorkspaceRuntime) -> None:
    if not Path(f"/run/netns/{runtime.namespace}").exists():
        raise RuntimeError(f"Saslik workspace neběží: chybí namespace {runtime.namespace}.")
    if not Path(f"/sys/class/net/{runtime.host_interface}").exists():
        raise RuntimeError(f"Saslik workspace neběží: chybí ingress rozhraní {runtime.host_interface}.")
    # iproute2 returns exit status 2 when a numeric table has never existed.
    # For an idempotent "up" that is the normal empty state, not an error.
    probe = _run(["ip", "route", "show", "table", runtime.route_table],
                 capture=True, tolerate=True)
    existing = probe.stdout.strip() if probe.returncode == 0 else ""
    expected = f"default via {runtime.namespace_address} dev {runtime.host_interface}"
    if existing and existing != expected:
        raise RuntimeError(f"Policy-routing tabulku {runtime.route_table} už používá jiná aplikace.")
    routing_down(runtime)

    _run(["ip", "route", "add", "table", runtime.route_table, "default", "via",
          runtime.namespace_address, "dev", runtime.host_interface])
    _run(["ip", "rule", "add", "pref", runtime.rule_preference, "fwmark",
          f"{runtime.route_mark}/0xffff", "lookup", runtime.route_table])
    _nft(f"""
table inet {runtime.host_nft_table} {{
  chain output {{
    type route hook output priority mangle; policy accept;
    meta skuid != {uid} return
    ip daddr {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }} return
    meta l4proto {{ tcp, udp }} counter meta mark set {runtime.route_mark}
  }}
}}
""", runtime)

    namespace_up(runtime)


def routing_status(runtime: WorkspaceRuntime) -> int:
    host = _run(["nft", "list", "table", "inet", runtime.host_nft_table], tolerate=True, capture=True).returncode == 0
    namespace = _run(
        ["ip", "netns", "exec", runtime.namespace, "nft", "list", "table", "inet",
         runtime.namespace_nft_table],
        tolerate=True, capture=True,
    ).returncode == 0
    print(f"host policy routing: {'up' if host else 'down'}")
    print(f"namespace TPROXY:   {'up' if namespace else 'down'}")
    print("scope:              current user, public IPv4 TCP/UDP")
    print("IPv6:               untouched")
    return 0 if host and namespace else 1


def _root(action: str, lab: Path, uid: int, runtime: WorkspaceRuntime) -> int:
    if action in {"up", "namespace-up"}:
        config = lab / "state/smithproxy.cfg"
        if not config.is_file() or not re.search(r"\baccept_tproxy\s*=\s*true", config.read_text(), re.I):
            raise RuntimeError("TPROXY není v konfiguraci aktivní; restartuj nejprve Saslik lab.")
        try:
            routing_up(uid, runtime) if action == "up" else namespace_up(runtime)
        except Exception:
            # "up" installs several kernel objects. Never leave a partial
            # policy rule behind when a later nft/ip command fails.
            routing_down(runtime)
            raise
        print("Saslik routing je zapnutý." if action == "up" else "Namespace TPROXY je zapnuté.")
        return 0
    if action == "down":
        routing_down(runtime)
        print("Saslik routing je vypnutý.")
        return 0
    return routing_status(runtime)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="saslik-routing")
    parser.add_argument("-i", "--instance", default="default")
    parser.add_argument("action", choices=("up", "down", "status", "namespace-up"))
    parser.add_argument("lab", nargs="?", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--uid", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if os.geteuid() == 0:
        lab = args.lab or Instance.load(args.instance).data_dir
        uid = args.uid if args.uid is not None else int(os.environ.get("SUDO_UID", "0"))
        return _root(args.action, lab, uid, WorkspaceRuntime.for_workspace(lab, args.instance))

    from .cli import acquire_privileges
    acquire_privileges()
    instance = Instance.load(args.instance)
    command = ["sudo", "-n", sys.executable, "-m", "saslik.routing", args.action,
               str(instance.data_dir), "--uid", str(os.getuid())]
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"saslik-routing: {exc}", file=sys.stderr)
        raise SystemExit(1)
