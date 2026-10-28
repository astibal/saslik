from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_WORKSPACE_POOL = ipaddress.IPv4Network("10.240.0.0/19")
DEFAULT_TUNNEL_POOL = ipaddress.IPv4Network("10.253.0.0/22")
DEFAULT_SERVICE_ADDRESS = ipaddress.IPv4Address("10.252.255.1")
ADDRESSES_PER_WORKSPACE = 8
MAX_WORKSPACES = 999
PLAN_FILE = "network-plan.json"

PRIVATE_RANGES = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("100.64.0.0/10"),
    ipaddress.IPv4Network("198.18.0.0/15"),
)


@dataclass(frozen=True)
class NetworkPlan:
    workspace_pool: ipaddress.IPv4Network = DEFAULT_WORKSPACE_POOL
    tunnel_pool: ipaddress.IPv4Network = DEFAULT_TUNNEL_POOL
    service_address: ipaddress.IPv4Address = DEFAULT_SERVICE_ADDRESS

    @classmethod
    def parse(cls, workspace_pool: str, tunnel_pool: str,
              service_address: str) -> "NetworkPlan":
        try:
            plan = cls(
                ipaddress.IPv4Network(workspace_pool.strip(), strict=True),
                ipaddress.IPv4Network(tunnel_pool.strip(), strict=True),
                ipaddress.IPv4Address(service_address.strip()),
            )
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
            raise ValueError(f"Neplatná IPv4 adresa nebo síť: {exc}") from exc
        plan.validate()
        return plan

    def validate(self, connected: Iterable[ipaddress.IPv4Network] = ()) -> None:
        if self.workspace_pool.num_addresses < MAX_WORKSPACES * ADDRESSES_PER_WORKSPACE:
            raise ValueError("Workspace pool musí pojmout 999 bloků po 8 adresách (alespoň /19).")
        if self.tunnel_pool.num_addresses < 1024:
            raise ValueError("Tunnel pool musí mít alespoň 1024 adres (/22 nebo větší).")
        networks = {
            "workspace pool": self.workspace_pool,
            "tunnel pool": self.tunnel_pool,
            "service point": ipaddress.IPv4Network(f"{self.service_address}/32"),
        }
        for label, network in networks.items():
            if not any(network.subnet_of(allowed) for allowed in PRIVATE_RANGES):
                raise ValueError(f"{label} {network} není v podporovaném privátním rozsahu.")
        pairs = list(networks.items())
        for index, (left_name, left) in enumerate(pairs):
            for right_name, right in pairs[index + 1:]:
                if left.overlaps(right):
                    raise ValueError(f"{left_name} {left} koliduje s {right_name} {right}.")
        conflicts = sorted({str(existing) for existing in connected
                            if not existing.is_loopback
                            and any(network.overlaps(existing) for network in networks.values())})
        if conflicts:
            raise ValueError("Network plan koliduje s připojenou sítí hosta: " + ", ".join(conflicts))

    def as_dict(self) -> dict[str, object]:
        return {
            "version": 1,
            "workspace_pool": str(self.workspace_pool),
            "tunnel_pool": str(self.tunnel_pool),
            "service_address": str(self.service_address),
        }


def load(root: Path) -> NetworkPlan:
    path = root / PLAN_FILE
    if not path.is_file():
        return NetworkPlan()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return NetworkPlan.parse(str(value["workspace_pool"]), str(value["tunnel_pool"]),
                                 str(value["service_address"]))
    except (OSError, KeyError, TypeError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError(f"Network plan {path} nelze načíst: {exc}") from exc


def root_for_lab(lab: Path) -> Path | None:
    """Resolve the installation data root from legacy or instances layout."""
    lab = lab.resolve()
    if lab.parent.name == "instances":
        return lab.parent.parent
    if lab.name == "lab":
        return lab.parent
    for candidate in (lab.parent, lab.parent.parent):
        if (candidate / PLAN_FILE).is_file():
            return candidate
    return None


def load_for_lab(lab: Path) -> NetworkPlan:
    root = root_for_lab(lab)
    return load(root) if root is not None else NetworkPlan()


def save(root: Path, plan: NetworkPlan) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    destination = root / PLAN_FILE
    descriptor, temporary = tempfile.mkstemp(prefix=f".{PLAN_FILE}.", dir=root)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(plan.as_dict(), stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return destination


def connected_networks() -> list[ipaddress.IPv4Network]:
    """Return real host link networks; failure is safe and yields no guesses."""
    try:
        output = subprocess.run(
            ["ip", "-j", "-4", "address", "show"], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        ).stdout
        links = json.loads(output)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return []
    result: set[ipaddress.IPv4Network] = set()
    for link in links if isinstance(links, list) else []:
        name = str(link.get("ifname", ""))
        if name == "lo" or name.startswith(("ws", "sxp-", "saslik")):
            continue
        for address in link.get("addr_info", []):
            if address.get("family") != "inet":
                continue
            try:
                result.add(ipaddress.IPv4Network(
                    f"{address['local']}/{address['prefixlen']}", strict=False))
            except (KeyError, ValueError):
                continue
    return sorted(result, key=lambda item: (int(item.network_address), item.prefixlen))
