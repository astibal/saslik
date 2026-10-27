from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import TypeAlias

from .runtime import ADDRESS_POOL
from .settings import setting_value


TUNTOM_POOL = ipaddress.ip_network("10.253.0.0/22")
Network: TypeAlias = ipaddress.IPv4Network | ipaddress.IPv6Network
Address: TypeAlias = ipaddress.IPv4Address | ipaddress.IPv6Address
_INTERNAL_INTERFACE = re.compile(
    r"^(?:ws\d{3}(?:h|p[01])|skt\d+[sc]|veth.*|docker\d*|br-[0-9a-f]+|"
    r"podman\d*|virbr\d*|tun\d*|tap\d*)$"
)
_cache_lock = threading.Lock()
_cached_at = 0.0
_cached_networks: tuple[Network, ...] = ()


def parse_networks(value: object) -> tuple[Network, ...]:
    """Parse the human-editable CIDR list into canonical, unique networks."""
    networks: list[Network] = []
    for line in str(value or "").splitlines():
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        network = ipaddress.ip_network(candidate, strict=False)
        if network not in networks:
            networks.append(network)
    return tuple(networks)


def _route_networks(family: int) -> list[Network]:
    command = ["ip", "-j"]
    if family == 6:
        command.append("-6")
    command.extend(("route", "show", "table", "main", "scope", "link"))
    result = subprocess.run(command, capture_output=True, text=True, timeout=2)
    if result.returncode:
        return []
    networks: list[Network] = []
    for route in json.loads(result.stdout or "[]"):
        device = str(route.get("dev", ""))
        destination = route.get("dst")
        if not destination or device == "lo" or _INTERNAL_INTERFACE.fullmatch(device):
            continue
        try:
            network = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            continue
        if network.is_loopback or network.subnet_of(ADDRESS_POOL) \
                or network.subnet_of(TUNTOM_POOL):
            continue
        networks.append(network)
    return networks


def host_connected_networks(*, max_age: float = 5.0) \
        -> tuple[Network, ...]:
    """Return host-facing link networks, excluding Saslik-owned transports."""
    global _cached_at, _cached_networks
    now = time.monotonic()
    with _cache_lock:
        if now - _cached_at <= max_age:
            return _cached_networks
        try:
            discovered = [*_route_networks(4), *_route_networks(6)]
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            discovered = []
        _cached_networks = tuple(dict.fromkeys(discovered))
        _cached_at = now
        return _cached_networks


def access_allowed(lab: Path, address: str, *,
                   host_networks: tuple[Network, ...] | None = None,
                   tunnel_addresses: tuple[Address, ...] = ()) -> bool:
    """Evaluate one workspace's API policy against the real gateway peer."""
    try:
        client = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(client, ipaddress.IPv6Address) and client.ipv4_mapped:
        client = client.ipv4_mapped
    if client.is_loopback:
        return True
    if setting_value(lab, "api_allow_tuntom") is True and client in tunnel_addresses:
        return True
    if setting_value(lab, "api_allow_host_networks") is True:
        networks = host_connected_networks() if host_networks is None else host_networks
        if any(client.version == network.version and client in network for network in networks):
            return True
    return any(client.version == network.version and client in network
               for network in parse_networks(setting_value(lab, "api_allowed_prefixes")))
