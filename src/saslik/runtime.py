from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path


WORKSPACE_ID_MIN = 1
WORKSPACE_ID_MAX = 999
ADDRESS_POOL = ipaddress.IPv4Network("10.240.0.0/19")
ADDRESSES_PER_WORKSPACE = 8


@dataclass(frozen=True)
class WorkspaceRuntime:
    """Kernel and service identities derived from a stable workspace ID."""

    workspace_id: int

    def __post_init__(self) -> None:
        if not WORKSPACE_ID_MIN <= self.workspace_id <= WORKSPACE_ID_MAX:
            raise ValueError("Workspace runtime ID musí být v rozsahu 001–999.")

    @classmethod
    def for_instance(cls, name: str) -> "WorkspaceRuntime":
        # Lazy import avoids the historical instance -> runner -> components
        # dependency cycle during CLI/module startup.
        from .instance import Instance
        instance = Instance.load(name)
        # Workspace creation owns ID allocation. Runtime lookup stays
        # read-only; ID 001 is the migration identity for a legacy workspace.
        return cls(instance.workspace_id or 1)

    @classmethod
    def for_workspace(cls, lab: Path, name: str) -> "WorkspaceRuntime":
        """Resolve identity from workspace data, including in root services."""
        marker = lab / "workspace-id"
        try:
            value = int(marker.read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            return cls.for_instance(name)
        try:
            return cls(value)
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc

    @property
    def prefix(self) -> str:
        return f"ws-{self.workspace_id:03d}"

    @property
    def nft_prefix(self) -> str:
        return self.prefix.replace("-", "_")

    @property
    def namespace(self) -> str:
        return self.prefix

    @property
    def probe_namespace(self) -> str:
        return f"{self.prefix}-probe"

    @property
    def host_interface(self) -> str:
        return f"ws{self.workspace_id:03d}h"

    @property
    def probe_host_interface(self) -> str:
        return f"ws{self.workspace_id:03d}p0"

    @property
    def probe_peer_interface(self) -> str:
        return f"ws{self.workspace_id:03d}p1"

    @property
    def host_address(self) -> str:
        return str(self._address(1))

    @property
    def namespace_address(self) -> str:
        return str(self._address(2))

    @property
    def probe_gateway(self) -> str:
        return str(self._address(5))

    @property
    def probe_address(self) -> str:
        return str(self._address(6))

    @property
    def host_nft_table(self) -> str:
        return f"{self.nft_prefix}_host"

    @property
    def namespace_nft_table(self) -> str:
        return f"{self.nft_prefix}_route"

    @property
    def network_nft_table(self) -> str:
        return f"{self.nft_prefix}_net"

    @property
    def route_table(self) -> str:
        return str(45000 + self.workspace_id)

    @property
    def rule_preference(self) -> str:
        return str(15000 + self.workspace_id)

    @property
    def route_mark(self) -> str:
        return hex(0x5000 + self.workspace_id)

    @property
    def slice_name(self) -> str:
        return f"{self.prefix}.slice"

    def unit_name(self, component: str) -> str:
        return f"{self.prefix}-{component}.service"

    def _address(self, host: int) -> ipaddress.IPv4Address:
        # Each workspace owns two adjacent /30s from ADDRESS_POOL.
        offset = (self.workspace_id - 1) * ADDRESSES_PER_WORKSPACE + host
        return ipaddress.IPv4Address(int(ADDRESS_POOL.network_address) + offset)
