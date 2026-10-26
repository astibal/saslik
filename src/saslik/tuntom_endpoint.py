"""Privileged, systemd-owned pairwise tunnel endpoints.

Only a local supervisor may call this module. Remote requests must first pass
pairing authorization and obtain a server-allocated TunnelLease.
"""
from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import tempfile
import time
import sys
from pathlib import Path

from .components import Component, SystemdComponents
from .tuntom import TunnelLease
from . import licensing


class SystemdTunnelEndpoint:
    def __init__(self, manager: SystemdComponents, binary: Path, *, runtime=Path("/run"),
                 netns_root=Path("/run/netns")):
        self.manager, self.binary, self.runtime = manager, binary, runtime
        self.netns_root = netns_root
        self.endpoints: dict[int, Path] = {}

    @staticmethod
    def run(command):
        return subprocess.run(command, check=True, capture_output=True, text=True, timeout=10)

    def _membership(self, lease, action):
        interface = lease.public()["server_interface"]
        self.run(["ip", "netns", "exec", self.manager.runtime.namespace, "nft", action,
                  "element", "inet", self.manager.runtime.namespace_nft_table,
                  "tunnel_interfaces", "{", interface, "}"])

    def _check_routes(self, lease):
        subnet = ipaddress.ip_interface(lease.public()["server_address"]).network
        for prefix in (["ip"], ["ip", "-n", self.manager.runtime.namespace]):
            rows = json.loads(self.run([*prefix, "-j", "-4", "route", "show", "table", "all"]).stdout)
            for row in rows:
                destination = row.get("dst", "default")
                if destination == "default":
                    continue
                if subnet.overlaps(ipaddress.IPv4Network(destination, strict=False)):
                    raise ValueError("Tunnel subnet overlaps an existing route")

    def start(self, lease: TunnelLease, key: bytes) -> None:
        print("[tuntom] Endpoint: checking entitlement and executable", file=sys.stderr, flush=True)
        licensing.require_tuntom()
        if os.geteuid() != 0:
            raise PermissionError("Tunnel endpoints require the privileged supervisor")
        if not (self.netns_root / self.manager.runtime.namespace).exists():
            raise RuntimeError("Workspace network namespace is not running")
        if not 1 <= lease.slot <= 255 or len(key) != 16:
            raise ValueError("Invalid endpoint")
        if lease.slot in self.endpoints:
            raise ValueError("Endpoint already reserved")
        if not self.binary.is_file() or not os.access(self.binary, os.X_OK):
            raise ValueError("Tuntom executable is unavailable; update the Tuntom workspace component")
        self.manager.prepare_tuntom()
        print("[tuntom] Endpoint: checking subnet conflicts", file=sys.stderr, flush=True)
        self._check_routes(lease)
        directory = Path(tempfile.mkdtemp(prefix="saslik-tuntom-", dir=self.runtime))
        self.endpoints[lease.slot] = directory
        secret = directory / "secret.env"
        fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write("TUNTOM_SECRET=" + key.hex() + "\n")
        endpoint = lease.public()
        component = Component(
            name=f"tuntom-{lease.slot}",
            command=(str(self.binary), "server", str(lease.slot), endpoint["server_interface"],
                     "--tun-netns", self.manager.runtime.namespace, "--tun-up"),
            log=self.manager.state / f"tuntom-{lease.slot}.log",
            environment_files=(secret,),
        )
        try:
            print(f"[tuntom] Endpoint {lease.slot}: starting systemd unit", file=sys.stderr, flush=True)
            # Keep the UDP socket on the host; only the TUN lives in the lab.
            # The secret is not placed in argv or systemd-run's --setenv flags.
            self.manager._start_component(component)
            deadline = time.monotonic() + 5
            while True:
                try:
                    self.run(["ip", "-n", self.manager.runtime.namespace, "link", "show",
                              "dev", endpoint["server_interface"]])
                    break
                except subprocess.CalledProcessError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("tuntom did not create its TUN interface") from None
                    time.sleep(0.05)
            self.run(["ip", "-n", self.manager.runtime.namespace, "address", "add", endpoint["server_address"],
                      "dev", endpoint["server_interface"]])
            self._membership(lease, "add")
            print(f"[tuntom] Endpoint {lease.slot}: ready", file=sys.stderr, flush=True)
        except BaseException:
            self.stop(lease)
            raise

    def stop(self, lease: TunnelLease) -> None:
        directory = self.endpoints.get(lease.slot)
        if directory is None:
            return
        # Stop the process first. Closing the nonpersistent TUN removes the
        # interface and its connected route. A collected transient unit means
        # the process is already gone, which is the desired final state. Other
        # systemd failures keep the reservation so they remain recoverable.
        try:
            self.run([
                "systemctl", "stop",
                self.manager.runtime.unit_name(f"tuntom-{lease.slot}"),
            ])
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 5:
                raise
        try:
            self._membership(lease, "delete")
        except subprocess.CalledProcessError:
            pass  # Lab teardown may already have removed the nftables table.
        (directory / "secret.env").unlink(missing_ok=True)
        directory.rmdir()
        del self.endpoints[lease.slot]
