"""Pairwise tuntom session planning; never enables routing by itself.

The supervisor owns interfaces/processes. Pairing credentials are persistent,
whereas these leases and their random key contexts live for one server run.

Saslik owns the commercial integration entitlement. Cleanup never requires a license.
Transport baseline: tuntom origin/main bfc946d, ordinary pairwise endpoints;
no auto-extension, external AUTH helpers or relocated workers are required.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable
from . import licensing

DOMAIN = b"saslik-skewer/tuntom/psk/v1"


def tunnel_key(psk: bytes, context: str) -> bytes:
    """RFC 5869 HKDF-SHA256, 128-bit output for TUNTOM_SECRET.

    Context is a fresh, public 32-byte nonce encoded as lowercase hex. Send it
    only over authenticated control transport. Never transmit the derived key.
    """
    if len(psk) != 32 or len(context) != 64 or any(c not in "0123456789abcdef" for c in context):
        raise ValueError("Invalid tuntom key context")
    prk = hmac.digest(bytes.fromhex(context), psk, hashlib.sha256)
    return hmac.digest(prk, DOMAIN + b"\x01", hashlib.sha256)[:16]


@dataclass
class TunnelLease:
    peer: str
    slot: int
    context: str
    deadline: float
    pool: str
    ready: bool = False

    def public(self) -> dict:
        network = ipaddress.IPv4Network(self.pool)
        base = int(network.network_address) + self.slot * 4
        return {
            "version": 1, "transport": "tuntom", "id": self.slot,
            "context": self.context, "port": 40000 + self.slot,
            "server_interface": f"skt{self.slot}s",
            "client_interface": f"skt{self.slot}c",
            "server_address": f"{ipaddress.IPv4Address(base + 1)}/30",
            "client_address": f"{ipaddress.IPv4Address(base + 2)}/30",
            "state": "ready" if self.ready else "preparing",
        }


class TunnelLeases:
    """Allocate one ordinary tunnel per authenticated peer (IDs 1..255).

    Callers must authenticate peers and validate advertised addresses against
    both hosts' routes before starting an endpoint. A lease is not proof of a
    working tunnel. Teardown must complete before an ID may be reused.
    """

    def __init__(self, stop: Callable[[TunnelLease], None], *, pool="10.253.0.0/22",
                 ttl=60, clock=time.monotonic, acquire_slot=None, release_slot=None):
        network = ipaddress.IPv4Network(pool)
        if not network.subnet_of(ipaddress.IPv4Network("10.0.0.0/8")) or network.prefixlen > 22:
            raise ValueError("Tunnel pool must contain 256 /30s inside 10/8")
        if not 10 <= ttl <= 3600:
            raise ValueError("Invalid tunnel lease timeout")
        self.pool, self.ttl, self.clock, self.stop = str(network), ttl, clock, stop
        self.leases: dict[str, TunnelLease] = {}
        self.lock = threading.RLock()
        self.acquire_slot = acquire_slot
        self.release_slot = release_slot

    def acquire(self, peer: str) -> TunnelLease:
        if not peer or len(peer) > 128:
            raise ValueError("Invalid peer identity")
        with self.lock:
            self.expire()
            if peer in self.leases:
                lease = self.leases[peer]
                lease.deadline = self.clock() + self.ttl
                return lease
            occupied = {lease.slot for lease in self.leases.values()}
            slot = (self.acquire_slot() if self.acquire_slot else
                    next((i for i in range(1, 256) if i not in occupied), None))
            if slot is None:
                raise ValueError("No free tuntom endpoints")
            lease = TunnelLease(peer, slot, secrets.token_hex(32), self.clock() + self.ttl, self.pool)
            self.leases[peer] = lease
            return lease

    def release(self, peer: str) -> None:
        with self.lock:
            lease = self.leases.get(peer)
            if lease is not None:
                lease.ready = False
                self.stop(lease)  # Failure keeps the reservation; never reuse a live endpoint.
                del self.leases[peer]
                if self.release_slot:
                    self.release_slot(lease.slot)

    def expire(self) -> None:
        with self.lock:
            errors = []
            for peer, lease in list(self.leases.items()):
                if lease.deadline <= self.clock():
                    try:
                        self.release(peer)
                    except Exception as exc:
                        errors.append(exc)
            if errors:
                raise RuntimeError("Tunnel expiration cleanup incomplete") from errors[0]


class TunnelSessions:
    """Authenticated control operations, independent of the transport process.

    The owner must call expire periodically even when no clients are polling,
    and release every lease before stopping the lab namespace.
    """

    def __init__(self, backend, **options):
        self.backend = backend
        self.leases = TunnelLeases(backend.stop, **options)

    def request(self, peer: str, request: dict, psk: bytes) -> dict:
        action = request.get("action")
        if action in {"tunnel-open", "tunnel-heartbeat"}:
            licensing.require_tuntom()
        with self.leases.lock:
            self.leases.expire()
            if action == "tunnel-open":
                existing = peer in self.leases.leases
                lease = self.leases.acquire(peer)
                if not existing:
                    try:
                        self.backend.start(lease, tunnel_key(psk, lease.context))
                    except BaseException:
                        self.leases.release(peer)
                        raise
                # Endpoint preparation is not proof of a successful handshake.
                return {"ok": True, "tunnel": lease.public(), "lease_seconds": self.leases.ttl}
            lease = self.leases.leases.get(peer)
            if lease is None or not secrets.compare_digest(str(request.get("context", "")), lease.context):
                raise ValueError("Tunnel session expired or replaced")
            if action == "tunnel-heartbeat":
                lease.deadline = self.leases.clock() + self.leases.ttl
                return {"ok": True, "tunnel": lease.public(), "lease_seconds": self.leases.ttl}
            if action == "tunnel-close":
                self.leases.release(peer)
                return {"ok": True}
            raise ValueError("Unknown tunnel operation")
