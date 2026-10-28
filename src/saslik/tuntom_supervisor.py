"""Guardian-owned tunnel sessions; remote callers never choose root commands."""
import threading

from .components import SystemdComponents
from .tuntom import TunnelSessions
from .tuntom_endpoint import SystemdTunnelEndpoint
from . import licensing
from .network_plan import load_for_lab


class TunnelSupervisor:
    def __init__(self, factory=None):
        self.sessions = {}
        self.factory = factory or self._create
        self.slots: set[int] = set()
        self.slot_lock = threading.Lock()

    def _acquire_slot(self) -> int:
        with self.slot_lock:
            slot = next((value for value in range(1, 256)
                         if value not in self.slots), None)
            if slot is None:
                raise ValueError("No free tuntom endpoints")
            self.slots.add(slot)
            return slot

    def _release_slot(self, slot: int) -> None:
        with self.slot_lock:
            self.slots.discard(slot)

    def _new_session(self, target):
        session = self.factory(target)
        # Tuntom listens on a host UDP port derived from the slot. Sharing one
        # allocator across workspace sessions prevents otherwise invisible
        # host-port collisions while TUN interfaces stay namespace-local.
        session.leases.acquire_slot = self._acquire_slot
        session.leases.release_slot = self._release_slot
        return session

    @staticmethod
    def _create(target):
        manager = SystemdComponents(*target)
        plan = load_for_lab(target[0])
        return TunnelSessions(SystemdTunnelEndpoint(manager, manager.tuntom_binary),
                              pool=str(plan.tunnel_pool))

    def request(self, target, payload):
        peer = payload.get("peer")
        if not isinstance(peer, str) or not peer.startswith("client-") or len(peer) > 128:
            raise ValueError("Invalid tunnel peer")
        action = payload.get("action")
        session = self.sessions.get(target)
        if action == "tunnel-revoke":
            # Revocation is idempotent, including peers with no active tunnel.
            for item in self.sessions.values():
                item.leases.release(peer)
            return {"ok": True}
        if action not in {"tunnel-open", "tunnel-heartbeat", "tunnel-close"}:
            raise ValueError("Unknown tunnel operation")
        if action != "tunnel-close":
            licensing.require_tuntom()
        if session is None:
            if action != "tunnel-open":
                raise ValueError("Tunnel session expired")
            session = self._new_session(target)
            self.sessions[target] = session
        key = bytes.fromhex(payload.get("psk", "")) if action == "tunnel-open" else b""
        if action == "tunnel-open" and len(key) != 32:
            raise ValueError("Invalid tunnel credential")
        return session.request(peer, payload, key)

    def expire(self):
        if not licensing.TUNTOM_ENABLED:
            try:
                self.close()
            except Exception as exc:
                return [exc]
            return []
        errors = []
        for session in self.sessions.values():
            try:
                session.leases.expire()
            except Exception as exc:
                errors.append(exc)
        return errors

    def close(self, target=None):
        errors = []
        for key, session in list(self.sessions.items()):
            if target is not None and key != target:
                continue
            for peer in list(session.leases.leases):
                try:
                    session.leases.release(peer)
                except Exception as exc:
                    errors.append(exc)
            if not session.leases.leases:
                del self.sessions[key]
        if errors:
            raise RuntimeError("Tunnel teardown incomplete; endpoint IDs remain reserved") from errors[0]
