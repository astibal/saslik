"""Guardian-owned tunnel sessions; remote callers never choose root commands."""
from .components import SystemdComponents
from .tuntom import TunnelSessions
from .tuntom_endpoint import SystemdTunnelEndpoint
from . import licensing


class TunnelSupervisor:
    def __init__(self, factory=None):
        self.sessions = {}
        self.factory = factory or self._create

    @staticmethod
    def _create(target):
        manager = SystemdComponents(*target)
        return TunnelSessions(SystemdTunnelEndpoint(manager, manager.tuntom_binary))

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
            # The current lab uses one shared network namespace. Never allocate
            # overlapping tunnel IDs for a second workspace during a transition.
            if any(item.leases.leases for item in self.sessions.values()):
                raise ValueError("Another workspace still owns tunnel endpoints")
            session = self.factory(target)
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
