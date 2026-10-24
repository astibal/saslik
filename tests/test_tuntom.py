import unittest
from unittest.mock import Mock

from saslik.tuntom import TunnelLeases, TunnelSessions, tunnel_key


class TuntomTests(unittest.TestCase):
    def test_control_session_lifecycle(self):
        now = [0]
        backend = Mock()
        sessions = TunnelSessions(backend, clock=lambda: now[0])
        psk = bytes(range(32))
        opened = sessions.request("peer", {"action": "tunnel-open"}, psk)
        context = opened["tunnel"]["context"]
        self.assertEqual(opened["tunnel"]["state"], "preparing")
        sessions.request("peer", {"action": "tunnel-open"}, psk)
        backend.start.assert_called_once()
        self.assertEqual(backend.start.call_args.args[1], tunnel_key(psk, context))
        now[0] = 50
        sessions.request("peer", {"action": "tunnel-heartbeat", "context": context}, psk)
        now[0] = 65
        sessions.leases.expire()
        backend.stop.assert_not_called()
        with self.assertRaises(ValueError):
            sessions.request("peer", {"action": "tunnel-close", "context": "old"}, psk)
        self.assertIn("peer", sessions.leases.leases)
        sessions.request("peer", {"action": "tunnel-close", "context": context}, psk)
        backend.stop.assert_called_once()
        self.assertNotIn("peer", sessions.leases.leases)

    def test_failed_start_releases_reservation_after_cleanup(self):
        backend = Mock()
        backend.start.side_effect = RuntimeError("start failed")
        sessions = TunnelSessions(backend)
        with self.assertRaisesRegex(RuntimeError, "start failed"):
            sessions.request("peer", {"action": "tunnel-open"}, bytes(32))
        backend.stop.assert_called_once()
        self.assertFalse(sessions.leases.leases)

    def test_expired_context_cannot_renew_replacement(self):
        now = [0]
        sessions = TunnelSessions(Mock(), clock=lambda: now[0])
        old = sessions.request("peer", {"action": "tunnel-open"}, bytes(32))
        now[0] = 61
        new = sessions.request("peer", {"action": "tunnel-open"}, bytes(32))
        self.assertNotEqual(old["tunnel"]["context"], new["tunnel"]["context"])
        with self.assertRaises(ValueError):
            sessions.request("peer", {"action": "tunnel-heartbeat", "context": old["tunnel"]["context"]}, bytes(32))

    def test_derivation(self):
        key = tunnel_key(bytes(range(32)), "00" * 32)
        self.assertEqual(len(key), 16)
        self.assertEqual(key.hex(), "af07b757429bdce394a510a8635cf9da")
        self.assertEqual(key, tunnel_key(bytes(range(32)), "00" * 32))
        self.assertNotEqual(key, tunnel_key(bytes(range(32)), "01" * 32))
        with self.assertRaises(ValueError):
            tunnel_key(b"short", "00" * 32)

    def test_lifecycle(self):
        now = [0]
        stopped = []
        leases = TunnelLeases(lambda lease: stopped.append(lease.slot), clock=lambda: now[0])
        first = leases.acquire("peer-a")
        self.assertEqual(leases.acquire("peer-a"), first)
        other = leases.acquire("peer-b")
        self.assertNotEqual(first.slot, other.slot)
        self.assertEqual(first.public()["state"], "preparing")
        self.assertNotIn("key", first.public())
        now[0] = 61
        leases.expire()
        self.assertEqual(stopped, [1, 2])
        replacement = leases.acquire("peer-a")
        self.assertEqual(replacement.slot, first.slot)
        self.assertNotEqual(replacement.context, first.context)

    def test_failed_teardown_keeps_id_reserved(self):
        def fail(_):
            raise RuntimeError("supervisor unavailable")
        leases = TunnelLeases(fail)
        first = leases.acquire("peer-a")
        with self.assertRaises(RuntimeError):
            leases.release("peer-a")
        self.assertIs(leases.leases["peer-a"], first)

    def test_capacity_and_addressing(self):
        leases = TunnelLeases(lambda _: None)
        endpoints = [leases.acquire(str(i)).public() for i in range(255)]
        self.assertEqual(len({e["server_address"] for e in endpoints}), 255)
        self.assertEqual(endpoints[-1]["port"], 40255)
        with self.assertRaises(ValueError):
            leases.acquire("overflow")
        with self.assertRaises(ValueError):
            TunnelLeases(lambda _: None, pool="10.253.0.0/24")
