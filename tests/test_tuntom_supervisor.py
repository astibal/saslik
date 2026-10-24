import unittest
from pathlib import Path
from unittest.mock import Mock

from saslik.tuntom import TunnelSessions
from saslik.tuntom_supervisor import TunnelSupervisor


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.now = [0]
        self.backends = []
        def factory(target):
            backend = Mock()
            self.backends.append(backend)
            return TunnelSessions(backend, clock=lambda: self.now[0])
        self.supervisor = TunnelSupervisor(factory)
        self.target = (Path("/tmp/test-lab"), "test", "127.0.0.1")

    def open(self, peer="client-test"):
        return self.supervisor.request(self.target, {
            "action": "tunnel-open", "peer": peer, "psk": bytes(32).hex()})

    def test_expiration_without_client_requests(self):
        self.open()
        self.now[0] = 61
        self.assertEqual([], self.supervisor.expire())
        self.backends[0].stop.assert_called_once()

    def test_revoke_is_idempotent(self):
        self.open()
        for _ in range(2):
            self.assertEqual({"ok": True}, self.supervisor.request(self.target, {
                "action": "tunnel-revoke", "peer": "client-test"}))
        self.backends[0].stop.assert_called_once()

    def test_close_attempts_all_peers_and_retains_failed_reservation(self):
        self.open("client-one")
        self.open("client-two")
        def stop(lease):
            if lease.peer == "client-one":
                raise RuntimeError("systemd unavailable")
        self.backends[0].stop.side_effect = stop
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            self.supervisor.close()
        remaining = self.supervisor.sessions[self.target].leases.leases
        self.assertEqual(["client-one"], list(remaining))
        self.backends[0].stop.side_effect = None
        self.supervisor.close()
        self.assertFalse(self.supervisor.sessions)

    def test_expiration_failure_does_not_starve_other_peers(self):
        self.open("client-one")
        self.open("client-two")
        self.backends[0].stop.side_effect = [RuntimeError("busy"), None]
        self.now[0] = 61
        self.assertEqual(1, len(self.supervisor.expire()))
        self.assertEqual(2, self.backends[0].stop.call_count)

    def test_invalid_requests_do_not_start_endpoint(self):
        for payload in (
            {"action": "tunnel-open", "peer": "not-a-peer"},
            {"action": "tunnel-open", "peer": "client-test", "psk": "bad"},
            {"action": "tunnel-heartbeat", "peer": "client-test"},
        ):
            with self.assertRaises(ValueError):
                self.supervisor.request(self.target, payload)
        for backend in self.backends:
            backend.start.assert_not_called()
