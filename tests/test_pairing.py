import concurrent.futures
import json
import os
import stat
import ssl
import socket
import subprocess
import tempfile
import threading
import unittest
import uuid
from unittest.mock import Mock, patch
from pathlib import Path

from saslik.pairing import PairingStore, PskServer
from saslik.server import skewer_ca
from saslik.tuntom import TunnelSessions


class PairingTests(unittest.TestCase):
    def test_public_ca_tracks_workspace_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            certs = root / "certs/default"
            certs.mkdir(parents=True)
            with patch("saslik.server.identity_root", return_value=root), patch("saslik.server.active_name", return_value="lab"):
                self.assertIn("ca_error", skewer_ca(root, "lab"))
                (certs / "ca-key.pem").write_text("PRIVATE KEY MUST NOT BE EXPORTED")
                (certs / "ca-cert.pem").write_text("public certificate one")
                self.assertEqual({"ca_pem": "public certificate one"}, skewer_ca(root, "lab"))
                (certs / "ca-cert.pem").write_text("public certificate two")
                self.assertEqual({"ca_pem": "public certificate two"}, skewer_ca(root, "lab"))
                (certs / "ca-cert.pem").write_text("x" * 32769)
                self.assertIn("ca_error", skewer_ca(root, "lab"))

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "clients.json"
        self.store = PairingStore(self.path)

    def enroll(self, **changes):
        request = {"action": "enroll", "instance": str(uuid.uuid4()), "request": str(uuid.uuid4()), **changes}
        return self.store.request(self.store.invitation, request, lambda: {}), request

    def test_lifecycle(self):
        invitation = self.store.invitation
        secret = self.store.secret
        client, request = self.enroll()
        self.assertEqual(client, self.store.request(invitation, request, lambda: {}))
        with self.assertRaises(ValueError):
            self.store.request(client["identity"], {"action": "status"}, lambda: {})
        self.store.request(client["identity"], {"action": "commit"}, lambda: {})
        self.assertNotEqual(secret, self.store.secret)
        self.assertEqual(b"", self.store.key(invitation))
        self.assertEqual({"ok": True}, self.store.request(client["identity"], {"action": "status"}, lambda: {"ok": True}))
        with self.assertRaises(ValueError):
            self.enroll(instance=request["instance"])
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_psk_runtime_tracks_source_and_tunnel_lease(self):
        server = PskServer.__new__(PskServer)
        server.client_activity = {}
        server.client_activity_lock = threading.Lock()
        identity = "client-" + "2" * 32

        server.observe_client(identity, "192.0.2.15", "tunnel-open",
                              {"ok": True, "lease_seconds": 60})
        self.assertEqual({"source_ip": "192.0.2.15", "tunnel_active": True},
                         server.client_runtime(identity))
        server.observe_client(identity, "192.0.2.15", "tunnel-close", {"ok": True})
        self.assertFalse(server.client_runtime(identity)["tunnel_active"])

    def test_tunnel_requires_active_authorized_pairing(self):
        client, _ = self.enroll()
        identity = client["identity"]
        callback = Mock(return_value={"ok": True})
        request = {"action": "tunnel-open"}
        with self.assertRaises(ValueError):
            self.store.request(identity, request, lambda: {}, tunnel=callback)
        callback.assert_not_called()
        self.store.request(identity, {"action": "commit"}, lambda: {})
        self.assertEqual({"ok": True}, self.store.request(identity, request, lambda: {}, tunnel=callback))
        callback.assert_called_once_with(identity, request, self.store.key(identity))
        callback.reset_mock()
        self.store.clients[identity]["permissions"] = ["status"]
        with self.assertRaises(ValueError):
            self.store.request(identity, request, lambda: {}, tunnel=callback)
        self.store.revoke(identity)
        with self.assertRaises(ValueError):
            self.store.request(identity, request, lambda: {}, tunnel=callback)
        callback.assert_not_called()

    def test_restart_recovers_pending_commit(self):
        client, _ = self.enroll()
        restarted = PairingStore(self.path)
        self.assertNotEqual(restarted.invitation, self.store.invitation)
        self.assertEqual({"paired": True}, restarted.request(client["identity"], {"action": "commit"}, lambda: {}))
        restarted.revoke(client["identity"])
        self.assertEqual(b"", restarted.key(client["identity"]))

    def test_legacy_active_pairing_gains_tunnel_permission(self):
        identity = "client-" + "1" * 32
        legacy = {
            identity: {
                "instance": str(uuid.uuid4()),
                "key": bytes(32).hex(),
                "state": "active",
                "permissions": ["status"],
            }
        }
        self.path.write_text(json.dumps(legacy))

        migrated = PairingStore(self.path)

        self.assertEqual(["status", "tunnel"], migrated.clients[identity]["permissions"])
        stored = json.loads(self.path.read_text())
        self.assertEqual(["status", "tunnel"], stored[identity]["permissions"])

    def test_only_one_reservation(self):
        def attempt(_):
            try:
                self.enroll()
                return True
            except ValueError:
                return False
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            self.assertEqual(sum(pool.map(attempt, range(8))), 1)

    def test_rotation_does_not_revoke_clients(self):
        client, _ = self.enroll()
        self.store.request(client["identity"], {"action": "commit"}, lambda: {})
        key = self.store.key(client["identity"])
        self.store.rotate()
        self.assertEqual(key, self.store.key(client["identity"]))

    def test_manual_rotation_cancels_pending_enrollment(self):
        client, _ = self.enroll()
        self.store.rotate()
        self.assertEqual(b"", self.store.key(client["identity"]))

    @unittest.skipUnless(os.environ.get("SKEWER_TUNTOM_TEST_BINARY"), "Native tunnel client not supplied")
    def test_native_tunnel_control(self):
        backend = Mock()
        sessions = TunnelSessions(backend)
        server = PskServer(("127.0.0.1", 0), self.store, lambda: {}, tunnel=sessions.request)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        endpoint = f"skewer://127.0.0.1:{server.server_address[1]}/pair"
        env = dict(os.environ, XDG_DATA_HOME=self.directory.name + "/client-data",
                   XDG_CONFIG_HOME=self.directory.name + "/client-config")
        result = subprocess.run([os.environ["SKEWER_TUNTOM_TEST_BINARY"], endpoint],
            input=self.store.link("127.0.0.1", server.server_address[1]) + "\n",
            env=env, text=True, capture_output=True, timeout=30)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(2, backend.start.call_count)
        self.assertEqual(2, backend.stop.call_count)
        self.assertFalse(sessions.leases.leases)

    @unittest.skipUnless(os.environ.get("SKEWER_TEST_BINARY"), "Native Skewer binary not supplied")
    def test_native_tls_pairing(self):
        public_ca = "-----BEGIN CERTIFICATE-----\ntransport fixture\n-----END CERTIFICATE-----\n"
        reports = []
        def receive_report(identity, payload):
            reports.append((identity, payload))
            return {"ok": True}
        server = PskServer(("127.0.0.1", 0), self.store, lambda: {"version": 1, "available": True, "ca_pem": public_ca}, receive_report)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        endpoint = f"skewer://127.0.0.1:{server.server_address[1]}/pair"
        env = dict(os.environ, XDG_DATA_HOME=self.directory.name + "/client-data", XDG_CONFIG_HOME=self.directory.name + "/client-config")
        binary = os.environ["SKEWER_TEST_BINARY"]
        link = self.store.link("127.0.0.1", server.server_address[1])
        invalid = subprocess.run([binary, "pair", "-"], input=link.replace("psk=", "psk=WRONG")+'\n', env=env, text=True, capture_output=True, timeout=10)
        self.assertNotEqual(0, invalid.returncode)
        paired = subprocess.run([binary, "pair", "-"], input=link+'\n', env=env, text=True, capture_output=True, timeout=10)
        self.assertEqual(0, paired.returncode, paired.stderr)
        self.assertNotIn(link.split('psk=')[1], paired.stdout + paired.stderr)
        status = subprocess.run([binary, "remote-status", endpoint], env=env, text=True, capture_output=True, timeout=10)
        self.assertEqual(0, status.returncode, status.stderr)
        self.assertTrue(json.loads(status.stdout)["available"])
        self.assertEqual(public_ca, json.loads(status.stdout)["ca_pem"])
        identity = next(iter(self.store.clients))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # PSK authenticates the peer, not PKI.
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.set_psk_client_callback(lambda hint: (identity, self.store.key(identity)))
        report = {"version": 1, "hostname": "razor-test", "ca": {"stores": []}}
        with socket.create_connection(server.server_address, timeout=5) as tcp:
            with context.wrap_socket(tcp, server_hostname="localhost") as connection:
                connection.sendall(json.dumps({"action": "report", "report": report}).encode() + b"\n")
                self.assertEqual({"ok": True}, json.loads(connection.recv(4096)))
        self.assertEqual([(identity, report)], reports)
        self.store.revoke(next(iter(self.store.clients)))
        revoked = subprocess.run([binary, "remote-status", endpoint], env=env, text=True, capture_output=True, timeout=10)
        self.assertNotEqual(0, revoked.returncode)


if __name__ == "__main__":
    unittest.main()
