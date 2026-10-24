import json
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from saslik.tuntom import TunnelLeases
from saslik.tuntom_endpoint import SystemdTunnelEndpoint


class EndpointTests(unittest.TestCase):
    """Exercise endpoint ownership without touching systemd or networking."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.manager = Mock(instance="test", state=self.root)
        self.backend = SystemdTunnelEndpoint(self.manager, Path("/bin/true"), runtime=self.root)
        self.backend.run = Mock(return_value=Mock(stdout="[]"))
        self.lease = TunnelLeases(lambda _: None).acquire("peer")

    @patch("saslik.tuntom_endpoint.os.geteuid", return_value=0)
    def test_start_keeps_secret_out_of_command_and_waits_for_handshake(self, _):
        key = bytes(range(16))
        self.backend.start(self.lease, key)
        component = self.manager._start_component.call_args.args[0]
        self.assertNotIn(key.hex(), " ".join(component.command + component.environment))
        secret, = component.environment_files
        self.assertEqual(stat.S_IMODE(secret.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(secret.parent.stat().st_mode), 0o700)
        self.assertEqual(secret.read_text(), "TUNTOM_SECRET=" + key.hex() + "\n")
        self.assertEqual(self.lease.public()["state"], "preparing")
        self.backend.stop(self.lease)
        self.assertFalse(secret.exists())
        self.assertFalse(self.backend.endpoints)

    @patch("saslik.tuntom_endpoint.os.geteuid", return_value=0)
    def test_route_collision_prevents_start(self, _):
        self.backend.run.return_value.stdout = json.dumps([{"dst": "10.253.0.0/24"}])
        with self.assertRaisesRegex(ValueError, "overlaps"):
            self.backend.start(self.lease, bytes(16))
        self.manager._start_component.assert_not_called()
        self.assertFalse(self.backend.endpoints)

    @patch("saslik.tuntom_endpoint.os.geteuid", return_value=0)
    def test_failed_stop_keeps_endpoint_and_secret(self, _):
        self.backend.start(self.lease, bytes(16))
        directory = self.backend.endpoints[self.lease.slot]
        self.backend.run.side_effect = subprocess.CalledProcessError(1, ["systemctl"])
        with self.assertRaises(subprocess.CalledProcessError):
            self.backend.stop(self.lease)
        self.assertTrue((directory / "secret.env").is_file())
        self.assertIn(self.lease.slot, self.backend.endpoints)

    @patch("saslik.tuntom_endpoint.os.geteuid", return_value=1000)
    def test_unprivileged_start_rejected(self, _):
        with self.assertRaises(PermissionError):
            self.backend.start(self.lease, bytes(16))
        self.backend.run.assert_not_called()
