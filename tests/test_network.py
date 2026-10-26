import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from saslik import network
from saslik.runtime import WorkspaceRuntime


class NetworkLifecycleTests(unittest.TestCase):
    @patch("saslik.network._run")
    def test_last_workspace_restores_host_forwarding(self, _run):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lab = root / "workspace"
            (lab / "state").mkdir(parents=True)
            ip_forward = root / "ip_forward"
            saved = root / "ip_forward.before"
            ip_forward.write_text("1\n", encoding="ascii")
            saved.write_text("0\n", encoding="ascii")

            with (
                patch.object(network, "IP_FORWARD", ip_forward),
                patch.object(network, "IP_FORWARD_STATE", saved),
                patch("saslik.network.Path.glob", return_value=iter(())),
            ):
                network.down(lab, WorkspaceRuntime(1))

            self.assertEqual("0\n", ip_forward.read_text(encoding="ascii"))
            self.assertFalse(saved.exists())

    @patch("saslik.network._run")
    def test_running_workspace_keeps_host_forwarding_enabled(self, _run):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lab = root / "workspace"
            (lab / "state").mkdir(parents=True)
            ip_forward = root / "ip_forward"
            saved = root / "ip_forward.before"
            ip_forward.write_text("1\n", encoding="ascii")
            saved.write_text("0\n", encoding="ascii")

            remaining = iter((Path("/sys/class/net/ws002h"),))
            with (
                patch.object(network, "IP_FORWARD", ip_forward),
                patch.object(network, "IP_FORWARD_STATE", saved),
                patch("saslik.network.Path.glob", return_value=remaining),
            ):
                network.down(lab, WorkspaceRuntime(1))

            self.assertEqual("1\n", ip_forward.read_text(encoding="ascii"))
            self.assertTrue(saved.exists())


if __name__ == "__main__":
    unittest.main()
