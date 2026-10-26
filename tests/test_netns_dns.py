import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from saslik import netns_dns
from saslik.runtime import WorkspaceRuntime


class NamespaceDnsTests(unittest.TestCase):
    def test_managed_resolver_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lab = root / "lab"
            netns = root / "etc/netns/ws-001"
            with patch.object(netns_dns, "_paths",
                              return_value=(netns, netns / "resolv.conf")):
                netns_dns.up(lab, "169.254.1.1", WorkspaceRuntime(1))
                self.assertIn("169.254.1.1", (netns / "resolv.conf").read_text())
                netns_dns.down(lab, WorkspaceRuntime(1))
                self.assertFalse((netns / "resolv.conf").exists())

    def test_existing_resolver_is_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lab = root / "lab"
            netns = root / "etc/netns/ws-001"
            netns.mkdir(parents=True)
            resolv = netns / "resolv.conf"
            resolv.write_text("nameserver 9.9.9.9\n")
            with patch.object(netns_dns, "_paths", return_value=(netns, resolv)):
                netns_dns.up(lab, "1.1.1.1", WorkspaceRuntime(1))
                netns_dns.down(lab, WorkspaceRuntime(1))
            self.assertEqual("nameserver 9.9.9.9\n", resolv.read_text())
