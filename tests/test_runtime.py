import tempfile
import unittest
from pathlib import Path

from saslik.runtime import WorkspaceRuntime


class WorkspaceRuntimeTests(unittest.TestCase):
    def test_workspace_id_owns_all_kernel_identities(self):
        first = WorkspaceRuntime(1)
        second = WorkspaceRuntime(2)
        self.assertEqual("ws-001", first.namespace)
        self.assertEqual("ws-001-probe", first.probe_namespace)
        self.assertEqual("ws001h", first.host_interface)
        self.assertEqual("ws001p0", first.probe_host_interface)
        self.assertEqual("ws001p1", first.probe_peer_interface)
        self.assertEqual("10.240.0.1", first.host_address)
        self.assertEqual("10.240.0.2", first.namespace_address)
        self.assertEqual("10.240.0.5", first.probe_gateway)
        self.assertEqual("10.240.0.6", first.probe_address)
        self.assertNotEqual(first.host_nft_table, second.host_nft_table)
        self.assertNotEqual(first.route_table, second.route_table)
        self.assertNotEqual(first.route_mark, second.route_mark)
        self.assertEqual(20000, first.public_port("api"))
        self.assertEqual(20007, first.public_port("pcap-viewer"))
        self.assertEqual(20010, second.public_port("api"))
        self.assertTrue(set(first.public_ports.values()).isdisjoint(
            second.public_ports.values()))

    def test_highest_workspace_id_stays_in_allocated_address_block(self):
        runtime = WorkspaceRuntime(999)
        self.assertEqual("10.240.31.50", runtime.namespace_address)
        self.assertEqual("ws-999", runtime.namespace)

    def test_privileged_runtime_reads_workspace_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            (lab / "workspace-id").write_text("7\n", encoding="ascii")
            runtime = WorkspaceRuntime.for_workspace(lab, "name-not-used")
        self.assertEqual("ws-007", runtime.prefix)
        self.assertEqual("ws-007-smithproxy.service",
                         runtime.unit_name("smithproxy"))

    def test_invalid_workspace_marker_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            (lab / "workspace-id").write_text("1000\n", encoding="ascii")
            with self.assertRaisesRegex(RuntimeError, "001–999"):
                WorkspaceRuntime.for_workspace(lab, "unused")

    def test_invalid_runtime_id_is_rejected_at_construction(self):
        for value in (0, 1000):
            with self.subTest(value=value), self.assertRaisesRegex(
                    ValueError, "001–999"):
                WorkspaceRuntime(value)

    def test_unknown_public_service_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unknown public workspace service"):
            WorkspaceRuntime(1).public_port("unknown")


if __name__ == "__main__":
    unittest.main()
