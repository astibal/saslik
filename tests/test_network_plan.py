import ipaddress
import tempfile
import unittest
from pathlib import Path

from saslik.network_plan import NetworkPlan, load, load_for_lab, save
from saslik.runtime import WorkspaceRuntime


class NetworkPlanTests(unittest.TestCase):
    def test_defaults_preserve_existing_addressing(self):
        plan = NetworkPlan()
        runtime = WorkspaceRuntime(1, plan.workspace_pool)
        self.assertEqual(runtime.host_address, "10.240.0.1")
        self.assertEqual(runtime.namespace_address, "10.240.0.2")
        self.assertEqual(str(plan.tunnel_pool), "10.253.0.0/22")
        self.assertEqual(str(plan.service_address), "10.252.255.1")

    def test_round_trip_and_workspace_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lab = root / "instances/lab1"
            lab.mkdir(parents=True)
            plan = NetworkPlan.parse("172.24.0.0/19", "172.25.0.0/22", "172.26.0.1")
            save(root, plan)
            self.assertEqual(load(root), plan)
            self.assertEqual(load_for_lab(lab), plan)

    def test_rejects_overlapping_plan(self):
        with self.assertRaisesRegex(ValueError, "koliduje"):
            NetworkPlan.parse("10.240.0.0/19", "10.240.0.0/22", "10.252.255.1")

    def test_rejects_connected_customer_network(self):
        plan = NetworkPlan.parse("10.240.0.0/19", "10.253.0.0/22", "10.252.255.1")
        with self.assertRaisesRegex(ValueError, "připojenou sítí"):
            plan.validate([ipaddress.IPv4Network("10.240.4.0/24")])

    def test_requires_capacity_for_all_workspace_ids(self):
        with self.assertRaisesRegex(ValueError, "999"):
            NetworkPlan.parse("172.24.0.0/20", "172.25.0.0/22", "172.26.0.1")


if __name__ == "__main__":
    unittest.main()
