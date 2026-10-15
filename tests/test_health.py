import tempfile
import unittest
from pathlib import Path

from saslik.health import interface_counters


class HealthTests(unittest.TestCase):
    def test_interface_counters(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stats = root / "sxp-test0/statistics"
            stats.mkdir(parents=True)
            names = ("rx_bytes", "rx_packets", "rx_errors", "rx_dropped",
                     "tx_bytes", "tx_packets", "tx_errors", "tx_dropped")
            for index, name in enumerate(names, 1):
                (stats / name).write_text(str(index), encoding="ascii")
            result = interface_counters(sysfs=root)
            self.assertTrue(result["available"])
            self.assertEqual(1, result["rx_bytes"])
            self.assertEqual(8, result["tx_dropped"])

    def test_missing_interface_is_normal(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                {"available": False, "interface": "sxp-test0"},
                interface_counters(sysfs=Path(directory)),
            )


if __name__ == "__main__":
    unittest.main()
