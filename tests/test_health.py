import tempfile
import unittest
from pathlib import Path

from unittest.mock import patch

from saslik.health import _json_check, interface_counters


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

    def test_json_check_returns_diagnostic_snapshot(self):
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b'{"service":"siftd","flows":{"active":2}}'

        with patch("urllib.request.urlopen", return_value=Response()):
            check, payload = _json_check("http://127.0.0.1/api/diagnostics")
        self.assertEqual("ok", check["state"])
        self.assertEqual("siftd", payload["service"])

    def test_json_check_rejects_non_object_payload(self):
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b'[]'

        with patch("urllib.request.urlopen", return_value=Response()):
            check, payload = _json_check("http://127.0.0.1/api/diagnostics")
        self.assertEqual("degraded", check["state"])
        self.assertEqual({}, payload)


if __name__ == "__main__":
    unittest.main()
