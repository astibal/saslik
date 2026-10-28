import tempfile
import unittest
from pathlib import Path

from unittest.mock import call, patch

from saslik.health import _json_check, collect, interface_counters


class HealthTests(unittest.TestCase):
    def test_interface_counters(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stats = root / "ws001h/statistics"
            stats.mkdir(parents=True)
            names = ("rx_bytes", "rx_packets", "rx_errors", "rx_dropped",
                     "tx_bytes", "tx_packets", "tx_errors", "tx_dropped")
            for index, name in enumerate(names, 1):
                (stats / name).write_text(str(index), encoding="ascii")
            result = interface_counters("ws001h", sysfs=root)
            self.assertTrue(result["available"])
            self.assertEqual(1, result["rx_bytes"])
            self.assertEqual(8, result["tx_dropped"])

    def test_missing_interface_is_normal(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                {"available": False, "interface": "ws001h"},
                interface_counters("ws001h", sysfs=Path(directory)),
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

    @patch("saslik.health._json_check", return_value=({"state": "ok"}, {}))
    @patch("saslik.health._http_check", return_value={"state": "ok"})
    @patch("saslik.health._tcp_check", return_value={"state": "ok"})
    def test_cli_health_uses_workspace_address(self, tcp_check, _http, _json):
        with tempfile.TemporaryDirectory() as directory:
            collect(Path(directory), namespace_address="10.240.0.42")

        self.assertIn(
            call("10.240.0.42", 55000),
            tcp_check.call_args_list,
        )

    @patch("saslik.health._json_check", return_value=({"state": "ok"}, {}))
    @patch("saslik.health._http_check", return_value={"state": "ok"})
    @patch("saslik.health._tcp_check", return_value={"state": "ok"})
    def test_smithproxy_gui_health_is_reported_only_when_installed(
            self, _tcp, http_check, _json):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            executable = lab / "build/smithproxy-gui/smithproxy-gui"
            executable.parent.mkdir(parents=True)
            executable.touch(mode=0o755)
            value = collect(lab, namespace_address="10.240.0.42")
        self.assertIn("smithproxy_gui", value["checks"])
        self.assertIn(call("http://10.240.0.42:18082/healthz"),
                      http_check.call_args_list)


if __name__ == "__main__":
    unittest.main()
