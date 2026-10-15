import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from saslik.routing import _root, apply_starting_template, routing_up


class RoutingTests(unittest.TestCase):
    def test_prepare_enables_transparent_workers_idempotently(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            state = lab / "state"
            state.mkdir()
            config = state / "smithproxy.cfg"
            config.write_text("""
accept_tproxy = false
plaintext_workers = 0
ssl_workers = 0
udp_workers = 0
dtls_workers = 0
ocsp_mode = 1
ocsp_stapling = true
ocsp_stapling_mode = 1
""", encoding="utf-8")
            self.assertTrue(apply_starting_template(lab))
            self.assertFalse(apply_starting_template(lab))
            text = config.read_text(encoding="utf-8")
            self.assertIn("accept_tproxy = true", text)
            self.assertEqual(4, text.count("workers = 1"))
            self.assertIn("ocsp_mode = 0", text)
            self.assertIn("ocsp_stapling = false", text)
            self.assertIn("ocsp_stapling_mode = 0", text)

    def test_prepare_waits_for_first_generated_config(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse(apply_starting_template(Path(directory)))

    def test_spider_sift_template_enables_payload_webhook(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            (lab / "state").mkdir()
            config = lab / "state/smithproxy.cfg"
            config.write_text("""
settings = { webhook = { enabled = false; sift = false; }; };
content_profiles = { default = { webhook_enable = false; }; };
""", encoding="utf-8")
            apply_starting_template(lab, "spider-sift")
            result = config.read_text(encoding="utf-8")
            self.assertRegex(result, r"enabled\s*=\s*true")
            self.assertRegex(result, r"sift\s*=\s*true")
            self.assertRegex(result, r"webhook_enable\s*=\s*true")

    @patch("saslik.routing.Path.exists", return_value=True)
    @patch("saslik.routing._host_ipv4_addresses", return_value=[])
    @patch("saslik.routing._nft")
    @patch("saslik.routing.routing_down")
    @patch("saslik.routing._run")
    def test_missing_numeric_route_table_is_normal_empty_state(
        self, run, _down, _nft, _addresses, _exists
    ):
        run.side_effect = lambda command, **kwargs: CompletedProcess(
            command, 2 if command[:4] == ["ip", "route", "show", "table"] else 0,
            stdout="", stderr="Error: ipv4: FIB table does not exist.",
        )
        routing_up(1000)
        probe = run.call_args_list[0]
        self.assertTrue(probe.kwargs["tolerate"])

    @patch("saslik.routing.routing_down")
    @patch("saslik.routing.routing_up", side_effect=RuntimeError("nft failed"))
    def test_failed_up_rolls_back_partial_routing(self, _up, down):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            (lab / "state").mkdir()
            (lab / "state/smithproxy.cfg").write_text("accept_tproxy = true")
            with self.assertRaisesRegex(RuntimeError, "nft failed"):
                _root("up", lab, 1000)
        down.assert_called_once_with()

if __name__ == "__main__":
    unittest.main()
