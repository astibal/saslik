import unittest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from saslik.server import (CliSession, Handler, SpiderBootstrapStore,
                           normalize_skewer_report,
                           fetch_skewer_deb, skewer_discovery,
                           web_log_tail)


class DummySocket:
    pass


class WebLogTests(unittest.TestCase):
    def test_named_component_log_is_returned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lab = root / "instances/lab1"
            (lab / "state").mkdir(parents=True)
            (lab / "state/smithproxy.log").write_text("proxy output\n", encoding="utf-8")

            value = web_log_tail(root, lab, "smithproxy")

            self.assertEqual("proxy output\n", value["data"])
            self.assertFalse(value["truncated"])

    def test_unknown_log_source_cannot_be_used_as_a_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                web_log_tail(root, root / "lab", "../../secret")

    def test_tuntom_source_combines_dynamic_slot_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lab = root / "instances/lab1"
            (lab / "state").mkdir(parents=True)
            (lab / "state/tuntom-1.log").write_text("first\n", encoding="utf-8")
            (lab / "state/tuntom-3.log").write_text("third\n", encoding="utf-8")

            value = web_log_tail(root, lab, "tuntom")

            self.assertIn("=== tuntom-1.log ===\nfirst", value["data"])
            self.assertIn("=== tuntom-3.log ===\nthird", value["data"])


class BrokenWriter:
    def write(self, _data):
        raise BrokenPipeError


class CliSessionTests(unittest.TestCase):
    def test_telnet_negotiation_is_removed_without_reply(self):
        session = CliSession(DummySocket())
        clean = session.decode(b"hello\xff\xfb\x01 world\xff\xfd\x03")
        self.assertEqual(b"hello world", clean)

    def test_split_telnet_sequence_does_not_leak_into_text(self):
        session = CliSession(DummySocket())
        first = session.decode(b"banner\xff")
        second = session.decode(b"\xfb\x03prompt")
        self.assertEqual(b"banner", first)
        self.assertEqual(b"prompt", second)


class SpiderBootstrapTests(unittest.TestCase):
    def test_grant_is_origin_bound_and_single_use(self):
        store = SpiderBootstrapStore(lifetime=60)
        code = store.issue("http://127.0.0.1:18080", "secret",
                           "http://127.0.0.1:15173", now=10)
        self.assertIsNone(store.redeem(code, "http://evil.example", now=11))
        grant = store.redeem(code, "http://127.0.0.1:15173", now=11)
        self.assertIsNotNone(grant)
        self.assertEqual("secret", grant.token)
        self.assertIsNone(store.redeem(code, "http://127.0.0.1:15173", now=12))

    def test_expired_grant_cannot_be_redeemed(self):
        store = SpiderBootstrapStore(lifetime=5)
        code = store.issue("backend", "secret", "http://spider", now=10)
        self.assertIsNone(store.redeem(code, "http://spider", now=15))


class ResponseTests(unittest.TestCase):
    def test_portal_uses_persistent_http_connections(self):
        self.assertEqual("HTTP/1.1", Handler.protocol_version)

    def test_json_ignores_browser_disconnect_during_write(self):
        handler = object.__new__(Handler)
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler.wfile = BrokenWriter()

        handler._json({"data": "", "closed": False})


class SkewerDiscoveryTests(unittest.TestCase):
    def test_interface_ifindex_is_a_reconnect_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            interface = root / "ws001h"
            interface.mkdir()
            (interface / "ifindex").write_text("846\n", encoding="ascii")

            value = skewer_discovery("lab1", root)

            self.assertTrue(value["available"])
            self.assertEqual("10.240.0.2", value["gateway"])
            self.assertEqual("ws001h", value["host_interface"])
            self.assertEqual("846", value["generation"])

    def test_missing_interface_reports_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            value = skewer_discovery("lab1", Path(directory))
        self.assertFalse(value["available"])
        self.assertEqual("", value["generation"])

    @patch("saslik.server.urlopen")
    def test_package_proxy_accepts_the_fixed_github_release_asset(self, urlopen):
        response = MagicMock()
        response.geturl.return_value = (
            "https://release-assets.githubusercontent.com/github-production-release-asset/file.deb")
        response.headers = {"Content-Length": "7"}
        response.read.side_effect = [b"package", b""]
        urlopen.return_value = response

        package, size = fetch_skewer_deb()
        try:
            self.assertEqual(7, size)
            self.assertEqual(b"package", package.read())
        finally:
            package.close()

        requested = urlopen.call_args.args[0]
        self.assertEqual(
            "https://github.com/astibal/saslik-skewer/releases/latest/download/"
            "skewer-linux-amd64.deb", requested)

    @patch("saslik.server.urlopen")
    def test_package_proxy_rejects_redirects_outside_github(self, urlopen):
        response = MagicMock()
        response.geturl.return_value = "https://example.net/skewer.deb"
        response.headers = {}
        urlopen.return_value = response

        with self.assertRaises(ValueError):
            fetch_skewer_deb()
        response.close.assert_called_once()

    def test_report_is_bounded_and_normalized(self):
        value = normalize_skewer_report({
            "version": 1, "hostname": "razor", "skewer_version": "0.9.50",
            "ca": {"fingerprint": "ab12", "applications": [{
                "id": "app:firefox", "alias": "Firefox",
                "recognized": True,
                "icon": "data:image/png;base64,aGVsbG8="}], "stores": [{
                "key": "/home/me/.pki/nssdb", "label": "Chromium",
                "application_id": "app:chromium", "snap_lifecycle": "current",
                "available": 1, "installed": False, "matches": 2}]}})
        self.assertEqual("razor", value["hostname"])
        self.assertTrue(value["ca"]["stores"][0]["available"])
        self.assertEqual(2, value["ca"]["stores"][0]["matches"])
        self.assertEqual("Firefox", value["ca"]["applications"][0]["alias"])
        self.assertTrue(value["ca"]["applications"][0]["recognized"])
        self.assertEqual("", value["ca"]["applications"][0]["icon"])
        self.assertEqual("current", value["ca"]["stores"][0]["snap_lifecycle"])

    def test_report_rejects_unsafe_hostname(self):
        with self.assertRaises(ValueError):
            normalize_skewer_report({"version": 1, "hostname": "<script>",
                                     "ca": {"stores": []}})


if __name__ == "__main__":
    unittest.main()
