import unittest
from unittest.mock import Mock, patch

from saslik import licensing
from saslik.server import Handler, fetch_tuntom_deb
from saslik.tuntom import TunnelSessions
from saslik.tuntom_supervisor import TunnelSupervisor


class TunnelDistributionTests(unittest.TestCase):
    def test_development_override_is_not_reported_as_verified_license(self):
        with patch.object(licensing, "TUNTOM_ENABLED", True):
            self.assertEqual("development-override", licensing.tunnel_features()["tuntom_license"])

    def test_plain_http_download_routes_select_architecture(self):
        handler = Mock(path="/downloads/tuntom-linux-amd64.deb")
        Handler.do_GET(handler)
        handler._tuntom_download.assert_called_once_with("amd64")
        handler._skewer_download.assert_not_called()

        handler.reset_mock()
        handler.path = "/downloads/tuntom_arm64.deb"
        Handler.do_GET(handler)
        handler._tuntom_download.assert_called_once_with("arm64")

    @patch("saslik.server.urlopen")
    def test_tuntom_fetch_uses_fixed_architecture_release(self, urlopen):
        response = Mock()
        response.geturl.return_value = "https://release-assets.githubusercontent.com/file.deb"
        response.headers = {"Content-Length": "3"}
        response.read.side_effect = [b"deb", b""]
        urlopen.return_value = response
        package, size = fetch_tuntom_deb("arm64")
        try:
            self.assertEqual((b"deb", 3), (package.read(), size))
        finally:
            package.close()
        self.assertEqual("https://github.com/astibal/tuntom/releases/latest/download/tuntom_arm64.deb",
                         urlopen.call_args.args[0])

    def test_server_policy_denies_open_and_renewal_but_allows_close(self):
        backend = Mock()
        sessions = TunnelSessions(backend)
        opened = sessions.request("peer", {"action": "tunnel-open"}, bytes(32))
        with patch.object(licensing, "TUNTOM_ENABLED", False):
            self.assertEqual({"tuntom": False, "tuntom_license": "not-present"}, licensing.tunnel_features())
            for action in ("tunnel-open", "tunnel-heartbeat"):
                with self.assertRaises(licensing.EntitlementMissing):
                    sessions.request("peer", {"action": action}, bytes(32))
            sessions.request("peer", {"action": "tunnel-close",
                             "context": opened["tunnel"]["context"]}, bytes(32))
        backend.stop.assert_called_once()

    def test_disabled_policy_does_not_allocate_backend(self):
        factory = Mock()
        supervisor = TunnelSupervisor(factory)
        with patch.object(licensing, "TUNTOM_ENABLED", False):
            with self.assertRaises(licensing.EntitlementMissing):
                supervisor.request(("lab", "test", "127.0.0.1"),
                    {"peer": "client-test", "action": "tunnel-open", "psk": bytes(32).hex()})
        factory.assert_not_called()

    def test_policy_disable_cleans_existing_endpoint(self):
        backend = Mock()
        sessions = TunnelSessions(backend)
        supervisor = TunnelSupervisor(lambda _: sessions)
        target = ("lab", "test", "127.0.0.1")
        supervisor.request(target, {"peer": "client-test", "action": "tunnel-open", "psk": bytes(32).hex()})
        with patch.object(licensing, "TUNTOM_ENABLED", False):
            self.assertEqual([], supervisor.expire())
        backend.stop.assert_called_once()
        self.assertFalse(supervisor.sessions)
