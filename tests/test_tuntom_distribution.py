import unittest
from http import HTTPStatus
from unittest.mock import Mock, patch

from saslik import licensing
from saslik.server import Handler
from saslik.tuntom import TunnelSessions
from saslik.tuntom_supervisor import TunnelSupervisor


class TunnelDistributionTests(unittest.TestCase):
    def test_development_override_is_not_reported_as_verified_license(self):
        with patch.object(licensing, "TUNTOM_ENABLED", True):
            self.assertEqual("development-override", licensing.tunnel_features()["tuntom_license"])

    def test_plain_http_download_route_reaches_placeholder(self):
        handler = Mock(path="/downloads/tuntom-linux-amd64.deb")
        Handler.do_GET(handler)
        handler._tuntom_download.assert_called_once_with()
        handler._skewer_download.assert_not_called()

    def test_placeholder_is_not_a_package_and_does_not_fetch(self):
        handler = Mock()
        with patch("saslik.server.urlopen") as fetch, patch.object(licensing, "TUNTOM_ENABLED", False):
            Handler._tuntom_download(handler)
        fetch.assert_not_called()
        value, status = handler._json.call_args.args
        self.assertEqual(status, HTTPStatus.NOT_IMPLEMENTED)
        self.assertFalse(value["available"])
        self.assertEqual(value["code"], "package_not_published")

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
