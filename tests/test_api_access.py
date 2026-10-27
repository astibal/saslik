import ipaddress
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from saslik.api_access import _route_networks, access_allowed, parse_networks
from saslik.settings import update_settings


class ApiAccessTests(unittest.TestCase):
    def test_loopback_is_always_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            update_settings(lab, {"api_allow_host_networks": False,
                                  "api_allow_tuntom": False})
            self.assertTrue(access_allowed(lab, "127.0.0.1", host_networks=()))
            self.assertTrue(access_allowed(lab, "::1", host_networks=()))

    def test_host_networks_are_enabled_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            networks = (ipaddress.ip_network("192.168.50.0/24"),)
            self.assertTrue(access_allowed(lab, "192.168.50.12",
                                           host_networks=networks))
            self.assertFalse(access_allowed(lab, "192.168.51.12",
                                            host_networks=networks))

    def test_tuntom_client_requires_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            address = ipaddress.ip_address("10.253.0.6")
            self.assertFalse(access_allowed(lab, str(address), host_networks=(),
                                            tunnel_addresses=(address,)))
            update_settings(lab, {"api_allow_tuntom": True})
            self.assertTrue(access_allowed(lab, str(address), host_networks=(),
                                           tunnel_addresses=(address,)))

    def test_explicit_prefixes_are_independent_of_host_network_setting(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            update_settings(lab, {"api_allow_host_networks": False,
                                  "api_allowed_prefixes": "172.20.3.0/24"})
            self.assertTrue(access_allowed(lab, "172.20.3.9", host_networks=()))
            self.assertFalse(access_allowed(lab, "172.20.4.9", host_networks=()))

    def test_comments_and_duplicates_are_ignored(self):
        self.assertEqual((ipaddress.ip_network("10.0.0.0/8"),),
                         parse_networks("# management\n10.0.0.0/8\n10.0.0.1/8"))

    def test_host_routes_exclude_internal_and_tunnel_networks(self):
        routes = """[
          {"dst":"192.168.50.0/24","dev":"eth0"},
          {"dst":"10.240.0.0/30","dev":"ws001h"},
          {"dst":"10.253.0.4/30","dev":"skt1s"},
          {"dst":"172.17.0.0/16","dev":"docker0"}
        ]"""
        with patch("saslik.api_access.subprocess.run",
                   return_value=SimpleNamespace(returncode=0, stdout=routes)):
            self.assertEqual([ipaddress.ip_network("192.168.50.0/24")],
                             _route_networks(4))


if __name__ == "__main__":
    unittest.main()
