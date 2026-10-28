import os
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import json
from pathlib import Path
from urllib.request import Request, urlopen
from unittest.mock import MagicMock, patch

from saslik.portal_tls import (CERTIFICATE_DAYS, details, ensure, generate,
                               host_interface_addresses, subject_names)
from saslik.server import SaslikServer


class PortalTlsTests(unittest.TestCase):
    @patch("saslik.portal_tls.subprocess.run")
    def test_host_interfaces_exclude_workspace_and_temporary_ipv6(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, stdout=json.dumps([
            {"ifname": "enp5s0", "operstate": "UP", "addr_info": [
                {"family": "inet", "scope": "global", "local": "172.30.1.73"},
                {"family": "inet6", "scope": "global", "local": "2001:db8::1"},
            ]},
            {"ifname": "ws001h", "addr_info": [
                {"family": "inet", "scope": "global", "local": "10.240.0.1"},
            ]},
            {"ifname": "skt1c", "addr_info": [
                {"family": "inet", "scope": "global", "local": "10.253.0.6"},
            ]},
            {"ifname": "virbr9", "operstate": "DOWN", "addr_info": [
                {"family": "inet", "scope": "global", "local": "192.168.123.1"},
            ]},
        ]))
        self.assertEqual({"172.30.1.73"}, host_interface_addresses())

    @patch("saslik.portal_tls.host_interface_addresses", return_value={"172.30.1.73"})
    @patch("saslik.portal_tls.socket.getfqdn", return_value="saslik-box.example")
    @patch("saslik.portal_tls.socket.getaddrinfo", return_value=[])
    @patch("saslik.portal_tls.socket.gethostname", return_value="saslik-box")
    def test_subject_names_include_interfaces_service_ip_and_local_names(
            self, _hostname, _addresses, _fqdn, _interfaces):
        dns, ips = subject_names("0.0.0.0", ("10.252.255.1",))
        self.assertEqual(["localhost", "saslik-box", "saslik-box.example"], dns)
        self.assertEqual(["10.252.255.1", "127.0.0.1", "172.30.1.73", "::1"], ips)

    @patch("saslik.portal_tls.host_interface_addresses", return_value=set())
    def test_certificate_is_created_once_and_has_server_sans(self, _interfaces):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "portal"
            certificate, key = ensure(directory, "198.18.18.1")
            first = certificate.read_bytes()
            self.assertEqual(0o600, os.stat(key).st_mode & 0o777)
            decoded = ssl._ssl._test_decode_cert(str(certificate))
            self.assertIn(("IP Address", "198.18.18.1"), decoded["subjectAltName"])
            self.assertIn(("DNS", "localhost"), decoded["subjectAltName"])
            self.assertIn("fingerprint", details(certificate))
            self.assertEqual(first, ensure(directory, "198.18.18.1")[0].read_bytes())

    @patch("saslik.portal_tls.host_interface_addresses", return_value=set())
    def test_existing_certificate_is_renewed_when_required_san_changes(self, _interfaces):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            first = ensure(directory, "127.0.0.1", ("10.252.255.1",))[0].read_bytes()
            second_path, _ = ensure(directory, "127.0.0.1", ("10.252.255.2",))
            self.assertNotEqual(first, second_path.read_bytes())
            decoded = ssl._ssl._test_decode_cert(str(second_path))
            self.assertIn(("IP Address", "10.252.255.2"), decoded["subjectAltName"])

    def test_explicit_generation_rotates_certificate(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            first = generate(directory, "127.0.0.1")[0].read_bytes()
            second = generate(directory, "127.0.0.1")[0].read_bytes()
            self.assertNotEqual(first, second)
            self.assertGreaterEqual(CERTIFICATE_DAYS, 365 * 5)

    def test_portal_metadata_is_served_over_the_self_signed_tls_connection(self):
        with tempfile.TemporaryDirectory() as temporary:
            certificate, key = generate(Path(temporary), "127.0.0.1")
            runner = MagicMock()
            server = SaslikServer(("127.0.0.1", 0), runner, log_root=Path(temporary))
            server.portal_sessions["tls-test"] = time.monotonic() + 60
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, key)
            server.tls_context = context
            server.tls_certificate = certificate
            server.socket = context.wrap_socket(server.socket, server_side=True)
            worker = threading.Thread(target=server.serve_forever)
            worker.start()
            try:
                client = ssl._create_unverified_context()
                request = Request(
                    f"https://127.0.0.1:{server.server_port}/api/portal-tls",
                    headers={"Cookie": "saslik_session=tls-test"},
                )
                with urlopen(request, context=client, timeout=3) as response:
                    value = json.load(response)
                self.assertEqual(details(certificate), value)
            finally:
                server.shutdown()
                worker.join(timeout=3)
                server.server_close()


if __name__ == "__main__":
    unittest.main()
