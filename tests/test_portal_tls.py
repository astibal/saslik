import os
import ssl
import tempfile
import threading
import time
import unittest
import json
from pathlib import Path
from urllib.request import Request, urlopen
from unittest.mock import MagicMock, patch

from saslik.portal_tls import CERTIFICATE_DAYS, details, ensure, generate, subject_names
from saslik.server import SaslikServer


class PortalTlsTests(unittest.TestCase):
    @patch("saslik.portal_tls.socket.getaddrinfo", return_value=[])
    @patch("saslik.portal_tls.socket.gethostname", return_value="saslik-box")
    def test_subject_names_include_bound_ip_and_local_names(self, _hostname, _addresses):
        dns, ips = subject_names("198.18.18.1")
        self.assertEqual(["localhost", "saslik-box"], dns)
        self.assertEqual(["127.0.0.1", "198.18.18.1", "::1"], ips)

    def test_certificate_is_created_once_and_has_server_sans(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "portal"
            certificate, key = ensure(directory, "198.18.18.1")
            first = certificate.read_bytes()
            self.assertEqual(0o600, os.stat(key).st_mode & 0o777)
            decoded = ssl._ssl._test_decode_cert(str(certificate))
            self.assertIn(("IP Address", "198.18.18.1"), decoded["subjectAltName"])
            self.assertIn(("DNS", "localhost"), decoded["subjectAltName"])
            self.assertIn("fingerprint", details(certificate))
            self.assertEqual(first, ensure(directory, "203.0.113.8")[0].read_bytes())

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
