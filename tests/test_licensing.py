import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from saslik.licensing import (EntitlementMissing, LicensingError,
                              install_issuer, license_grant)


class LicensingTests(unittest.TestCase):
    def serve(self, *responses: str) -> tuple[Path, threading.Thread]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "licensing.sock"
        ready = threading.Event()

        def server() -> None:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(path))
                listener.listen()
                ready.set()
                for response in responses:
                    connection, _ = listener.accept()
                    with connection:
                        while connection.recv(4096):
                            pass
                        connection.sendall((response + "\n").encode())

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        ready.wait(1)
        self.addCleanup(thread.join, 1)
        return path, thread

    def test_grant_returns_effective_arguments(self):
        path, _ = self.serve("OK 1", "OK\tchannel=earlybird\tworkers=4")
        self.assertEqual(
            {"channel": "earlybird", "workers": "4"},
            license_grant("component.demo", "demo", socket_path=path),
        )

    def test_missing_entitlement_is_explicit(self):
        path, _ = self.serve("OK 0")
        with self.assertRaisesRegex(EntitlementMissing, "component.demo"):
            license_grant("component.demo", "demo", socket_path=path)

    def test_unavailable_daemon_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.sock"
            with self.assertRaisesRegex(LicensingError, "není dostupná"):
                license_grant("component.demo", "demo", socket_path=path)

    def test_environment_selects_socket(self):
        path, _ = self.serve("OK 1", "OK")
        with patch.dict(os.environ, {"SASLIK_LICENSING_SOCKET": str(path)}):
            self.assertEqual({}, license_grant("component.demo", "demo"))

    def test_install_issuer_sends_utf8_byte_size_and_pem(self):
        key = "-----BEGIN PUBLIC KEY-----\náč\n-----END PUBLIC KEY-----\n"
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "licensing.sock"
        received: list[bytes] = []
        ready = threading.Event()

        def server() -> None:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(path))
                listener.listen()
                ready.set()
                connection, _ = listener.accept()
                with connection:
                    while chunk := connection.recv(4096):
                        received.append(chunk)
                    connection.sendall(b"OK issuer=smithproxy\n")

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        ready.wait(1)
        install_issuer("smithproxy", key, socket_path=path)
        thread.join(1)
        command, body = b"".join(received).split(b"\n", 1)
        self.assertEqual(
            f"INSTALL-ISSUER smithproxy {len(key.encode())}".encode(), command)
        self.assertEqual(key.encode(), body)


if __name__ == "__main__":
    unittest.main()
