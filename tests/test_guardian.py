import unittest
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from unittest.mock import patch

from saslik.guardian import send_response
from saslik.server import SaslikServer


class GuardianResponseTests(unittest.TestCase):
    def test_disconnected_client_does_not_escape_response_handler(self):
        connection = Mock()
        connection.sendall.side_effect = BrokenPipeError

        self.assertFalse(send_response(connection, {"ok": True}))

    def test_response_uses_compact_line_delimited_json(self):
        connection = Mock()

        self.assertTrue(send_response(connection, {"ok": True}))
        connection.sendall.assert_called_once_with(b'{"ok":true}\n')


class GuardianRecoveryTests(unittest.TestCase):
    def server(self):
        server = SaslikServer.__new__(SaslikServer)
        server.guardian_socket = Mock()
        server.guardian_unit = "saslik-guardian-test.service"
        server.guardian_start_lock = threading.Lock()
        server.guardian_retry_after = 0.0
        server.guardian_started_once = True
        server.guardian_last_error = ""
        server.runner = SimpleNamespace(
            lab=Path("/tmp/lab"), instance="lab", expose_address="127.0.0.1"
        )
        server.devel = False
        return server

    @patch("saslik.server.logging.warning")
    @patch("saslik.server.logging.error")
    @patch("saslik.server.subprocess.run")
    def test_missing_guardian_recovers_with_cached_sudo_ticket(
            self, run, error, warning):
        server = self.server()
        server.guardian_socket.exists.side_effect = [False, True, True]

        with patch("saslik.server.data_root", return_value=Path("/tmp/data")):
            server.start_guardian()

        run.assert_called_once()
        self.assertEqual("sudo", run.call_args.args[0][0])
        self.assertIn("GUARDIAN LOST", error.call_args.args[0])
        warning.assert_called_once()

    @patch("saslik.server.logging.error")
    @patch("saslik.server.subprocess.run", side_effect=OSError("no sudo ticket"))
    def test_failed_recovery_is_loud_and_rate_limited(self, run, error):
        server = self.server()
        server.guardian_socket.exists.return_value = False

        with self.assertRaises(OSError), patch(
                "saslik.server.data_root", return_value=Path("/tmp/data")):
            server.start_guardian()

        self.assertEqual(2, error.call_count)
        with self.assertRaisesRegex(RuntimeError, "další pokus"):
            server.start_guardian()
        run.assert_called_once()

    def test_degraded_status_is_extensible(self):
        server = self.server()
        server.fatal_health_checks = {
            "guardian": lambda: "privileged Guardian is unavailable",
            "storage": lambda: None,
        }

        self.assertEqual({
            "active": True,
            "issues": [{
                "code": "guardian",
                "error": "privileged Guardian is unavailable",
            }],
        }, server.degraded_status())

    def test_guardian_health_attempts_recovery_before_degrading(self):
        server = self.server()
        server.guardian_socket.exists.return_value = False
        server.guardian_last_error = "cached sudo authorization is unavailable"
        server.start_guardian = Mock(side_effect=RuntimeError("no ticket"))

        self.assertEqual(
            "cached sudo authorization is unavailable",
            server._guardian_health_error(),
        )
        server.start_guardian.assert_called_once()


if __name__ == "__main__":
    unittest.main()
