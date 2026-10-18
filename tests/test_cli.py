import subprocess
import unittest
from unittest.mock import patch

from saslik.cli import acquire_privileges, parser


class CliTests(unittest.TestCase):
    def test_browser_is_not_opened_by_default(self):
        self.assertEqual("none", parser().parse_args([]).display_mode)

    def test_devel_mode_is_explicit(self):
        self.assertFalse(parser().parse_args([]).devel)
        self.assertTrue(parser().parse_args(["--devel"]).devel)

    @patch("saslik.cli.subprocess.run")
    @patch("saslik.cli.os.geteuid", return_value=0)
    def test_root_does_not_request_sudo(self, _geteuid, run):
        acquire_privileges()
        run.assert_not_called()

    @patch("saslik.cli.subprocess.run")
    @patch("saslik.cli.os.geteuid", return_value=1000)
    def test_user_acquires_sudo_ticket(self, _geteuid, run):
        acquire_privileges()
        run.assert_called_once_with(["sudo", "-v"], check=True)

    @patch("saslik.cli.subprocess.run", side_effect=subprocess.CalledProcessError(1, ["sudo", "-v"]))
    @patch("saslik.cli.os.geteuid", return_value=1000)
    def test_refused_sudo_has_readable_error(self, _geteuid, _run):
        with self.assertRaisesRegex(RuntimeError, "nepodařilo"):
            acquire_privileges()


if __name__ == "__main__":
    unittest.main()
