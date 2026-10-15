import unittest
from unittest.mock import patch

from saslik.server import CliSession, app_launch_command, open_frontend


class DummySocket:
    pass


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


class FrontendTests(unittest.TestCase):
    @patch("saslik.server.shutil.which")
    def test_app_command_uses_available_browser_without_launching_it(self, which):
        which.side_effect = lambda name: "/snap/bin/brave" if name == "brave-browser" else None
        self.assertEqual("/snap/bin/brave --app=http://127.0.0.1:8765/",
                         app_launch_command("http://127.0.0.1:8765/"))

    @patch("saslik.server.subprocess.Popen")
    @patch("saslik.server.shutil.which")
    def test_app_mode_uses_first_available_chromium_browser(self, which, popen):
        which.side_effect = lambda name: "/usr/bin/google-chrome" if name == "google-chrome" else None
        self.assertEqual("google-chrome", open_frontend("http://127.0.0.1:8765/"))
        command = popen.call_args.args[0]
        self.assertEqual("/usr/bin/google-chrome", command[0])
        self.assertEqual("--app=http://127.0.0.1:8765/", command[1])

    @patch("saslik.server.webbrowser.open")
    @patch("saslik.server.shutil.which", return_value=None)
    def test_app_mode_falls_back_to_default_browser(self, _which, browser_open):
        self.assertEqual("browser", open_frontend("http://127.0.0.1:8765/"))
        browser_open.assert_called_once()

    @patch("saslik.server.webbrowser.open")
    def test_no_browser_opens_nothing(self, browser_open):
        self.assertEqual("none", open_frontend("http://127.0.0.1:8765/", "none"))
        browser_open.assert_not_called()


if __name__ == "__main__":
    unittest.main()
