import unittest
from unittest.mock import MagicMock, patch

from saslik.server import (CliSession, Handler, SpiderBootstrapStore,
                           app_launch_command, open_frontend)


class DummySocket:
    pass


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
    def test_json_ignores_browser_disconnect_during_write(self):
        handler = object.__new__(Handler)
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler.wfile = BrokenWriter()

        handler._json({"data": "", "closed": False})


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
