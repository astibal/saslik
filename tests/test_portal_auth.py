import json
import http.client
import stat
import tempfile
import threading
import unittest
from types import SimpleNamespace
from pathlib import Path
from urllib.parse import urlencode
from unittest.mock import Mock, patch

from saslik.portal_auth import (ensure_portal_credentials, portal_account_info,
                                record_portal_login, set_portal_password,
                                verify_portal_password)
from saslik.server import SaslikServer
from saslik.settings import update_settings


class PortalCredentialsTests(unittest.TestCase):
    def test_credentials_are_stable_and_owner_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = ensure_portal_credentials(root)
            second = ensure_portal_credentials(root)

            self.assertEqual(first, second)
            self.assertEqual("saslik", first[0])
            self.assertFalse(first[1])
            self.assertEqual(0o600, stat.S_IMODE(first[2].stat().st_mode))
            set_portal_password(first[2], "correct horse battery")
            self.assertTrue(ensure_portal_credentials(root)[1])
            self.assertTrue(verify_portal_password(first[2], "correct horse battery"))
            self.assertFalse(verify_portal_password(first[2], "wrong password"))
            self.assertNotIn("correct horse battery", first[2].read_text())

    def test_invalid_credentials_file_is_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.mkdir(exist_ok=True)
            path = root / "portal-credentials.json"
            path.write_text("broken")

            username, configured, _ = ensure_portal_credentials(root)

            self.assertEqual("saslik", username)
            self.assertFalse(configured)

    def test_plaintext_credentials_are_migrated_and_account_times_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "portal-credentials.json"
            path.write_text(json.dumps({"username": "saslik",
                                        "password": "correct horse battery",
                                        "password_changed_at": 123.0,
                                        "last_login_at": 456.0}))

            _, configured, _ = ensure_portal_credentials(root)

            self.assertTrue(configured)
            self.assertTrue(verify_portal_password(path, "correct horse battery"))
            self.assertNotIn("correct horse battery", path.read_text())
            self.assertEqual({"password_changed_at": 123.0, "last_login_at": 456.0},
                             portal_account_info(path))
            record_portal_login(path)
            self.assertGreater(portal_account_info(path)["last_login_at"], 456.0)


class PortalSessionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        lab = root / "instances" / "test"
        (lab / "state/certs/default").mkdir(parents=True)
        (lab / "state/certs/default/ca-cert.pem").write_text("test ca")
        runner = Mock(root=root, lab=lab, instance="test",
                      runtime=SimpleNamespace(namespace_address="10.240.0.2"))
        runner.snapshot.return_value = {
            "endpoints": {"proxy": "http://127.0.0.1:3128",
                          "socks": "socks5h://127.0.0.1:1080",
                          "spider_ui": "http://127.0.0.1:8080",
                          "cli": "tcp://127.0.0.1:5000"},
            "services": {"smithproxy": {"state": "running"}},
        }
        self.server = SaslikServer(("127.0.0.1", 0), runner, log_root=root)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        data = response.read()
        headers = dict(response.getheaders())
        connection.close()
        return response.status, headers, data

    def claim(self, password="correct horse battery"):
        body = urlencode({"password": password, "confirm": password})
        status, headers, _ = self.request(
            "POST", "/setup", body,
            {"Content-Type": "application/x-www-form-urlencoded",
             "Content-Length": str(len(body))},
        )
        self.assertEqual(303, status)
        return headers["Set-Cookie"].split(";", 1)[0], headers["Set-Cookie"]

    def test_first_access_claims_portal_and_accepts_session_cookie(self):
        status, headers, _ = self.request("GET", "/")
        self.assertEqual(303, status)
        self.assertEqual("/login", headers["Location"])

        status, _, page = self.request("GET", "/login")
        self.assertEqual(200, status)
        self.assertIn(b"Claim your Saslik", page)
        cookie, set_cookie = self.claim()
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("Secure", set_cookie)

        status, _, page = self.request("GET", "/", headers={"Cookie": cookie})
        self.assertEqual(200, status)
        self.assertIn(b"Saslik", page)

    def test_skewer_discovery_is_public_but_ui_api_is_not(self):
        status, _, _ = self.request("GET", "/api/skewer")
        self.assertEqual(200, status)
        status, _, _ = self.request("GET", "/api/status")
        self.assertEqual(401, status)

    def test_connect_portal_is_public_and_contains_only_unprivileged_links(self):
        for path in ("/connect", "/connect.css", "/connect-custom.css", "/connect.js", "/api/connect",
                     "/connect/ca.pem"):
            status, _, _ = self.request("GET", path)
            self.assertEqual(200, status, path)

        status, _, payload = self.request("GET", "/api/connect")
        self.assertEqual(200, status)
        value = json.loads(payload)
        urls = {item["url"] for item in value["items"]}
        self.assertIn("http://127.0.0.1:3128", urls)
        self.assertIn("socks5h://127.0.0.1:1080", urls)
        self.assertIn("/api/skewer", urls)
        self.assertIn("/connect/ca.pem", urls)
        self.assertNotIn("tcp://127.0.0.1:5000", urls)
        self.assertNotIn("http://127.0.0.1:8080", urls)
        self.assertFalse(any(item["kind"] in {"API", "APPLICATION"}
                             for item in value["items"]))
        self.assertEqual("10.240.0.2/32", value["routing"]["target"])
        self.assertEqual("127.0.0.1", value["routing"]["via"])
        self.assertNotIn("socks_url", value["routing"])
        self.assertEqual("127.0.0.1", value["client"]["address"])
        self.assertTrue(all(item["qr"].startswith("data:image/svg+xml;base64,")
                            for item in value["items"]))
        self.assertTrue(all(item["qr"].startswith("data:image/svg+xml;base64,")
                            for item in value["downloads"]))

        status, _, _ = self.request("GET", "/api/skewer/pairing")
        self.assertEqual(401, status)

    def test_custom_installer_is_listed_and_downloadable_without_login(self):
        root = self.server.runner.lab / "public/installers"
        root.mkdir(parents=True)
        (root / "skewer-android.apk").write_bytes(b"apk payload")
        (root / "manifest.json").write_text(json.dumps({"installers": [{
            "file": "skewer-android.apk", "title": "Skewer Mobile",
            "platform": "Android APK", "description": "Android client",
            "order": 5,
        }]}))

        status, _, payload = self.request("GET", "/api/connect")
        self.assertEqual(200, status)
        downloads = json.loads(payload)["downloads"]
        custom = next(item for item in downloads if item.get("file") == "skewer-android.apk")
        self.assertEqual("Skewer Mobile", custom["title"])
        self.assertEqual("Android APK", custom["platform"])
        self.assertEqual("devel", custom["channel"])
        self.assertEqual(64, len(custom["sha256"]))

        status, headers, payload = self.request("GET", custom["url"])
        self.assertEqual(200, status)
        self.assertEqual(b"apk payload", payload)
        self.assertIn("attachment", headers["Content-Disposition"])

    def test_custom_installer_rejects_traversal_and_symlinks(self):
        root = self.server.runner.lab / "public/installers"
        root.mkdir(parents=True)
        outside = self.server.runner.lab / "private.bin"
        outside.write_bytes(b"private")
        (root / "escape.bin").symlink_to(outside)

        status, _, _ = self.request("GET", "/downloads/custom/%2e%2e%2fprivate.bin")
        self.assertEqual(400, status)
        status, _, _ = self.request("GET", "/downloads/custom/escape.bin")
        self.assertEqual(404, status)

    def test_custom_installer_metadata_and_delete_require_admin_session(self):
        root = self.server.runner.lab / "public/installers"
        root.mkdir(parents=True)
        (root / "client.apk").write_bytes(b"apk")
        body = json.dumps({"operation": "metadata", "workspace": "",
                           "file": "client.apk", "title": "Mobile client",
                           "platform": "Android", "architecture": "arm64",
                           "version": "1.2.3", "channel": "stable"})
        status, _, _ = self.request("POST", "/api/public-installers", body,
                                    {"Content-Type": "application/json",
                                     "Content-Length": str(len(body))})
        self.assertEqual(401, status)

        cookie, _ = self.claim()
        status, _, payload = self.request("GET", "/api/session", headers={"Cookie": cookie})
        csrf = json.loads(payload)["csrf"]
        status, _, payload = self.request(
            "POST", "/api/public-installers", body,
            {"Cookie": cookie, "Content-Type": "application/json",
             "Content-Length": str(len(body)), "X-Saslik-CSRF": csrf})
        self.assertEqual(200, status, payload)
        item = json.loads(payload)["installers"][0]
        self.assertEqual("stable", item["channel"])
        self.assertEqual("1.2.3", item["version"])

        delete = json.dumps({"operation": "delete", "workspace": "",
                             "file": "client.apk"})
        status, _, payload = self.request(
            "POST", "/api/public-installers", delete,
            {"Cookie": cookie, "Content-Type": "application/json",
             "Content-Length": str(len(delete)), "X-Saslik-CSRF": csrf})
        self.assertEqual(200, status, payload)
        self.assertFalse((root / "client.apk").exists())

    def test_cli_and_debug_transports_require_portal_session(self):
        for method, path in (("GET", "/api/cli?session=guessed"),
                             ("GET", "/api/dev/gdb/session?session=guessed"),
                             ("POST", "/api/cli")):
            status, _, _ = self.request(method, path)
            self.assertEqual(401, status)

    def test_gateway_auth_accepts_only_gateway_secret_and_live_session(self):
        self.server.gateway = SimpleNamespace(
            auth_secret="gateway-secret", close=Mock()
        )
        status, _, _ = self.request("GET", "/api/gateway/auth")
        self.assertEqual(404, status)

        status, _, _ = self.request(
            "GET", "/api/gateway/auth",
            headers={"X-Saslik-Gateway": "gateway-secret"},
        )
        self.assertEqual(401, status)

        cookie, _ = self.claim()
        status, _, _ = self.request(
            "GET", "/api/gateway/auth",
            headers={"X-Saslik-Gateway": "gateway-secret", "Cookie": cookie},
        )
        self.assertEqual(204, status)

    def test_gateway_api_auth_uses_workspace_network_policy_or_session(self):
        self.server.gateway = SimpleNamespace(
            auth_secret="gateway-secret", close=Mock()
        )
        lab = self.server.runner.lab
        instance = SimpleNamespace(name="test", workspace_id=1, data_dir=lab)
        update_settings(lab, {"api_allow_host_networks": False,
                              "api_allowed_prefixes": "198.51.100.0/24"})

        def authorize(address, cookie=""):
            headers = {
                "X-Saslik-Gateway": "gateway-secret",
                "X-Saslik-Client-IP": address,
                "X-Saslik-Original-URI": "/ws001/smithproxy-api/api/status",
            }
            if cookie:
                headers["Cookie"] = cookie
            with patch("saslik.server.Instance.discover", return_value=[instance]):
                return self.request("GET", "/api/gateway/api-auth", headers=headers)[0]

        self.assertEqual(204, authorize("198.51.100.27"))
        self.assertEqual(403, authorize("203.0.113.27"))
        cookie, _ = self.claim()
        self.assertEqual(204, authorize("203.0.113.27", cookie))

    def test_password_change_keeps_current_session_and_revokes_others(self):
        cookie, _ = self.claim()
        status, _, data = self.request("GET", "/api/session", headers={"Cookie": cookie})
        self.assertEqual(200, status)
        session = json.loads(data)
        self.assertGreater(session["expires_in"], 60)
        self.assertIsNotNone(session["password_changed_at"])
        body = json.dumps({"current": "correct horse battery",
                           "password": "new correct horse battery"})
        status, _, data = self.request(
            "POST", "/api/account/password", body,
            {"Cookie": cookie, "Content-Type": "application/json",
             "Content-Length": str(len(body)), "X-Saslik-CSRF": session["csrf"]},
        )
        self.assertEqual(200, status, data)
        status, _, _ = self.request("GET", "/api/session", headers={"Cookie": cookie})
        self.assertEqual(200, status)
        self.assertTrue(verify_portal_password(self.server.portal_credentials_path,
                                               "new correct horse battery"))
        self.assertNotIn("new correct horse battery",
                         self.server.portal_credentials_path.read_text())
