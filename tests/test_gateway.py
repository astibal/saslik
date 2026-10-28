import tempfile
import unittest
from pathlib import Path

from saslik.gateway import nginx_config
from saslik.instance import Instance


class GatewayConfigurationTests(unittest.TestCase):
    @staticmethod
    def location(config: str, path: str) -> str:
        start = config.index(f"location ^~ {path} {{")
        end = config.index("\n    }", start)
        return config[start:end]

    def test_routes_workspace_apps_below_stable_authenticated_prefixes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = nginx_config(
                host="0.0.0.0", port=8765, upstream_port=43123,
                certificate=root / "certificate.pem", key=root / "private-key.pem",
                runtime_dir=root, auth_secret="private-token",
                instances=[Instance("alpha", workspace_id=1),
                           Instance("beta", workspace_id=7)],
            )

        self.assertIn("listen 0.0.0.0:8765 ssl", config)
        self.assertIn("location ^~ /ws001/spider/", config)
        self.assertIn("location ^~ /ws001/spider-api/", config)
        self.assertIn("location ^~ /ws007/viewer/", config)
        self.assertIn("location ^~ /ws001/smithproxy-gui/", config)
        self.assertIn("auth_request /__saslik_auth", config)
        self.assertIn("proxy_pass https://10.240.0.2:15173;", config)
        self.assertIn("proxy_pass https://10.240.0.50:15174;", config)
        self.assertIn("proxy_pass https://10.240.0.2:18080/", config)
        self.assertIn("location ^~ /ws001/smithproxy-api/", config)
        self.assertIn("location = /ws001/smithproxy-api/", config)
        self.assertIn(
            "return 302 /ws001/smithproxy-api/api/status/ping;", config
        )
        self.assertIn("return 302 /ws001/sift-api/api/status;", config)
        self.assertIn("return 302 /ws001/lored-api/readyz;", config)
        self.assertIn("X-Saslik-Gateway private-token", config)
        self.assertIn(
            "auth_request /__saslik_auth",
            self.location(config, "/ws001/spider/"),
        )
        self.assertIn(
            "auth_request /__saslik_auth",
            self.location(config, "/ws001/viewer/"),
        )
        gui = self.location(config, "/ws001/smithproxy-gui/")
        self.assertIn("auth_request /__saslik_auth", gui)
        self.assertIn("proxy_pass http://10.240.0.2:18082;", gui)
        self.assertIn("X-Forwarded-Prefix /ws001/smithproxy-gui", gui)
        self.assertIn("proxy_buffering off", gui)
        self.assertIn(
            "auth_request /__saslik_api_auth",
            self.location(config, "/ws001/smithproxy-api/"),
        )
        self.assertIn("X-Saslik-Client-IP $remote_addr", config)
        self.assertIn("X-Saslik-Original-URI $request_uri", config)


if __name__ == "__main__":
    unittest.main()
