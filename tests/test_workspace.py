import tempfile
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch

from saslik.workspace import initialize_state, load_binary_bundle, save_binary_bundle


class WorkspaceTests(unittest.TestCase):
    def test_binary_bundle_round_trip_and_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / "lab"
            artifacts = {
                "build/smithproxy/smithproxy": b"smith",
                "build/spider/smithproxy-spider": b"spider",
                "build/sift/siftd": b"sift",
                "src/smithproxy-spider/frontend/index.html": b"frontend",
            }
            for relative, data in artifacts.items():
                path = lab / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                if relative.startswith("build/"):
                    path.chmod(0o755)
            (lab / "state").mkdir()
            (lab / "state/source-ref").write_text("master\n", encoding="utf-8")
            bundle = Path(directory) / "binaries.tar.gz"
            save_binary_bundle(lab, bundle)
            for directory_name in ("smithproxy", "spider", "sift"):
                shutil.rmtree(lab / "build" / directory_name)
            shutil.rmtree(lab / "src/smithproxy-spider/frontend")

            manifest = load_binary_bundle(lab, bundle)

            self.assertEqual("master", manifest["source_ref"])
            for relative, data in artifacts.items():
                self.assertEqual(data, (lab / relative).read_bytes())
            self.assertTrue((lab / "state/binary-bundle.json").is_file())
    def test_existing_config_ca_and_credentials_are_never_touched(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            state = lab / "state"
            certs = state / "certs/default"
            certs.mkdir(parents=True)
            config = state / "smithproxy.cfg"
            env = state / "state.env"
            ca = certs / "ca-cert.pem"
            config.write_bytes(b"custom-config\n")
            env.write_bytes(b"SECRET=keep\n")
            ca.write_bytes(b"custom-ca\n")
            self.assertFalse(initialize_state(lab, "proxy"))
            self.assertEqual(b"custom-config\n", config.read_bytes())
            self.assertEqual(b"SECRET=keep\n", env.read_bytes())
            self.assertEqual(b"custom-ca\n", ca.read_bytes())

    def test_existing_ca_requires_certificate_and_key(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            (lab / "src/smithproxy/etc/certs/default").mkdir(parents=True)
            (lab / "src/smithproxy/etc/certs/default/sslca.json").write_text("{}")
            with self.assertRaises(RuntimeError):
                initialize_state(lab, ca_cert=lab / "ca.pem")


if __name__ == "__main__":
    unittest.main()
