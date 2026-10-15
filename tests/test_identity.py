import tempfile
import subprocess
import unittest
from pathlib import Path

from saslik.identity import activate, active_name, list_identities, rename_workspace, rotate


class IdentityTests(unittest.TestCase):
    def test_rotate_preserves_config_and_archives_old_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            state = lab / "state"
            certs = state / "certs/default"
            certs.mkdir(parents=True)
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-keyout", str(certs / "ca-key.pem"), "-out", str(certs / "ca-cert.pem"),
                "-subj", "/CN=Saslik test CA",
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            old_ca = (certs / "ca-cert.pem").read_bytes()
            old_ca_key = (certs / "ca-key.pem").read_bytes()
            (certs / "sslca.json").write_text("{}", encoding="ascii")
            old_api = "a" * 48
            old_spider = "b" * 48
            config = state / "smithproxy.cfg"
            config.write_text(
                f'custom_user_setting = 731;\nkeys = [ "{old_api}" ];\n', encoding="utf-8"
            )
            env = state / "state.env"
            env.write_text(
                f"SMITHPROXY_API_KEY={old_api}\nSPIDER_TOKEN={old_spider}\nKEEP=this\n",
                encoding="utf-8",
            )

            archive = rotate(lab)

            new_config = config.read_text(encoding="utf-8")
            new_env = env.read_text(encoding="utf-8")
            self.assertIn("custom_user_setting = 731", new_config)
            self.assertNotIn(old_api, new_config)
            self.assertNotIn(old_spider, new_env)
            self.assertIn("KEEP=this", new_env)
            self.assertEqual(old_ca, (archive / "certs-default/ca-cert.pem").read_bytes())
            self.assertEqual(old_ca, (certs / "ca-cert.pem").read_bytes())
            self.assertEqual(old_ca_key, (certs / "ca-key.pem").read_bytes())

            new_name = active_name(lab)
            self.assertTrue(new_name.startswith("workspace-"))
            self.assertEqual([new_name, "default"],
                             [item["id"] for item in list_identities(lab)])

            activate(lab, "default")
            self.assertEqual("default", active_name(lab))
            self.assertIn(old_api, config.read_text(encoding="utf-8"))
            self.assertTrue(any(item["id"] == new_name for item in list_identities(lab)))

            rename_workspace(lab, "default", "my-workspace")
            rename_workspace(lab, new_name, "saved-workspace")
            self.assertEqual("my-workspace", active_name(lab))
            self.assertTrue((state / "identities/saved-workspace").is_dir())

    def test_workspace_rename_rejects_collision_and_unsafe_name(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            state = lab / "state"
            (state / "identities/taken").mkdir(parents=True)
            (state / "smithproxy.cfg").write_text("x", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                rename_workspace(lab, "default", "taken")
            with self.assertRaises(RuntimeError):
                rename_workspace(lab, "default", "../escape")


if __name__ == "__main__":
    unittest.main()
