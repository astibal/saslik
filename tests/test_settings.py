import json
import stat
import tempfile
import unittest
from pathlib import Path

from saslik.settings import component_environment, provision_settings, public_settings, update_settings


class WorkspaceSettingsTests(unittest.TestCase):
    def test_secret_is_persisted_privately_and_never_returned(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            update_settings(lab, {"ipinfo_token": "secret-token"})
            path = lab / "state/workspace-settings.json"
            public = public_settings(lab)
            stored = json.loads(path.read_text(encoding="utf-8"))
            mode = stat.S_IMODE(path.stat().st_mode)
        self.assertEqual({"ipinfo_token": "secret-token"}, stored)
        self.assertEqual(0o600, mode)
        self.assertTrue(public["ipinfo_token"]["configured"])
        self.assertNotIn("value", public["ipinfo_token"])

    def test_empty_value_removes_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            update_settings(lab, {"ipinfo_token": "secret-token"})
            update_settings(lab, {"ipinfo_token": ""})
            self.assertFalse(public_settings(lab)["ipinfo_token"]["configured"])
            self.assertEqual((), component_environment(lab, "pcap-viewer"))

    def test_ipinfo_token_is_only_passed_to_viewer(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            update_settings(lab, {"ipinfo_token": "secret-token"})
            self.assertEqual(("IPINFO_TOKEN=secret-token",),
                             component_environment(lab, "pcap-viewer"))
            self.assertEqual((), component_environment(lab, "smithproxy"))

    def test_remote_provisioning_contract_is_set_once(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            provision_settings(lab, {"ipinfo_token": "first"})
            with self.assertRaisesRegex(ValueError, "už je uložené"):
                provision_settings(lab, {"ipinfo_token": "second"})
            self.assertEqual(("IPINFO_TOKEN=first",),
                             component_environment(lab, "pcap-viewer"))


if __name__ == "__main__":
    unittest.main()
