import json
import stat
import tempfile
import unittest
from pathlib import Path

from saslik.settings import (component_environment, component_restart_on_failure,
                             provision_settings, public_settings, setting_value,
                             update_settings)


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

    def test_component_restart_defaults_on_and_is_workspace_configurable(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            self.assertTrue(component_restart_on_failure(lab, "smithproxy"))
            update_settings(lab, {"restart_smithproxy": False})
            self.assertFalse(component_restart_on_failure(lab, "smithproxy"))
            self.assertFalse(public_settings(lab)["restart_smithproxy"]["value"])

    def test_debug_and_crash_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            self.assertFalse(setting_value(lab, "debug_build"))
            self.assertTrue(setting_value(lab, "collect_coredumps"))
            self.assertTrue(setting_value(lab, "collect_backtraces"))

    def test_component_refs_are_strings_and_reject_option_injection(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            update_settings(lab, {"ref_smithproxy": "feature/cli-fix",
                                  "ref_spider": "main"})
            self.assertEqual("feature/cli-fix", setting_value(lab, "ref_smithproxy"))
            self.assertEqual("feature/cli-fix",
                             public_settings(lab)["ref_smithproxy"]["value"])
            with self.assertRaisesRegex(ValueError, "Git ref"):
                update_settings(lab, {"ref_smithproxy": "--upload-pack=evil"})


if __name__ == "__main__":
    unittest.main()
