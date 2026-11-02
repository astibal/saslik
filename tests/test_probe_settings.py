import json
import tempfile
import unittest
from pathlib import Path

from saslik.probe_settings import load, save, validate


class ProbeSettingsTests(unittest.TestCase):
    def test_defaults_keep_existing_periodic_probe_behaviour(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                {"target": "example.com", "enabled": True, "interval": 15},
                load(Path(directory)),
            )

    def test_settings_are_normalized_and_saved_privately(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = save(root, "Probe.Example.", False, "30")
            path = root / "probe-settings.json"
            self.assertEqual({"target": "probe.example", "enabled": False,
                              "interval": 30}, value)
            self.assertEqual(value, json.loads(path.read_text(encoding="utf-8")))
            self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_invalid_target_and_interval_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "hostname"):
            validate("https://example.com/", True, 15)
        with self.assertRaisesRegex(ValueError, "15–3600"):
            validate("example.com", True, 5)


if __name__ == "__main__":
    unittest.main()
