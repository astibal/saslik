import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from saslik.instance import (
    Instance, remember_instance, remembered_instance, rename_instance,
    validate_instance_name,
)


class InstanceTests(unittest.TestCase):
    def test_last_workspace_is_persistent(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"SASLIK_CONFIG_DIR": directory}
        ):
            self.assertEqual("default", remembered_instance())
            remember_instance("lab1")
            self.assertEqual("lab1", remembered_instance())

    def test_name_validation(self):
        self.assertEqual("lab-1.quic", validate_instance_name("lab-1.quic"))
        for value in ("", "../lab", "lab/one", "bad name", "x" * 49):
            with self.assertRaises(ValueError):
                validate_instance_name(value)

    def test_default_egress_and_override(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"SASLIK_CONFIG_DIR": directory, "SASLIK_DATA_DIR": directory}
        ):
            self.assertEqual("nat", Instance.load("lab1").egress)
            self.assertEqual("pasta", Instance.load("lab1", "pasta").egress)

    def test_saved_egress(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"SASLIK_CONFIG_DIR": directory, "SASLIK_DATA_DIR": directory}
        ):
            path = Path(directory) / "lab1"
            path.mkdir()
            (path / "saslik.toml").write_text('egress = "pasta"\n')
            self.assertEqual("pasta", Instance.load("lab1").egress)

    def test_new_instance_does_not_create_runtime_profiles(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"SASLIK_CONFIG_DIR": directory, "SASLIK_DATA_DIR": directory}
        ):
            instance = Instance.load("lab1")
            instance.ensure_config()
            self.assertFalse((Path(directory) / "lab1/profiles.toml").exists())

    def test_discover_finds_named_workspace_without_cli_selection(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"SASLIK_CONFIG_DIR": f"{directory}/config",
                         "SASLIK_DATA_DIR": f"{directory}/data"}
        ):
            lab = Instance.load("lab1")
            lab.ensure_config()
            lab.data_dir.mkdir(parents=True)
            self.assertEqual(["default", "lab1"],
                             [item.name for item in Instance.discover()])

    def test_rename_moves_config_and_data(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"SASLIK_CONFIG_DIR": f"{directory}/config",
                         "SASLIK_DATA_DIR": f"{directory}/data"}
        ):
            old = Instance.load("lab1")
            old.ensure_config()
            old.data_dir.mkdir(parents=True)
            (old.data_dir / "marker").write_text("kept", encoding="utf-8")
            rename_instance("lab1", "demo")
            new = Instance.load("demo")
            self.assertTrue((new.config_dir / "saslik.toml").is_file())
            self.assertEqual("kept", (new.data_dir / "marker").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
