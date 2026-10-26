import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from saslik.instance import (
    Instance, clone_instance, remember_instance, remembered_instance, rename_instance,
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
            stored = Instance.load("lab1")
            self.assertEqual(1, stored.workspace_id)
            self.assertEqual("ws-001", stored.runtime_prefix)
            self.assertTrue((stored.data_dir / "public/installers").is_dir())

    def test_workspace_ids_are_stable_sequential_and_three_digit(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"SASLIK_CONFIG_DIR": directory,
                         "SASLIK_DATA_DIR": f"{directory}/data"}
        ):
            Instance.load("first").ensure_config()
            Instance.load("second").ensure_config()
            Instance.load("first").ensure_config()
            self.assertEqual("ws-001", Instance.load("first").runtime_prefix)
            self.assertEqual("ws-002", Instance.load("second").runtime_prefix)

    def test_discover_finds_named_workspace_without_cli_selection(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"SASLIK_CONFIG_DIR": f"{directory}/config",
                         "SASLIK_DATA_DIR": f"{directory}/data"}
        ):
            lab = Instance.load("lab1")
            lab.ensure_config()
            lab.data_dir.mkdir(parents=True, exist_ok=True)
            self.assertEqual(["default", "lab1"],
                             [item.name for item in Instance.discover()])

    def test_rename_moves_config_and_data(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"SASLIK_CONFIG_DIR": f"{directory}/config",
                         "SASLIK_DATA_DIR": f"{directory}/data"}
        ):
            old = Instance.load("lab1")
            old.ensure_config()
            old.data_dir.mkdir(parents=True, exist_ok=True)
            (old.data_dir / "marker").write_text("kept", encoding="utf-8")
            rename_instance("lab1", "demo")
            new = Instance.load("demo")
            self.assertTrue((new.config_dir / "saslik.toml").is_file())
            self.assertEqual("kept", (new.data_dir / "marker").read_text(encoding="utf-8"))
            self.assertEqual("ws-001", new.runtime_prefix)

    def test_clone_copies_only_persistent_workspace_state(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"SASLIK_CONFIG_DIR": f"{directory}/config",
                         "SASLIK_DATA_DIR": f"{directory}/data"}
        ):
            source = Instance.load("lab1")
            source.ensure_config()
            state = source.data_dir / "state"
            (state / "certs/default").mkdir(parents=True)
            (state / "smithproxy.cfg").write_text(
                f'certs_path = "{source.data_dir}/state/certs/default"', encoding="utf-8")
            (state / "state.env").write_text(
                f"API_KEY=secret\nSMITHPROXY_CA_CERT={source.data_dir}/state/certs/default/ca-cert.pem",
                encoding="utf-8")
            (state / "workspace-settings.json").write_text(
                '{"ref_smithproxy":"feature"}', encoding="utf-8")
            (state / "certs/default/ca-cert.pem").write_text("CA", encoding="utf-8")
            (state / "smithproxy.log").write_text("runtime log", encoding="utf-8")
            (state / "crashes").mkdir()
            dirty_source = source.data_dir / "src/smithproxy"
            dirty_source.mkdir(parents=True)
            subprocess.run(["git", "init", "-q", str(dirty_source)], check=True)
            tracked = dirty_source / "tracked.txt"
            tracked.write_text("original\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(dirty_source), "add", "tracked.txt"], check=True)
            subprocess.run([
                "git", "-C", str(dirty_source), "-c", "user.name=Saslik test",
                "-c", "user.email=saslik@example.invalid", "commit", "-qm", "initial",
            ], check=True)
            tracked.write_text("locally changed\n", encoding="utf-8")
            (source.data_dir / "build").mkdir()

            clone_instance("lab1", "lab-copy")

            clone = Instance.load("lab-copy")
            cloned_config = (clone.data_dir / "state/smithproxy.cfg").read_text()
            cloned_env = (clone.data_dir / "state/state.env").read_text()
            self.assertIn(str(clone.data_dir), cloned_config)
            self.assertIn(str(clone.data_dir), cloned_env)
            self.assertNotIn(str(source.data_dir), cloned_config)
            self.assertNotIn(str(source.data_dir), cloned_env)
            self.assertIn("API_KEY=secret", cloned_env)
            self.assertEqual("CA", (clone.data_dir /
                                     "state/certs/default/ca-cert.pem").read_text())
            self.assertTrue((clone.config_dir / "saslik.toml").is_file())
            self.assertNotEqual(Instance.load("lab1").runtime_prefix, clone.runtime_prefix)
            self.assertEqual("ws-002", clone.runtime_prefix)
            self.assertEqual("locally changed\n", (clone.data_dir /
                             "src/smithproxy/tracked.txt").read_text())
            self.assertEqual('["smithproxy"]\n', (clone.data_dir /
                             "state/cloned-dirty-sources.json").read_text())
            for relative in ("state/smithproxy.log", "state/crashes", "build"):
                self.assertFalse((clone.data_dir / relative).exists())

    def test_clone_rejects_existing_destination(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"SASLIK_CONFIG_DIR": f"{directory}/config",
                         "SASLIK_DATA_DIR": f"{directory}/data"}
        ):
            Instance.load("lab1").ensure_config()
            Instance.load("existing").ensure_config()
            with self.assertRaises(RuntimeError):
                clone_instance("lab1", "existing")


if __name__ == "__main__":
    unittest.main()
