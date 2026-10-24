import tempfile
import tarfile
import unittest
from pathlib import Path
from unittest.mock import patch

from saslik.maintenance import (component_logs, process_log, rotate_copytruncate,
                                repair_log_ownership, save_logpack)


class MaintenanceTests(unittest.TestCase):
    def test_component_log_discovery_is_limited_to_workspace_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = [root / "lab/state/smithproxy.log",
                        root / "instances/lab1/state/spider.log"]
            for path in [*expected, root / "instances/lab1/src/build.log"]:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("log", encoding="utf-8")
            self.assertEqual(sorted(expected), component_logs(root))

    def test_copytruncate_keeps_active_inode_and_rotates_backups(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "service.log"
            path.write_text("first payload", encoding="utf-8")
            inode = path.stat().st_ino
            self.assertTrue(rotate_copytruncate(path, limit=4, backups=2))
            self.assertEqual(inode, path.stat().st_ino)
            self.assertEqual(b"", path.read_bytes())
            self.assertTrue(Path(f"{path}.1.gz").is_file())

    @patch("saslik.maintenance.os.chown")
    @patch("saslik.maintenance.os.geteuid", return_value=0)
    @patch("saslik.maintenance.pwd.getpwuid")
    def test_privileged_repair_returns_service_logs_to_owner(self, getpwuid, _geteuid, chown):
        getpwuid.return_value.pw_gid = 100
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "instances/lab1/state/smithproxy.log"
            log.parent.mkdir(parents=True)
            log.write_text("output", encoding="utf-8")

            repaired = repair_log_ownership(root, 1000)

            self.assertEqual([log], repaired)
            chown.assert_called_once_with(log, 1000, 100)

    def test_process_log_keeps_terminal_output_and_rotates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with process_log(root):
                print("saslik process message")
            self.assertIn("saslik process message",
                          (root / "saslik.log").read_text(encoding="utf-8"))

    @patch("saslik.maintenance._journal", return_value=b"journal output\n")
    def test_logpack_contains_logs_but_not_workspace_secrets(self, _journal):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lab = root / "instances/lab1"
            state = lab / "state"
            crashes = state / "crashes/report"
            crashes.mkdir(parents=True)
            (root / "saslik.log").write_text("launcher", encoding="utf-8")
            (root / "skewer-api.log").write_text("status request", encoding="utf-8")
            (state / "smithproxy.log").write_text("proxy", encoding="utf-8")
            (state / "state.env").write_text("SECRET=value", encoding="utf-8")
            (crashes / "backtrace.log").write_text("trace", encoding="utf-8")
            (crashes / "core").write_bytes(b"core")
            destination = root / "logpack.tar.gz"

            save_logpack(root, lab, "lab1", destination)

            with tarfile.open(destination, "r:gz") as bundle:
                names = set(bundle.getnames())
            self.assertIn("manifest.txt", names)
            self.assertIn("saslik/saslik.log", names)
            self.assertIn("saslik/skewer-api.log", names)
            self.assertIn("workspace/smithproxy.log", names)
            self.assertIn("crashes/report/backtrace.log", names)
            self.assertIn("journal/workspace.log", names)
            self.assertNotIn("workspace/state.env", names)
            self.assertNotIn("crashes/report/core", names)


if __name__ == "__main__":
    unittest.main()
