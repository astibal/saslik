import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from saslik.pasta import pasta_down, pasta_up, snapshot_host, unit_name


class PastaTests(unittest.TestCase):
    def test_ip_forward_snapshot_is_idempotent_and_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            knob = root / "ip_forward"
            knob.write_text("0\n", encoding="ascii")
            with patch("saslik.pasta.IP_FORWARD", knob), \
                 patch("saslik.pasta._unmount_namespace_reference"):
                snapshot_host(root)
                knob.write_text("1\n", encoding="ascii")
                snapshot_host(root)
                pasta_down(root, "lab1")
            self.assertEqual("0\n", knob.read_text(encoding="ascii"))
            self.assertFalse((root / "state/pasta.ip_forward.before").exists())

    @patch("saslik.pasta._restore_host")
    @patch("saslik.pasta._run")
    @patch("saslik.pasta.pasta_down")
    @patch("saslik.pasta._mount_namespace_reference", return_value=Path("/run/user/0/saslik/sxp-test"))
    @patch("saslik.pasta.shutil.which", return_value="/usr/bin/pasta")
    def test_existing_root_namespace_keeps_privileges_until_join(
        self, _which, _mount, _down, run, _restore
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            with patch("saslik.pasta.subprocess.run", return_value=SimpleNamespace(returncode=0)):
                pasta_up(root, "lab1")

        pasta_command = run.call_args_list[0].args[0]
        self.assertEqual("systemd-run", pasta_command[0])
        self.assertIn("--unit=saslik-pasta-lab1.service", pasta_command)
        self.assertIn("--slice=saslik-egress.slice", pasta_command)
        self.assertIn("/usr/bin/pasta", pasta_command)
        self.assertIn("--foreground", pasta_command)
        self.assertNotIn("--pid", pasta_command)
        binary = pasta_command.index("/usr/bin/pasta")
        self.assertEqual(["--foreground", "--runas", "0"], pasta_command[binary + 1:binary + 4])
        self.assertIn("--netns", pasta_command)
        self.assertIn("/run/user/0/saslik/sxp-test", pasta_command)
        self.assertIn("--netns-only", pasta_command)

    def test_unit_name_is_workspace_specific_and_systemd_safe(self):
        self.assertEqual("saslik-pasta-lab-1.service", unit_name("lab/1"))


if __name__ == "__main__":
    unittest.main()
