import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from saslik.pasta import pasta_down, pasta_up, snapshot_host


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
                pasta_down(root)
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

            def create_pid(command, **_kwargs):
                if command[0] == "/usr/bin/pasta":
                    (root / "state/pasta.pid").write_text("123\n", encoding="ascii")

            run.side_effect = create_pid
            pasta_up(root)

        pasta_command = run.call_args_list[0].args[0]
        self.assertEqual(["--runas", "0"], pasta_command[1:3])
        self.assertIn("--netns", pasta_command)
        self.assertIn("/run/user/0/saslik/sxp-test", pasta_command)
        self.assertIn("--netns-only", pasta_command)


if __name__ == "__main__":
    unittest.main()
