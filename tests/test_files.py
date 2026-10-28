import tempfile
import unittest
from pathlib import Path

from saslik.files import (
    delete_path, is_locked, is_secret, list_directory, make_directory, read_file,
    target_path, write_file,
)


class FilesTests(unittest.TestCase):
    def test_secret_environment_files_cannot_be_read(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            state = lab / "state"
            state.mkdir()
            for name in ("state.env", "smithproxy-gui.env"):
                (state / name).write_text("SECRET=value\n", encoding="utf-8")
                relative = Path("state") / name
                self.assertTrue(is_locked(relative))
                self.assertTrue(is_secret(relative))
                with self.assertRaises(PermissionError):
                    read_file(lab, relative.as_posix())

    def test_file_round_trip_and_directory_listing(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            make_directory(lab, "notes")
            write_file(lab, "notes/readme.txt", b"hello\n")
            listing = list_directory(lab, "notes")
            self.assertEqual("notes", listing["path"])
            self.assertEqual("readme.txt", listing["entries"][0]["name"])
            self.assertEqual(b"hello\n", read_file(lab, "notes/readme.txt"))
            delete_path(lab, "notes/readme.txt")
            self.assertFalse((lab / "notes/readme.txt").exists())

    def test_paths_cannot_escape_workspace_or_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / "lab"
            outside = Path(directory) / "outside"
            lab.mkdir()
            outside.mkdir()
            (lab / "escape").symlink_to(outside, target_is_directory=True)
            for value in ("../outside", "/etc/passwd", "escape/file"):
                with self.assertRaises(ValueError):
                    target_path(lab, value, allow_missing=True)

    def test_required_files_need_explicit_delete_override(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            required = lab / "state/certs/default/ca-cert.pem"
            required.parent.mkdir(parents=True)
            required.write_text("CA", encoding="utf-8")
            self.assertTrue(is_locked(Path("state/certs/default/ca-cert.pem")))
            self.assertTrue(is_locked(Path("state")))
            with self.assertRaises(PermissionError):
                delete_path(lab, "state/certs/default/ca-cert.pem")
            delete_path(lab, "state/certs/default/ca-cert.pem", override_locked=True)
            self.assertFalse(required.exists())

    def test_workspace_root_cannot_be_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                delete_path(Path(directory), "")


if __name__ == "__main__":
    unittest.main()
