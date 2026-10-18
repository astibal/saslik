import subprocess
import tempfile
import unittest
from pathlib import Path

from saslik.dev import (apply_named_patch, apply_text_patch, clear_patch_history,
                        list_patches, normalize_text_patch, project_root,
                        reapply_patch, remember_applied_patch,
                        revert_all_patches, revert_patch)


class DevPatchTests(unittest.TestCase):
    PATCH = """diff --git a/hello.txt b/hello.txt
index 3367afd..3e75765 100644
--- a/hello.txt
+++ b/hello.txt
@@ -1 +1 @@
-old
+new
"""

    def make_checkout(self, root: Path) -> tuple[Path, Path]:
        lab = root / "lab"
        checkout = lab / "src/smithproxy"
        checkout.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(checkout)], check=True)
        source = checkout / "hello.txt"
        source.write_text("old\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(checkout), "add", "hello.txt"], check=True)
        subprocess.run([
            "git", "-C", str(checkout), "-c", "user.name=Saslik test",
            "-c", "user.email=saslik@example.invalid", "commit", "-qm", "initial",
        ], check=True)
        return lab, source

    def test_applies_text_patch_inside_whitelisted_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            lab, source = self.make_checkout(Path(directory))
            apply_text_patch(lab, "smithproxy", self.PATCH)
            self.assertEqual("new\n", source.read_text(encoding="utf-8"))

    def test_named_patch_can_be_reverted_and_reapplied(self):
        with tempfile.TemporaryDirectory() as directory:
            lab, source = self.make_checkout(Path(directory))
            record = apply_named_patch(lab, "smithproxy", self.PATCH, "Greeting")
            self.assertEqual("new\n", source.read_text(encoding="utf-8"))
            self.assertEqual("Greeting", list_patches(lab)[0]["name"])
            revert_patch(lab, record["id"])
            self.assertEqual("old\n", source.read_text(encoding="utf-8"))
            self.assertEqual("reverted", list_patches(lab)[0]["state"])
            reapply_patch(lab, record["id"])
            self.assertEqual("new\n", source.read_text(encoding="utf-8"))
            self.assertEqual("applied", list_patches(lab)[0]["state"])

    def test_revert_all_unwinds_and_clear_only_forgets_history(self):
        with tempfile.TemporaryDirectory() as directory:
            lab, source = self.make_checkout(Path(directory))
            apply_named_patch(lab, "smithproxy", self.PATCH, "Keep me")
            self.assertEqual(1, revert_all_patches(lab))
            self.assertEqual("old\n", source.read_text(encoding="utf-8"))
            reapply_patch(lab, list_patches(lab)[0]["id"])
            self.assertEqual(1, clear_patch_history(lab))
            self.assertEqual([], list_patches(lab))
            self.assertEqual("new\n", source.read_text(encoding="utf-8"))

    def test_remembers_patch_already_present_for_later_revert(self):
        with tempfile.TemporaryDirectory() as directory:
            lab, source = self.make_checkout(Path(directory))
            apply_text_patch(lab, "smithproxy", self.PATCH)
            record = remember_applied_patch(lab, "smithproxy", self.PATCH, "Imported")
            self.assertEqual("new\n", source.read_text(encoding="utf-8"))
            self.assertEqual("true", record["imported"])
            revert_patch(lab, record["id"])
            self.assertEqual("old\n", source.read_text(encoding="utf-8"))

    def test_restores_blank_context_marker_lost_by_clipboard(self):
        patch = "@@ -1,3 +1,3 @@\n old\n\n-new\n+newer\n"
        normalized = normalize_text_patch(patch).splitlines()
        self.assertEqual(" ", normalized[2])

    def test_rejects_path_escape(self):
        patch = """diff --git a/../../outside b/../../outside
new file mode 100644
--- /dev/null
+++ b/../../outside
@@ -0,0 +1 @@
+escape
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lab, _ = self.make_checkout(root)
            with self.assertRaises(RuntimeError):
                apply_text_patch(lab, "smithproxy", patch)
            self.assertFalse((root / "outside").exists())

    def test_rejects_unknown_project(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                project_root(Path(directory), "../../tmp")

    def test_rejects_checkout_symlink_outside_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lab = root / "lab"
            outside = root / "outside"
            (lab / "src").mkdir(parents=True)
            (outside / ".git").mkdir(parents=True)
            (lab / "src/smithproxy").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "mimo workspace"):
                project_root(lab, "smithproxy")


if __name__ == "__main__":
    unittest.main()
