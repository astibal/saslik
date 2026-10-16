import tarfile
import tempfile
import unittest
from pathlib import Path

from saslik.crash import clear_reports, reports, save_bundle


class CrashReportTests(unittest.TestCase):
    def test_reports_bundle_and_clear_only_generated_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / "lab"
            crash_dir = lab / "state/crashes"
            crash_dir.mkdir(parents=True)
            first = crash_dir / "20261016-smithproxy-100.txt"
            second = crash_dir / "20261016-spider-200.txt"
            keep = crash_dir / "README"
            first.write_text("smithproxy trace", encoding="utf-8")
            second.write_text("spider trace", encoding="utf-8")
            keep.write_text("keep", encoding="utf-8")
            bundle = Path(directory) / "crashes.tar.gz"

            self.assertEqual([first, second], reports(lab))
            self.assertEqual(2, save_bundle(lab, bundle))
            with tarfile.open(bundle, "r:gz") as archive:
                self.assertEqual([first.name, second.name], archive.getnames())
                self.assertEqual(b"smithproxy trace", archive.extractfile(first.name).read())

            self.assertEqual(2, clear_reports(lab))
            self.assertEqual([], reports(lab))
            self.assertTrue(keep.is_file())

    def test_empty_bundle_is_valid_and_reports_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "empty.tar.gz"
            self.assertEqual(0, save_bundle(Path(directory) / "lab", bundle))
            with tarfile.open(bundle, "r:gz") as archive:
                self.assertEqual([], archive.getnames())


if __name__ == "__main__":
    unittest.main()
