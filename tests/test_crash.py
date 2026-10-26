import tarfile
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from saslik.crash import clear_reports, collect, reports, save_bundle


class CrashReportTests(unittest.TestCase):
    def test_reports_bundle_and_clear_only_generated_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / "lab"
            crash_dir = lab / "state/crashes"
            crash_dir.mkdir(parents=True)
            first = crash_dir / "20261016-smithproxy-100.txt"
            second = crash_dir / "20261016-spider-200.txt"
            companion = crash_dir / "20261016-smithproxy-100.native-crash.log"
            keep = crash_dir / "README"
            first.write_text("smithproxy trace", encoding="utf-8")
            second.write_text("spider trace", encoding="utf-8")
            companion.write_text("native crash", encoding="utf-8")
            keep.write_text("keep", encoding="utf-8")
            bundle = Path(directory) / "crashes.tar.gz"

            self.assertEqual([first, second], reports(lab))
            self.assertEqual(2, save_bundle(lab, bundle))
            with tarfile.open(bundle, "r:gz") as archive:
                self.assertEqual([companion.name, first.name, second.name], archive.getnames())
                self.assertEqual(b"smithproxy trace", archive.extractfile(first.name).read())
                self.assertEqual(b"native crash", archive.extractfile(companion.name).read())

            self.assertEqual(2, clear_reports(lab))
            self.assertEqual([], reports(lab))
            self.assertFalse(companion.exists())
            self.assertTrue(keep.is_file())

    def test_empty_bundle_is_valid_and_reports_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "empty.tar.gz"
            self.assertEqual(0, save_bundle(Path(directory) / "lab", bundle))
            with tarfile.open(bundle, "r:gz") as archive:
                self.assertEqual([], archive.getnames())

    @patch("saslik.crash.time.sleep")
    @patch("saslik.crash._record_for_pid", return_value=None)
    @patch("saslik.crash._run", return_value="journal output\n")
    def test_failed_service_still_creates_report_without_coredump(self, run, record, sleep):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / "lab"
            state = lab / "state"
            state.mkdir(parents=True)
            (state / "smithproxy.log").write_text("service output", encoding="utf-8")
            (state / "messages.default.log.crashlog.log").write_text(
                "native backtrace", encoding="utf-8")
            with patch.dict("os.environ", {"SERVICE_RESULT": "signal", "MAINPID": "4242"}):
                report = collect(lab, "smithproxy", "ws-001-smithproxy.service")
            self.assertIsNotNone(report)
            self.assertIn("No matching coredump", report.read_text(encoding="utf-8"))
            siblings = {path.name for path in report.parent.iterdir()}
            self.assertTrue(any(name.endswith(".service.log") for name in siblings))
            self.assertTrue(any(name.endswith(".native-crash.log") for name in siblings))


if __name__ == "__main__":
    unittest.main()
