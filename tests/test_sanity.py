import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from saslik.sanity import collect, report


class SanityTests(unittest.TestCase):
    @patch("saslik.sanity._capture", return_value="")
    def test_clean_runtime_reports_no_artifacts(self, _capture):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            with patch("saslik.sanity._processes", return_value=[]), \
                    patch("saslik.sanity.Path.exists", return_value=False):
                self.assertTrue(all(not values for _, values in collect(lab)))

    @patch("saslik.sanity.collect", return_value=[
        ("ports", ["tcp LISTEN 0 128 0.0.0.0:55000"]),
        ("routing", []),
    ])
    @patch("builtins.print")
    def test_report_names_artifacts_before_cleanup(self, output, _collect):
        self.assertEqual(0, report(Path("/tmp/lab")))
        rendered = "\n".join(" ".join(str(value) for value in call.args)
                             for call in output.call_args_list)
        self.assertIn("PRE-START SANITY CHECK", rendered)
        self.assertIn("0.0.0.0:55000", rendered)
        self.assertIn("následuje řízený cleanup", rendered)


if __name__ == "__main__":
    unittest.main()
