import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from saslik.ca import nss_databases


class CaStoreTests(unittest.TestCase):
    def test_all_retained_brave_snap_nss_databases_are_discovered(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            old_revision = home / "snap/brave/684/.pki/nssdb"
            revision = home / "snap/brave/690/.pki/nssdb"
            old_revision.mkdir(parents=True)
            revision.mkdir(parents=True)
            (old_revision / "cert9.db").touch()
            (revision / "cert9.db").touch()
            (home / "snap/brave/current").symlink_to("690")

            with patch("saslik.ca.Path.home", return_value=home):
                databases = nss_databases()

            self.assertIn(("brave-snap", "Brave Snap", revision.resolve()), databases)
            self.assertIn(("brave-snap", "Brave Snap", old_revision.resolve()), databases)
            self.assertEqual(2, sum(key == "brave-snap" for key, _, _ in databases))

    def test_all_retained_chromium_snap_nss_databases_are_discovered(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            for number in (3537, 3551):
                database = home / f"snap/chromium/{number}/.pki/nssdb"
                database.mkdir(parents=True)
                (database / "cert9.db").touch()

            with patch("saslik.ca.Path.home", return_value=home):
                databases = nss_databases()

            self.assertEqual(2, sum(key == "chromium-snap" for key, _, _ in databases))


if __name__ == "__main__":
    unittest.main()
