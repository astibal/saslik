import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from saslik.ca import STORE_DEFINITIONS, nss_databases, remove_store, remove_system
from saslik.instance import Instance


class CaStoreTests(unittest.TestCase):
    def test_store_definitions_group_variants_by_application(self):
        self.assertEqual("Firefox", STORE_DEFINITIONS["firefox-snap"]["family"])
        self.assertEqual("Snap", STORE_DEFINITIONS["firefox-snap"]["variant"])
        self.assertEqual("Thunderbird", STORE_DEFINITIONS["thunderbird"]["family"])
        self.assertEqual("LibreWolf", STORE_DEFINITIONS["librewolf-flatpak"]["family"])
        self.assertEqual("Ubuntu", STORE_DEFINITIONS["system"]["variant"])

    def test_thunderbird_and_snap_profiles_are_discovered(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            native = home / ".thunderbird/native.default-release"
            snap = home / "snap/thunderbird/common/.thunderbird/snap.default-release"
            native.mkdir(parents=True)
            snap.mkdir(parents=True)
            (native / "cert9.db").touch()
            (snap / "cert9.db").touch()

            with patch("saslik.ca.Path.home", return_value=home):
                databases = nss_databases()

            self.assertIn(("thunderbird", "Thunderbird", native.resolve()), databases)
            self.assertIn(("thunderbird-snap", "Thunderbird Snap", snap.resolve()), databases)

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

    def test_librewolf_and_flatpak_profiles_are_discovered(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            native = home / ".librewolf/native.default"
            flatpak = home / ".var/app/io.gitlab.librewolf-community/.librewolf/flatpak.default"
            native.mkdir(parents=True)
            flatpak.mkdir(parents=True)
            (native / "cert9.db").touch()
            (flatpak / "cert9.db").touch()

            with patch("saslik.ca.Path.home", return_value=home):
                databases = nss_databases()

            self.assertIn(("librewolf", "LibreWolf", native.resolve()), databases)
            self.assertIn(("librewolf-flatpak", "LibreWolf Flatpak", flatpak.resolve()), databases)

    def test_chromium_uses_new_xdg_nss_database_when_legacy_is_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            database = home / ".local/share/pki/nssdb"
            database.mkdir(parents=True)

            with patch("saslik.ca.Path.home", return_value=home), patch.dict("os.environ", {}, clear=True):
                databases = nss_databases()

            self.assertIn(("chromium", "Chromium / NSS", database), databases)

    @patch("saslik.ca._certutil")
    @patch("saslik.ca.nss_databases")
    def test_remove_store_removes_named_ca_from_every_profile(self, databases, certutil):
        databases.return_value = [
            ("firefox", "Firefox", Path("/profiles/one")),
            ("firefox", "Firefox", Path("/profiles/two")),
        ]
        certutil.return_value.returncode = 0

        removed = remove_store(Instance("lab1"), "firefox")

        self.assertEqual(2, removed)
        self.assertEqual(2, certutil.call_count)
        self.assertTrue(all(call.args[0][0] == "-D" for call in certutil.call_args_list))

    @patch("saslik.ca.subprocess.run")
    @patch("saslik.ca.os.geteuid", return_value=0)
    @patch("saslik.ca.system_certificate_path")
    def test_remove_system_rebuilds_system_trust(self, certificate_path, _geteuid, run):
        target = certificate_path.return_value

        remove_system("lab1")

        target.unlink.assert_called_once_with(missing_ok=True)
        run.assert_called_once_with(["update-ca-certificates", "--fresh"], check=True)


if __name__ == "__main__":
    unittest.main()
