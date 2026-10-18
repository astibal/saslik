import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from saslik.version import _source_root, _version_key


class DistributionStub:
    def __init__(self, direct_url: str):
        self.direct_url = direct_url

    def read_text(self, name: str) -> str | None:
        return self.direct_url if name == "direct_url.json" else None


class VersionTests(unittest.TestCase):
    def test_editable_install_is_detected_as_source_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            direct = ('{"dir_info":{"editable":true},'
                      f'"url":"{root.as_uri()}"}}')
            self.assertEqual(root, _source_root(DistributionStub(direct)))

    def test_regular_file_install_is_not_mistaken_for_editable(self):
        direct = '{"dir_info":{"editable":false},"url":"file:///tmp/saslik.whl"}'
        with patch("saslik.version.Path.resolve", return_value=Path("/installed/saslik/version.py")):
            self.assertIsNone(_source_root(DistributionStub(direct)))

    def test_version_key_compares_release_numbers(self):
        self.assertLess(_version_key("0.2.0"), _version_key("0.10.0"))


if __name__ == "__main__":
    unittest.main()
