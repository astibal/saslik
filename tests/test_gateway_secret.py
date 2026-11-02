import tempfile
import unittest
from pathlib import Path

from saslik.gateway_secret import ensure_gateway_secret


class GatewaySecretTests(unittest.TestCase):
    def test_secret_is_stable_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            first = ensure_gateway_secret(runtime)
            second = ensure_gateway_secret(runtime)
            path = runtime / "smithproxy-gui.gateway-secret"

            self.assertEqual(first, second)
            self.assertGreaterEqual(len(first), 32)
            self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_invalid_existing_secret_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            (runtime / "smithproxy-gui.gateway-secret").write_text(
                "short\n", encoding="ascii")
            with self.assertRaises(RuntimeError):
                ensure_gateway_secret(runtime)


if __name__ == "__main__":
    unittest.main()
