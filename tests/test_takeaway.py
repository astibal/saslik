"""Takeaway images must not clone machine or workspace identity."""

import json
from pathlib import Path
import tempfile
import unittest

from saslik.takeaway import MARKER_NAME, PENDING_SECRET, first_boot, seal


class TakeawayIdentityTests(unittest.TestCase):
    def _tree(self, root: Path, source: Path) -> Path:
        lab = root / "instances/lab1"
        state = lab / "state"
        certs = state / "certs/default"
        certs.mkdir(parents=True)
        (lab / "workspace-id").write_text("1\n", encoding="ascii")
        (state / "smithproxy.cfg").write_text(
            f'api_key = "old-api-key"\ndata = "{source}/instances/lab1/data"\n',
            encoding="utf-8")
        (state / "state.env").write_text(
            "SMITHPROXY_API_KEY=old-api-key\n"
            "SPIDER_TOKEN=old-spider-token\n"
            f"SMITHPROXY_CA_CERT={source}/instances/lab1/state/certs/default/ca-cert.pem\n",
            encoding="utf-8")
        (certs / "ca-key.pem").write_text("old-ca-key", encoding="ascii")
        (certs / "ca-cert.pem").write_text("old-ca-cert", encoding="ascii")
        (certs / "sslca.json").write_text('{"templates": []}\n', encoding="utf-8")
        (state / "workspace-settings.json").write_text(json.dumps({
            "ipinfo_token": "old-ipinfo-token",
            "debug_build": True,
        }), encoding="utf-8")
        (state / "identities").mkdir()
        (state / "identities/token").write_text("old-identity", encoding="ascii")
        (state / "pcap-viewer").mkdir()
        (state / "pcap-viewer/storage.token").write_text("old-storage-token", encoding="ascii")
        (state / "smithproxy.log").write_text("old log", encoding="ascii")
        (state / "traffic.pcapng").write_bytes(b"old capture")
        (lab / "src/repository/.git").mkdir(parents=True)
        (lab / "src/repository/.git/config").write_text("private remote", encoding="ascii")
        (root / "portal-credentials.json").write_text("old-password", encoding="ascii")
        (root / "skewer-clients.json").write_text("old-pairing", encoding="ascii")
        (root / "portal-tls").mkdir()
        (root / "portal-tls/key.pem").write_text("old-portal-key", encoding="ascii")
        (root / "gateway").mkdir()
        (root / "gateway/secret").write_text("old-gateway-key", encoding="ascii")
        return lab

    @staticmethod
    def _all_bytes(root: Path) -> bytes:
        return b"\n".join(path.read_bytes() for path in root.rglob("*") if path.is_file())

    def test_seal_then_first_boot_rotates_managed_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "live"
            source.mkdir()
            staging = base / "staging"
            staging.mkdir()
            lab = self._tree(staging, source)

            self.assertEqual(seal(staging, str(source)), ["lab1"])
            sealed = self._all_bytes(staging)
            for secret in (b"old-api-key", b"old-spider-token", b"old-ca-key",
                           b"old-portal-key", b"old-pairing", b"old-ipinfo-token",
                           b"old-storage-token"):
                self.assertNotIn(secret, sealed)
            self.assertIn(PENDING_SECRET.encode(), sealed)
            self.assertFalse((lab / "src/repository/.git").exists())
            self.assertFalse((lab / "state/traffic.pcapng").exists())
            self.assertEqual(json.loads((lab / "state/workspace-settings.json").read_text()),
                             {"debug_build": True})

            self.assertEqual(first_boot(staging, generate_ssh_keys=False), ["lab1"])
            self.assertFalse((staging / MARKER_NAME).exists())
            final = self._all_bytes(staging)
            self.assertNotIn(PENDING_SECRET.encode(), final)
            self.assertNotIn(b"old-api-key", final)
            self.assertTrue((lab / "state/certs/default/ca-key.pem").is_file())
            self.assertTrue((lab / "state/certs/default/portal-cert.pem").is_file())
            env = (lab / "state/state.env").read_text(encoding="utf-8")
            config = (lab / "state/smithproxy.cfg").read_text(encoding="utf-8")
            api_key = next(line.split("=", 1)[1] for line in env.splitlines()
                           if line.startswith("SMITHPROXY_API_KEY="))
            self.assertEqual(len(api_key), 48)
            self.assertIn(f'"{api_key}"', config)
            self.assertIn(str(staging / "instances/lab1"), env)
            self.assertNotIn(str(source), env)

    def test_seal_refuses_live_data_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(RuntimeError, "živý"):
                seal(root, str(root))
