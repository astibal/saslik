"""Exercise the smoke-test contract without booting a privileged VM."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ApplianceSmokeTests(unittest.TestCase):
    def run_smoke(self, private_status="401", expect="api", firmware="bios"):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            image = work / "base.raw"
            image.write_bytes(b"base image must remain unchanged")
            commands = {
                "qemu-img": '#!/bin/sh\nif [ "$1" = info ]; then echo \'{"format":"raw"}\'; fi\n',
                "qemu-system-x86_64": "#!/bin/sh\nexit 0\n",
                "curl": '''#!/bin/sh
case "$*" in
  *https://127.0.0.1:18765/login*) echo '<form action="/setup">' ;;
  *https://127.0.0.1:18765/api/connect*) echo '{}' ;;
  *https://127.0.0.1:18765/api/status*) echo "$TEST_PRIVATE_STATUS" ;;
  *) exit 1 ;;
esac
''',
            }
            for name, content in commands.items():
                executable = work / name
                executable.write_text(content)
                executable.chmod(0o755)
            env = dict(os.environ, PATH=f"{work}:{os.environ['PATH']}",
                       SASLIK_QEMU_ARTIFACTS=str(work / "artifacts"),
                       SASLIK_QEMU_EXPECT=expect, SASLIK_QEMU_TIMEOUT="5",
                       SASLIK_QEMU_FIRMWARE=firmware,
                       SASLIK_QEMU_WEB_PORT="18765", SASLIK_QEMU_GUEST_IP="10.77.0.2",
                       TEST_PRIVATE_STATUS=private_status)
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/test-appliance-qemu.sh"), str(image)],
                env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(image.read_bytes(), b"base image must remain unchanged")
            return result

    def test_https_setup_and_auth_boundary(self):
        result = self.run_smoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("protected API", result.stdout)

    def test_unprotected_api_fails(self):
        result = self.run_smoke(private_status="200")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("místo 401", result.stderr)

    def test_unknown_expectation_fails_immediately(self):
        result = self.run_smoke(expect="typo")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("boot nebo api", result.stderr)

    def test_unknown_firmware_fails_immediately(self):
        result = self.run_smoke(firmware="typo")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bios nebo uefi", result.stderr)

    def test_shell_syntax(self):
        for script in (ROOT / "scripts").glob("*appliance*.sh"):
            with self.subTest(script=script.name):
                subprocess.run(["bash", "-n", str(script)], check=True)

    def test_takeaway_first_boot_precedes_portal(self):
        unit = (ROOT / "scripts/appliance/saslik.service").read_text()
        first_boot = (ROOT / "scripts/appliance/saslik-takeaway-firstboot.service").read_text()
        builder = (ROOT / "scripts/build-appliance-rootfs.sh").read_text()
        self.assertIn("Requires=saslik-takeaway-firstboot.service", unit)
        self.assertIn("Before=saslik.service", first_boot)
        self.assertIn("ConditionPathExists=/var/lib/saslik/.takeaway-first-boot.json", first_boot)
        self.assertIn("saslik-takeaway-firstboot.service", builder)
        self.assertIn("saslik.build_cache prune", builder)
        self.assertIn('flock 8', builder)
        self.assertIn('mount --bind "$cache/apt/archives"', builder)

    def test_linux_takeaway_contract(self):
        launcher = (ROOT / "scripts/takeaway/saslik").read_text()
        builder = (ROOT / "scripts/build-takeaway-linux.sh").read_text()
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn("takeaway-linux:", makefile)
        self.assertIn("mksquashfs", builder)
        self.assertIn("saslik-takeaway.sqfs", builder)
        self.assertIn("-keep-as-directory", builder)
        self.assertIn("-processors 2", builder)
        self.assertIn('--work-root', builder)
        self.assertIn('mktemp -d --tmpdir="$work_root"', builder)
        self.assertNotIn("zstd -T0", builder)
        self.assertIn("saslik.takeaway seal", builder)
        self.assertIn('"$bundle/saslik-tkw"', builder)
        self.assertIn("/instances/*/state/smithproxy-data/***", builder)
        self.assertIn("/instances/*/state/pcap-viewer/***", builder)
        self.assertIn("--exclude='*.pcapng'", builder)
        self.assertIn("systemd-nspawn", launcher)
        self.assertIn("--network-namespace-path", launcher)
        self.assertIn("--tcp-ports \"$bind_address/$host_port-$psk_port:8765-8766\"", launcher)
        self.assertIn("SASLIK_TUNTOM_PUBLIC_PORT_BASE", launcher)
        self.assertIn("saslik-takeaway-slot-$candidate.lock", launcher)
        self.assertIn("state/smithproxy-data", launcher)
        self.assertIn("sha256sum -c SHA256SUMS", launcher)
        self.assertIn('lower="$image_mount/rootfs"', launcher)
