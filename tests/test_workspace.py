import tempfile
import shutil
import unittest
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

from saslik.workspace import (
    _run, _sync_checkout, component_source_status, discard_source_changes, initialize_state, load_binary_bundle,
    save_binary_bundle, source_changes,
)


class WorkspaceTests(unittest.TestCase):
    def test_component_source_status_reports_missing_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            result = component_source_status(Path(directory), "smithproxy")
        self.assertEqual("missing", result["state"])

    @patch("saslik.workspace.subprocess.run")
    def test_component_source_status_fetches_without_touching_fetch_head(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, stdout=""),
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 0, stdout="abc\n"),
            subprocess.CompletedProcess([], 0, stdout="abc\n"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            (lab / "src/smithproxy/.git").mkdir(parents=True)
            result = component_source_status(lab, "smithproxy")
        self.assertEqual("current", result["state"])
        fetch = run.call_args_list[1].args[0]
        self.assertIn("--no-write-fetch-head", fetch)
        self.assertIn("+master:refs/saslik/source-status/smithproxy", fetch)

    @patch("saslik.workspace.subprocess.run")
    def test_git_is_noninteractive_and_uses_ssh_agent(self, run):
        _run(["git", "fetch", "origin", "main"])
        environment = run.call_args.kwargs["env"]
        self.assertEqual("0", environment["GIT_TERMINAL_PROMPT"])
        self.assertEqual("ssh -oBatchMode=yes", environment["GIT_SSH_COMMAND"])
        self.assertEqual(os.environ.get("SSH_AUTH_SOCK"), environment.get("SSH_AUTH_SOCK"))

    def test_discard_source_changes_is_limited_to_managed_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / "lab"
            checkout = lab / "src/smithproxy"
            checkout.mkdir(parents=True)
            subprocess.run(["git", "init", "-q", str(checkout)], check=True)
            tracked = checkout / "tracked.txt"
            tracked.write_text("original\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(checkout), "add", "tracked.txt"], check=True)
            subprocess.run([
                "git", "-C", str(checkout), "-c", "user.name=Saslik test",
                "-c", "user.email=saslik@example.invalid", "commit", "-qm", "initial",
            ], check=True)
            tracked.write_text("changed\n", encoding="utf-8")
            (checkout / "untracked.txt").write_text("temporary\n", encoding="utf-8")
            preserved = lab / "state/smithproxy.cfg"
            preserved.parent.mkdir(parents=True)
            preserved.write_text("keep\n", encoding="utf-8")

            self.assertEqual(["smithproxy"], source_changes(lab))
            self.assertEqual(["smithproxy"], discard_source_changes(lab))
            self.assertEqual([], source_changes(lab))
            self.assertEqual("original\n", tracked.read_text(encoding="utf-8"))
            self.assertFalse((checkout / "untracked.txt").exists())
            self.assertEqual("keep\n", preserved.read_text(encoding="utf-8"))

    @patch("saslik.workspace._run")
    def test_sync_can_preserve_a_cloned_dirty_checkout_on_same_branch(self, run):
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory) / "smithproxy"
            checkout.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main", str(checkout)], check=True)
            tracked = checkout / "tracked.txt"
            tracked.write_text("original\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(checkout), "add", "tracked.txt"], check=True)
            subprocess.run([
                "git", "-C", str(checkout), "-c", "user.name=Saslik test",
                "-c", "user.email=saslik@example.invalid", "commit", "-qm", "initial",
            ], check=True)
            tracked.write_text("keep my work\n", encoding="utf-8")

            _sync_checkout(checkout, "unused", "main", preserve_dirty=True)

            self.assertEqual("keep my work\n", tracked.read_text(encoding="utf-8"))
            commands = [call.args[0] for call in run.call_args_list]
            self.assertIn(["git", "-C", str(checkout), "merge", "--ff-only", "FETCH_HEAD"],
                          commands)

    def test_sync_fast_forwards_same_branch_around_non_conflicting_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote = root / "remote.git"
            upstream = root / "upstream"
            checkout = root / "checkout"
            subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
            subprocess.run(["git", "init", "-q", "-b", "main", str(upstream)], check=True)
            for name, content in (("local.txt", "original\n"), ("remote.txt", "v1\n")):
                (upstream / name).write_text(content, encoding="utf-8")
            subprocess.run(["git", "-C", str(upstream), "add", "."], check=True)
            subprocess.run([
                "git", "-C", str(upstream), "-c", "user.name=Saslik test",
                "-c", "user.email=saslik@example.invalid", "commit", "-qm", "initial",
            ], check=True)
            subprocess.run(["git", "-C", str(upstream), "remote", "add", "origin", str(remote)],
                           check=True)
            subprocess.run(["git", "-C", str(upstream), "push", "-q", "-u", "origin", "main"],
                           check=True)
            subprocess.run(["git", "clone", "-q", "-b", "main", str(remote), str(checkout)],
                           check=True)
            (checkout / "local.txt").write_text("my work\n", encoding="utf-8")
            (upstream / "remote.txt").write_text("v2\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(upstream), "add", "remote.txt"], check=True)
            subprocess.run([
                "git", "-C", str(upstream), "-c", "user.name=Saslik test",
                "-c", "user.email=saslik@example.invalid", "commit", "-qm", "remote update",
            ], check=True)
            subprocess.run(["git", "-C", str(upstream), "push", "-q"], check=True)

            _sync_checkout(checkout, str(remote), "main")

            self.assertEqual("my work\n", (checkout / "local.txt").read_text(encoding="utf-8"))
            self.assertEqual("v2\n", (checkout / "remote.txt").read_text(encoding="utf-8"))

    def test_binary_bundle_round_trip_and_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory) / "lab"
            artifacts = {
                "build/smithproxy/smithproxy": b"smith",
                "build/spider/smithproxy-spider": b"spider",
                "build/sift/siftd": b"sift",
                "src/smithproxy-spider/frontend/index.html": b"frontend",
            }
            for relative, data in artifacts.items():
                path = lab / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                if relative.startswith("build/"):
                    path.chmod(0o755)
            (lab / "state").mkdir()
            (lab / "state/source-ref").write_text("master\n", encoding="utf-8")
            bundle = Path(directory) / "binaries.tar.gz"
            save_binary_bundle(lab, bundle)
            for directory_name in ("smithproxy", "spider", "sift"):
                shutil.rmtree(lab / "build" / directory_name)
            shutil.rmtree(lab / "src/smithproxy-spider/frontend")

            manifest = load_binary_bundle(lab, bundle)

            self.assertEqual("master", manifest["source_ref"])
            for relative, data in artifacts.items():
                self.assertEqual(data, (lab / relative).read_bytes())
            self.assertTrue((lab / "state/binary-bundle.json").is_file())
    def test_existing_config_ca_and_credentials_are_never_touched(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            state = lab / "state"
            certs = state / "certs/default"
            certs.mkdir(parents=True)
            config = state / "smithproxy.cfg"
            env = state / "state.env"
            ca = certs / "ca-cert.pem"
            config.write_bytes(b"custom-config\n")
            env.write_bytes(b"SECRET=keep\n")
            ca.write_bytes(b"custom-ca\n")
            self.assertFalse(initialize_state(lab, "proxy"))
            self.assertEqual(b"custom-config\n", config.read_bytes())
            self.assertEqual(b"SECRET=keep\n", env.read_bytes())
            self.assertEqual(b"custom-ca\n", ca.read_bytes())

    def test_existing_ca_requires_certificate_and_key(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            (lab / "src/smithproxy/etc/certs/default").mkdir(parents=True)
            (lab / "src/smithproxy/etc/certs/default/sslca.json").write_text("{}")
            with self.assertRaises(RuntimeError):
                initialize_state(lab, ca_cert=lab / "ca.pem")


if __name__ == "__main__":
    unittest.main()
