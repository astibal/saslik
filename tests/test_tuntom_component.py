import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from saslik.components import SystemdComponents
from saslik.guardian import UPDATABLE_COMPONENTS
from saslik.runner import LabRunner
from saslik.settings import update_settings
from saslik.tuntom_supervisor import TunnelSupervisor
from saslik.workspace import _publish_tuntom, build_component, sync, sync_component


class TuntomComponentTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.lab = Path(directory.name)

    def binary(self, contents=b"fixture; never executed"):
        binary = self.lab / "build/tuntom/tuntom"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(contents)
        binary.chmod(0o755)
        return binary

    def test_sync_honors_workspace_ref_and_repository_override(self):
        update_settings(self.lab, {"ref_tuntom": "feature/test"})
        with patch("saslik.workspace._sync_checkout") as checkout, patch.dict(
            os.environ, {"SASLIK_TUNTOM_REPOSITORY": "local-test-repository"}
        ):
            sync_component(self.lab, "tuntom")
        checkout.assert_called_once_with(self.lab / "src/tuntom", "local-test-repository",
                                         "feature/test", False)

    def test_full_sync_includes_tuntom(self):
        with patch("saslik.workspace._sync_checkout") as checkout:
            sync(self.lab, "master")
        self.assertIn(self.lab / "src/tuntom", [call.args[0] for call in checkout.call_args_list])

    def test_build_only_tuntom_and_publish(self):
        self.binary()
        update_settings(self.lab, {"debug_build": True})
        with patch("saslik.workspace._run") as run:
            build_component(self.lab, "tuntom")
        self.assertEqual(2, run.call_count)
        self.assertIn("-DCMAKE_BUILD_TYPE=Debug", run.call_args_list[0].args[0])
        self.assertEqual(["--target", "tuntom"], run.call_args_list[1].args[0][-2:])
        self.assertEqual(self.binary().read_bytes(), (self.lab / "runtime/tuntom/tuntom").read_bytes())

    def test_publication_keeps_old_inode_and_failed_build_keeps_runtime(self):
        self.binary(b"old")
        _publish_tuntom(self.lab)
        runtime = self.lab / "runtime/tuntom/tuntom"
        with runtime.open("rb") as old:
            self.binary(b"new")
            _publish_tuntom(self.lab)
            self.assertEqual(b"old", old.read())
        with patch("saslik.workspace._run", side_effect=RuntimeError("build failed")):
            with self.assertRaises(RuntimeError):
                build_component(self.lab, "tuntom")
        self.assertEqual(b"new", runtime.read_bytes())
        self.assertEqual([runtime], list(runtime.parent.iterdir()))

    def test_supervisor_uses_workspace_runtime_not_system_path(self):
        with patch("saslik.tuntom_supervisor.SystemdTunnelEndpoint") as endpoint:
            TunnelSupervisor._create((self.lab, "test", "127.0.0.1"))
        self.assertEqual(self.lab / "runtime/tuntom/tuntom", endpoint.call_args.args[1])

    def test_update_does_not_restart_other_components(self):
        self.assertIn("tuntom", UPDATABLE_COMPONENTS)
        runner = LabRunner(self.lab)
        with patch("saslik.runner.pasta_cleanup_needed", return_value=False):
            commands = runner._commands("update-component", "master", component="tuntom")
        self.assertEqual(3, len(commands))
        self.assertTrue(all(command[-1] == "tuntom" for command in commands))
        manager = SystemdComponents(self.lab, "test")
        with patch.object(manager, "prepare_tuntom"), patch("saslik.components._run") as run:
            manager.restart_component("tuntom")
        run.assert_called_once_with(["systemctl", "stop", "saslik-test-tuntom-*.service"])

    def test_binary_bundle_still_builds_tuntom(self):
        runner = LabRunner(self.lab)
        state = runner.lab / "state"
        state.mkdir(parents=True)
        (state / "binary-bundle.json").write_text("{}")
        with patch("saslik.runner.pasta_cleanup_needed", return_value=False):
            commands = runner._commands("start", "master")
        tuntom = [command for command in commands if "tuntom" in command]
        self.assertEqual(2, len(tuntom))
        self.assertIn("component-sync", tuntom[0])
        self.assertIn("component-build", tuntom[1])

    def test_missing_runtime_does_not_modify_accounts_or_stop_tunnels(self):
        with patch("saslik.components._run") as run:
            with self.assertRaisesRegex(RuntimeError, "Tuntom"):
                SystemdComponents(self.lab, "test").restart_component("tuntom")
        run.assert_not_called()

    def test_runtime_account_is_reused_and_root_rejected(self):
        self.binary()
        _publish_tuntom(self.lab)
        manager = SystemdComponents(self.lab, "test")
        with patch("saslik.components.grp.getgrnam", return_value=SimpleNamespace(gr_gid=900)), \
             patch("saslik.components.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=900, pw_gid=900)), \
             patch("saslik.components._run") as run:
            manager.prepare_tuntom()
            run.assert_not_called()
        with patch("saslik.components.grp.getgrnam", return_value=SimpleNamespace(gr_gid=0)):
            with self.assertRaisesRegex(RuntimeError, "root"):
                with patch("saslik.components.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=0, pw_gid=0)):
                    manager.prepare_tuntom()

    def test_missing_account_created_without_home_or_login(self):
        self.binary()
        _publish_tuntom(self.lab)
        with patch("saslik.components.grp.getgrnam", side_effect=[KeyError(), SimpleNamespace(gr_gid=900)]), \
             patch("saslik.components.pwd.getpwnam", side_effect=[KeyError(), SimpleNamespace(pw_uid=900, pw_gid=900)]), \
             patch("saslik.components._run") as run:
            SystemdComponents(self.lab, "test").prepare_tuntom()
        self.assertEqual(2, run.call_count)
        self.assertIn("--no-create-home", run.call_args.args[0])
        self.assertIn("/usr/sbin/nologin", run.call_args.args[0])
