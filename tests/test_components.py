import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from saslik.components import Component, SystemdComponents, unit_name
from saslik.settings import update_settings


class ComponentTests(unittest.TestCase):
    @patch("saslik.components._state_env", return_value={
        "SMITHPROXY_API_URL": "https://localhost:55580",
        "SMITHPROXY_CALLBACK_URL": "http://localhost:18080/webhook",
        "SMITHPROXY_API_KEY": "test", "SPIDER_TOKEN": "test",
    })
    def test_frontend_uses_spider_versioned_server_when_available(self, _state):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            manager = SystemdComponents(lab, "lab1")
            legacy = next(c for c in manager.components() if c.name == "frontend")
            self.assertEqual(legacy.command[1:3], ("-m", "http.server"))
            server = lab / "src/smithproxy-spider/tools/serve-frontend.py"
            server.parent.mkdir(parents=True)
            server.touch()
            frontend = next(c for c in manager.components() if c.name == "frontend")
            self.assertEqual(frontend.command[1], str(server))
            self.assertEqual(frontend.command[2:], (
                "15173", "--bind", "0.0.0.0", "--directory", str(lab / "state/frontend")))

    def test_unit_names_are_instance_scoped(self):
        self.assertEqual("saslik-lab-1-smithproxy.service",
                         unit_name("lab.1", "smithproxy"))

    @patch("saslik.components._run")
    def test_down_stops_whole_slice(self, run):
        with tempfile.TemporaryDirectory() as directory:
            manager = SystemdComponents(Path(directory), "lab1")
            manager.down()
        first = run.call_args_list[0].args[0]
        self.assertEqual(["systemctl", "stop", "saslik-lab1.slice"], first)

    @patch("saslik.components._run")
    def test_selective_spider_stop_does_not_touch_smithproxy(self, run):
        with tempfile.TemporaryDirectory() as directory:
            SystemdComponents(Path(directory), "lab1").stop_component("spider")
        commands = [call.args[0] for call in run.call_args_list]
        self.assertTrue(any("saslik-lab1-spider.service" in command for command in commands))
        self.assertTrue(any("saslik-lab1-frontend.service" in command for command in commands))
        self.assertFalse(any("smithproxy" in " ".join(command) for command in commands))

    def test_runtime_has_no_profile_dimension(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = SystemdComponents(Path(directory), "lab1")
        self.assertFalse(hasattr(manager, "profile"))

    def test_smithproxy_restarts_after_unexpected_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            state = lab / "state"
            state.mkdir()
            (state / "state.env").write_text(
                "SMITHPROXY_API_URL=https://10.254.77.2:55580\n"
                "SMITHPROXY_CALLBACK_URL=http://10.254.77.1:18080/webhook\n"
                "SMITHPROXY_API_KEY=key\nSPIDER_TOKEN=token\n",
                encoding="utf-8",
            )
            smithproxy = next(component for component in
                              SystemdComponents(lab, "lab1").components()
                              if component.name == "smithproxy")
        self.assertTrue(smithproxy.restart_on_failure)
        self.assertIn("--no-pidfile", smithproxy.command)
        self.assertFalse(any(value.startswith("SMITHPROXY_PID_FILE=")
                             for value in smithproxy.environment))
        self.assertEqual(
            ((state / "smithproxy-data", Path("/var/smithproxy/data")),),
            smithproxy.bind_paths,
        )

    def test_remote_mode_exposes_forwarders_on_all_ipv4_addresses(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            state = lab / "state"
            state.mkdir()
            (state / "state.env").write_text(
                "SMITHPROXY_API_URL=https://10.254.77.2:55580\n"
                "SMITHPROXY_CALLBACK_URL=http://10.254.77.1:18080/webhook\n"
                "SMITHPROXY_API_KEY=key\nSPIDER_TOKEN=token\n",
                encoding="utf-8",
            )
            manager = SystemdComponents(lab, "lab1", "192.0.2.10")
            expose = [component for component in manager.components()
                      if component.name.startswith("expose-")]
        self.assertEqual(3, len(expose))
        self.assertTrue(all("bind=0.0.0.0" in component.command[1]
                            for component in expose))

    def test_pcap_viewer_uses_workspace_local_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            state = lab / "state"
            state.mkdir()
            (state / "state.env").write_text(
                "SMITHPROXY_API_URL=https://10.254.77.2:55580\n"
                "SMITHPROXY_CALLBACK_URL=http://10.254.77.1:18080/webhook\n"
                "SMITHPROXY_API_KEY=key\nSPIDER_TOKEN=token\n",
                encoding="utf-8",
            )
            executable = lab / "runtime/pcap-viewer-venv/bin/capture-viewer"
            executable.parent.mkdir(parents=True)
            executable.touch()
            (executable.parent / "capture-storage").touch()
            components = SystemdComponents(lab, "lab1").components()
            component = next(item for item in components
                             if item.name == "pcap-viewer")
            storage = next(item for item in components if item.name == "pcap-storage")
        self.assertIn(str(state / "pcap-viewer/storage.token"), component.command)
        self.assertIn("--storage-url", component.command)
        self.assertIn("http://127.0.0.1:15175", component.command)
        self.assertIn("--capacity-profile", component.command)
        self.assertEqual("desktop", component.command[
            component.command.index("--capacity-profile") + 1])
        self.assertIn("--theme-fixed", component.command)
        self.assertEqual("saslik", component.command[
            component.command.index("--theme-fixed") + 1])
        self.assertIn("15174", component.command)
        self.assertIn("--no-browser", component.command)
        self.assertIn(str(state), storage.command)
        self.assertIn("--watch-root", storage.command)
        self.assertIn("15175", storage.command)

    def test_pcap_viewer_receives_workspace_ipinfo_token(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            state = lab / "state"
            state.mkdir()
            (state / "state.env").write_text(
                "SMITHPROXY_API_URL=https://10.254.77.2:55580\n"
                "SMITHPROXY_CALLBACK_URL=http://10.254.77.1:18080/webhook\n"
                "SMITHPROXY_API_KEY=key\nSPIDER_TOKEN=token\n",
                encoding="utf-8",
            )
            executable = lab / "runtime/pcap-viewer-venv/bin/capture-viewer"
            executable.parent.mkdir(parents=True)
            executable.touch()
            (executable.parent / "capture-storage").touch()
            update_settings(lab, {"ipinfo_token": "workspace-secret"})
            viewer = next(component for component in
                          SystemdComponents(lab, "lab1").components()
                          if component.name == "pcap-viewer")
        self.assertEqual(("IPINFO_TOKEN=workspace-secret",), viewer.environment)

    @patch("saslik.components._state_env", return_value={
        "SMITHPROXY_API_URL": "https://localhost:55580",
        "SMITHPROXY_CALLBACK_URL": "http://localhost:18080/webhook",
        "SMITHPROXY_API_KEY": "test", "SPIDER_TOKEN": "test",
    })
    def test_lored_uses_workspace_pack_and_selective_component_group(self, _state):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            executable = lab / "build/lore/lored/lored"
            executable.parent.mkdir(parents=True)
            executable.touch()
            for relative in ("build/spider/smithproxy-spider", "build/sift/siftd",
                             "state/certs/default/ca-cert.pem"):
                dependency = lab / relative
                dependency.parent.mkdir(parents=True, exist_ok=True)
                dependency.touch()
            (lab / "src/smithproxy-spider/frontend").mkdir(parents=True)
            manager = SystemdComponents(lab, "lab1", devel=True)
            manager.build_auxiliaries()
            component = next(item for item in manager.components()
                             if item.name == "lored")
            pack = lab / "state/lored/lore-pack.json"
            pack_text = pack.read_text(encoding="utf-8")
        self.assertEqual(("lored",), manager.component_group("lored"))
        self.assertEqual(str(executable), component.command[0])
        self.assertIn(str(pack), component.command)
        self.assertIn('"format":"lore-pack/2"', pack_text)
        self.assertTrue(component.restart_on_failure)
        self.assertEqual("component.lored", component.required_feature)

    @patch("saslik.components._run")
    @patch("saslik.components.license_grant", return_value={"workers": "4", "ignored": "x"})
    def test_licensed_arguments_use_saslik_allow_list(self, grant, run):
        with tempfile.TemporaryDirectory() as directory:
            manager = SystemdComponents(Path(directory), "lab1")
            manager._start_component(Component(
                "demo", ("/bin/demo",), Path(directory) / "demo.log",
                required_feature="component.demo",
                licensed_arguments=(("workers", "--workers"),),
            ))
        command = run.call_args_list[-1].args[0]
        grant.assert_called_once_with("component.demo", "demo")
        self.assertEqual(["/bin/demo", "--workers", "4"], command[-3:])
        self.assertNotIn("ignored", command)

    @patch("saslik.components._run")
    @patch("saslik.components.install_issuer")
    @patch("saslik.components.license_grant", side_effect=RuntimeError("bez licence"))
    def test_restart_checks_license_before_stopping_running_component(
            self, _grant, _install_issuer, run):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            update_settings(lab, {"license_issuer_key": "public-key"})
            manager = SystemdComponents(lab, "lab1")
            licensed = Component(
                "demo", ("/bin/demo",), Path(directory) / "demo.log",
                required_feature="component.demo",
            )
            with patch.object(manager, "component_group", return_value=("demo",)), \
                    patch.object(manager, "components", return_value=[licensed]), \
                    self.assertRaisesRegex(RuntimeError, "bez licence"):
                manager.restart_component("demo")
        run.assert_not_called()

    def test_initial_start_skips_licensed_component_without_public_key(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = SystemdComponents(Path(directory), "lab1")
            community = Component("community", ("/bin/true",), Path("community.log"))
            licensed = Component(
                "pro", ("/bin/pro",), Path("pro.log"),
                required_feature="component.pro",
            )
            runnable, commands = manager._preflight_licenses(
                [community, licensed], skip_unlicensed=True)
        self.assertEqual([community], runnable)
        self.assertEqual({"community": community.command}, commands)

    @patch("saslik.components._run")
    def test_component_is_started_as_transient_service_in_lab_slice(self, run):
        with tempfile.TemporaryDirectory() as directory:
            manager = SystemdComponents(Path(directory), "lab1")
            capture_path = Path(directory) / "state/smithproxy-data"
            manager._start_component(Component(
                "smithproxy", ("/bin/true",), Path(directory) / "smithproxy.log",
                network_namespace="sxp-test",
                bind_paths=((capture_path, Path("/var/smithproxy/data")),),
            ))
            capture_path_created = capture_path.is_dir()
        command = run.call_args_list[-1].args[0]
        self.assertIn("--unit=saslik-lab1-smithproxy.service", command)
        self.assertIn("--slice=saslik-lab1.slice", command)
        self.assertIn("--property=KillMode=control-group", command)
        self.assertIn("--property=NetworkNamespacePath=/run/netns/sxp-test", command)
        self.assertIn(
            f"--property=BindPaths={capture_path}:/var/smithproxy/data", command)
        self.assertTrue(capture_path_created)

    @patch("saslik.components._run")
    def test_forwarder_restarts_after_transient_bind_failure(self, run):
        with tempfile.TemporaryDirectory() as directory:
            manager = SystemdComponents(Path(directory), "lab1")
            manager._start_component(Component(
                "expose-cli", ("socat", "listen", "connect"),
                Path(directory) / "expose-cli.log",
                restart_on_failure=True,
            ))
        command = run.call_args_list[-1].args[0]
        self.assertIn("--property=Restart=on-failure", command)
        self.assertIn("--property=RestartSec=500ms", command)

    @patch("saslik.components._run")
    def test_crash_diagnostics_are_attached_to_managed_components(self, run):
        with tempfile.TemporaryDirectory() as directory:
            manager = SystemdComponents(Path(directory), "lab1")
            manager._start_component(Component(
                "smithproxy", ("/bin/false",), Path(directory) / "smithproxy.log",
            ))
        command = run.call_args_list[-1].args[0]
        self.assertIn("--property=LimitCORE=infinity", command)
        self.assertTrue(any(value.startswith("--property=ExecStopPost=")
                            and "saslik.crash collect" in value for value in command))


if __name__ == "__main__":
    unittest.main()
