import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from saslik.components import Component, SystemdComponents
from saslik.runtime import WorkspaceRuntime
from saslik.settings import update_settings


class ComponentTests(unittest.TestCase):
    @patch("saslik.components.urllib.request.urlopen")
    def test_storage_readiness_preserves_loopback_host_identity(self, urlopen):
        response = MagicMock()
        response.__enter__.return_value = response
        urlopen.return_value = response
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            token = lab / "state/pcap-viewer/storage.token"
            token.parent.mkdir(parents=True)
            token.write_text("storage-secret", encoding="ascii")

            SystemdComponents(lab, "lab1")._wait_storage_ready()

        request = urlopen.call_args.args[0]
        self.assertEqual("http://10.240.0.2:15175/readyz", request.full_url)
        self.assertEqual("127.0.0.1", request.get_header("Host"))
        self.assertEqual("Bearer storage-secret",
                         request.get_header("Authorization"))

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
                "25173", "--bind", "127.0.0.1", "--directory", str(lab / "state/frontend"),
                "--base-path", "/ws001/spider/", "--backend-path", "/ws001/spider-api/"))
            relay = next(c for c in manager.components() if c.name == "frontend-tls")
            self.assertIn("OPENSSL-LISTEN:15173", relay.command[1])
            self.assertIn("bind=10.240.0.2", relay.command[1])
            self.assertEqual("TCP4:127.0.0.1:25173", relay.command[2])
            self.assertEqual("ws-001", relay.network_namespace)
            spider = next(c for c in manager.components() if c.name == "spider")
            spider_tls = next(c for c in manager.components() if c.name == "spider-tls")
            self.assertEqual("127.0.0.1", spider.command[2])
            self.assertIn("OPENSSL-LISTEN:18080", spider_tls.command[1])
            self.assertEqual("TCP4:127.0.0.1:18080", spider_tls.command[2])
            self.assertEqual("ws-001", spider_tls.network_namespace)
            self.assertFalse(any(c.name == "expose-spider" for c in manager.components()))

    def test_unit_names_are_instance_scoped(self):
        self.assertEqual("ws-007-smithproxy.service",
                         WorkspaceRuntime(7).unit_name("smithproxy"))

    @patch("saslik.components._run")
    def test_down_stops_whole_slice(self, run):
        with tempfile.TemporaryDirectory() as directory:
            manager = SystemdComponents(Path(directory), "lab1")
            # The slice test must never inspect or signal real host processes.
            with patch.object(manager, "_stop_stale_forwarders"):
                manager.down()
        first = run.call_args_list[0].args[0]
        self.assertEqual(["systemctl", "stop", "ws-001.slice"], first)

    @patch("saslik.components._run")
    def test_selective_spider_stop_does_not_touch_smithproxy(self, run):
        with tempfile.TemporaryDirectory() as directory:
            SystemdComponents(Path(directory), "lab1").stop_component("spider")
        commands = [call.args[0] for call in run.call_args_list]
        self.assertTrue(any("ws-001-spider.service" in command for command in commands))
        self.assertTrue(any("ws-001-frontend.service" in command for command in commands))
        self.assertTrue(any("ws-001-frontend-tls.service" in command for command in commands))
        self.assertFalse(any("smithproxy" in " ".join(command) for command in commands))

    def test_runtime_has_no_profile_dimension(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = SystemdComponents(Path(directory), "lab1")
        self.assertFalse(hasattr(manager, "profile"))

    def test_stale_forwarder_match_is_specific_to_saslik_topology(self):
        match = SystemdComponents(Path("/tmp/test"), "lab1")._saslik_forwarder_command
        self.assertTrue(match(
            "socat TCP4-LISTEN:20000,bind=0.0.0.0,reuseaddr,fork "
            "TCP4:10.240.0.2:55580"
        ))
        self.assertTrue(match(
            "socat OPENSSL-LISTEN:15174,bind=0.0.0.0,reuseaddr,fork "
            "TCP4:127.0.0.1:25174"
        ))
        self.assertFalse(match("socat TCP4-LISTEN:55000 TCP4:192.0.2.8:55000"))
        self.assertFalse(match("python -m http.server 55000"))

    def test_smithproxy_restarts_after_unexpected_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            state = lab / "state"
            state.mkdir()
            (state / "state.env").write_text(
                "SMITHPROXY_API_URL=https://10.240.0.2:55580\n"
                "SMITHPROXY_CALLBACK_URL=http://127.0.0.1:18080/webhook\n"
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
                "SMITHPROXY_API_URL=https://10.240.0.2:55580\n"
                "SMITHPROXY_CALLBACK_URL=http://127.0.0.1:18080/webhook\n"
                "SMITHPROXY_API_KEY=key\nSPIDER_TOKEN=token\n",
                encoding="utf-8",
            )
            manager = SystemdComponents(lab, "lab1", "192.0.2.10")
            expose = [component for component in manager.components()
                      if component.name.startswith("expose-")]
        self.assertEqual(["expose-proxy"], [component.name for component in expose])
        self.assertIn("bind=0.0.0.0", expose[0].command[1])

    def test_pcap_viewer_uses_workspace_local_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            state = lab / "state"
            state.mkdir()
            (state / "state.env").write_text(
                "SMITHPROXY_API_URL=https://10.240.0.2:55580\n"
                "SMITHPROXY_CALLBACK_URL=http://127.0.0.1:18080/webhook\n"
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
        self.assertIn("25174", component.command)
        relay = next(item for item in components if item.name == "pcap-viewer-tls")
        self.assertIn("OPENSSL-LISTEN:15174", relay.command[1])
        self.assertEqual("TCP4:127.0.0.1:25174", relay.command[2])
        self.assertEqual("ws-001", component.network_namespace)
        self.assertEqual("ws-001", storage.network_namespace)
        self.assertEqual("ws-001", relay.network_namespace)
        self.assertIn("--no-browser", component.command)
        self.assertIn("--base-path", component.command)
        self.assertIn("/ws001/viewer/", component.command)
        self.assertIn(str(state), storage.command)
        self.assertIn("--watch-root", storage.command)
        self.assertIn("15175", storage.command)

    @patch("socket.create_connection")
    @patch("saslik.components.urllib.request.urlopen")
    @patch("saslik.components._state_env", return_value={
        "SMITHPROXY_API_URL": "https://10.240.0.2:55580",
        "SMITHPROXY_API_KEY": "test",
    })
    def test_readiness_probes_viewer_through_workspace_tls_relay(
            self, _state, urlopen, create_connection):
        response = MagicMock()
        response.__enter__.return_value = response
        urlopen.return_value = response
        create_connection.return_value.__enter__.return_value = MagicMock()
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            executable = lab / "runtime/pcap-viewer-venv/bin/capture-viewer"
            executable.parent.mkdir(parents=True)
            executable.touch()
            SystemdComponents(lab, "lab1")._wait_ready({"pcap-viewer"})
        urls = [call.args[0].full_url for call in urlopen.call_args_list]
        self.assertIn("https://10.240.0.2:15174/readyz", urls)
        viewer_request = next(call.args[0] for call in urlopen.call_args_list
                              if call.args[0].full_url.endswith(":15174/readyz"))
        self.assertEqual("127.0.0.1", viewer_request.get_header("Host"))
        self.assertNotIn("http://127.0.0.1:25174/readyz", urls)
        self.assertNotIn("http://10.240.0.2:25174/readyz", urls)

    def test_pcap_viewer_receives_workspace_ipinfo_token(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            state = lab / "state"
            state.mkdir()
            (state / "state.env").write_text(
                "SMITHPROXY_API_URL=https://10.240.0.2:55580\n"
                "SMITHPROXY_CALLBACK_URL=http://127.0.0.1:18080/webhook\n"
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
            sift_component = next(item for item in manager.components()
                                  if item.name == "sift")
            pack = lab / "state/lored/lore-pack.json"
            pack_text = pack.read_text(encoding="utf-8")
        self.assertEqual(("lored", "lored-bridge"),
                         manager.component_group("lored"))
        self.assertEqual(str(executable), component.command[0])
        self.assertIn(str(pack), component.command)
        self.assertIn('"format":"lore-pack/2"', pack_text)
        self.assertTrue(component.restart_on_failure)
        self.assertEqual("ws-001", component.network_namespace)
        self.assertIsNone(component.required_feature)

        self.assertIn("--lored-url", sift_component.command)
        self.assertIn("http://127.0.0.1:8091/v1/query", sift_component.command)

    @patch("saslik.components._state_env", return_value={
        "SMITHPROXY_API_URL": "https://localhost:55580",
        "SMITHPROXY_CALLBACK_URL": "http://localhost:18080/webhook",
        "SMITHPROXY_API_KEY": "test", "SPIDER_TOKEN": "test",
    })
    def test_workspace_services_share_one_network_namespace(self, _state):
        with tempfile.TemporaryDirectory() as directory:
            components = SystemdComponents(Path(directory), "workspace").components()
        host_ingress = {item.name for item in components
                        if item.network_namespace is None}
        self.assertTrue(host_ingress)
        self.assertTrue(all(name.startswith("expose-") for name in host_ingress))
        self.assertEqual(
            "ws-001-probe",
            next(item for item in components if item.name == "e2e-probe").network_namespace,
        )
        workspace_services = [item for item in components
                              if item.name != "e2e-probe" and
                              not item.name.startswith("expose-")]
        self.assertTrue(workspace_services)
        self.assertTrue(all(item.network_namespace == "ws-001"
                            for item in workspace_services))

    def test_generated_host_callbacks_migrate_to_workspace_loopback(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            state = lab / "state"
            state.mkdir()
            env = state / "state.env"
            config = state / "smithproxy.cfg"
            env.write_text(
                "SMITHPROXY_CALLBACK_URL=http://192.0.2.1:18080/webhook\n",
                encoding="utf-8",
            )
            config.write_text(
                'url = "http://192.0.2.1:18080/webhook";\n'
                'sift_url = "http://192.0.2.1:18081/webhook";\n'
                'custom = "http://192.0.2.8/webhook";\n',
                encoding="utf-8",
            )
            SystemdComponents(lab, "workspace")._migrate_internal_endpoints()
            migrated_env = env.read_text(encoding="utf-8")
            migrated_config = config.read_text(encoding="utf-8")
        self.assertIn("http://127.0.0.1:18080/webhook", migrated_env)
        self.assertIn("http://192.0.2.1:18080/webhook", migrated_config)
        self.assertIn("http://127.0.0.1:18081/webhook", migrated_config)
        self.assertIn("http://192.0.2.8/webhook", migrated_config)

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
                network_namespace="ws-001",
                bind_paths=((capture_path, Path("/var/smithproxy/data")),),
            ))
            capture_path_created = capture_path.is_dir()
        command = run.call_args_list[-1].args[0]
        self.assertIn("--unit=ws-001-smithproxy.service", command)
        self.assertIn("--slice=ws-001.slice", command)
        self.assertIn("--property=KillMode=control-group", command)
        self.assertIn("--property=NetworkNamespacePath=/run/netns/ws-001", command)
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
