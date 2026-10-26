import tempfile
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from saslik.runner import Job, LabRunner, ensure_friendly_data_link, parse_endpoints, runtime_state, validate_ref
from saslik.runtime import WorkspaceRuntime


class RunnerTests(unittest.TestCase):
    def test_runtime_state_requires_the_dataplane(self):
        healthy = {name: {"state": "running"} for name in
                   ("smithproxy", "spider", "sift")}
        self.assertEqual(("running", []), runtime_state(healthy))
        healthy["smithproxy"] = {"state": "failed"}
        self.assertEqual(("degraded", ["smithproxy"]), runtime_state(healthy))
        healthy["smithproxy"] = {"state": "starting"}
        self.assertEqual(("recovering", ["smithproxy"]), runtime_state(healthy))

    def test_runtime_state_requires_lored_when_built(self):
        healthy = {name: {"state": "running"} for name in
                   ("smithproxy", "spider", "sift", "lored")}
        self.assertEqual(("running", []), runtime_state(healthy, lored_enabled=True))
        healthy["lored"] = {"state": "failed"}
        self.assertEqual(("degraded", ["lored"]),
                         runtime_state(healthy, lored_enabled=True))

    def test_friendly_data_link_is_safe_and_idempotent(self):
        with tempfile.TemporaryDirectory() as directory, patch(
            "saslik.runner.Path.home", return_value=Path(directory)
        ):
            target = Path(directory) / ".local/share/saslik"
            link = ensure_friendly_data_link(target)
            self.assertEqual(Path(directory) / "Saslik", link)
            self.assertEqual(target.resolve(), link.resolve())
            self.assertEqual(link, ensure_friendly_data_link(target))

    def test_friendly_data_link_never_replaces_existing_path(self):
        with tempfile.TemporaryDirectory() as directory, patch(
            "saslik.runner.Path.home", return_value=Path(directory)
        ):
            link = Path(directory) / "Saslik"
            link.mkdir()
            self.assertIsNone(ensure_friendly_data_link(Path(directory) / "data"))
            self.assertTrue(link.is_dir())

    def test_refs(self):
        self.assertEqual("feature/api-ng", validate_ref("feature/api-ng"))
        for value in ("", "../main", "main;id", " main branch "):
            with self.assertRaises(ValueError):
                validate_ref(value)

    def test_endpoint_parser(self):
        result = parse_endpoints([
            "Spider:", "  UI:      https://helmut:15173/", "  Token:   secret",
            "  Backend: https://helmut:18080",
            "  HTTP CONNECT: http://10.240.0.2:33128", "  CLI: 10.240.0.2:55000",
            "  PCAP Viewer: https://127.0.0.1:15174/",
        ])
        self.assertEqual("https://helmut:15173/", result["spider_ui"])
        self.assertEqual("https://helmut:18080", result["spider_backend"])
        self.assertEqual("https://helmut:15173/test-ca.pem", result["ca_download"])
        self.assertNotIn("spider_token", result)
        self.assertEqual("http://10.240.0.2:33128", result["proxy"])
        self.assertEqual("https://127.0.0.1:15174/", result["pcap_viewer"])

    @patch("saslik.runner.LabRunner._service_status", return_value={})
    @patch("saslik.runner.LabRunner._health_status", return_value={})
    @patch("saslik.runner.WorkspaceRuntime.for_instance",
           return_value=WorkspaceRuntime(1))
    def test_snapshot_reconstructs_workspace_endpoints_without_build_log(
            self, _runtime, _health, _services):
        with tempfile.TemporaryDirectory() as directory:
            runner = LabRunner(Path(directory))
            state = runner.lab / "state"
            state.mkdir(parents=True)
            (state / "smithproxy.cfg").touch()
            snapshot = runner.snapshot()

        self.assertEqual("/ws001/smithproxy-api/",
                         snapshot["endpoints"]["smithproxy_api"])
        self.assertEqual("http://127.0.0.1:20001",
                         snapshot["endpoints"]["proxy"])
        self.assertEqual("/ws001/spider/",
                         snapshot["endpoints"]["spider_ui"])

    def test_nat_is_default_and_does_not_start_pasta(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = LabRunner(Path(directory))
            runner.spider.mkdir(parents=True)
            commands = runner._commands("start", "main")
        joined = [" ".join(command) for command in commands]
        self.assertFalse(any("saslik.pasta snapshot" in command for command in joined))
        self.assertFalse(any("saslik.pasta up" in command for command in joined))
        self.assertFalse(any("saslik.pasta down" in command for command in joined))
        self.assertFalse(any("run-test-" in command for command in joined))

    def test_nat_stop_and_reset_do_not_touch_pasta(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = LabRunner(Path(directory))
            for action in ("stop", "reset"):
                joined = [" ".join(command) for command in runner._commands(action, "main")]
                self.assertFalse(any("saslik.pasta down" in command for command in joined))

    def test_nat_cleans_up_previous_pasta_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = LabRunner(Path(directory))
            state = runner.lab / "state"
            state.mkdir(parents=True)
            (state / "egress").write_text("pasta\n", encoding="ascii")
            joined = [" ".join(command) for command in runner._commands("start", "main")]
        self.assertTrue(any("saslik.pasta down" in command for command in joined))

    def test_workspace_operations_run_as_user(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = LabRunner(Path(directory))
            commands = runner._commands("start", "main")
        workspace_commands = [command for command in commands if "saslik.workspace" in command]
        self.assertTrue(workspace_commands)
        self.assertTrue(all(command[0] != "sudo" for command in workspace_commands))

    def test_binary_bundle_refreshes_independent_components(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = LabRunner(Path(directory), devel=True)
            marker = runner.lab / "state/binary-bundle.json"
            marker.parent.mkdir(parents=True)
            marker.write_text("{}", encoding="utf-8")
            commands = [" ".join(command) for command in runner._commands("start", "main")]
        self.assertTrue(any("saslik.workspace viewer-sync" in command for command in commands))
        self.assertTrue(any("saslik.workspace viewer-install" in command for command in commands))
        self.assertTrue(any("component-sync" in command and "--component lored" in command
                            for command in commands))
        self.assertTrue(any("component-build" in command and "--component lored" in command
                            for command in commands))
        self.assertFalse(any("saslik.workspace build" in command for command in commands))

    def test_lored_is_absent_without_devel_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = LabRunner(Path(directory))
            marker = runner.lab / "state/binary-bundle.json"
            marker.parent.mkdir(parents=True)
            marker.write_text("{}", encoding="utf-8")
            commands = [" ".join(command) for command in runner._commands("start", "main")]
        self.assertFalse(any("lored" in command for command in commands))

    def test_pasta_wraps_runner_network_setup(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = LabRunner(Path(directory), egress="pasta")
            runner.spider.mkdir(parents=True)
            commands = runner._commands("start", "main")
        joined = [" ".join(command) for command in commands]
        snapshot = next(i for i, command in enumerate(joined) if "saslik.pasta snapshot" in command)
        network_up = next(i for i, command in enumerate(joined) if "saslik.network up" in command)
        pasta_up = next(i for i, command in enumerate(joined) if "saslik.pasta up" in command)
        components_up = next(i for i, command in enumerate(joined) if "saslik.components up" in command)
        namespace_up = next(i for i, command in enumerate(joined)
                            if "saslik.routing" in command and "namespace-up" in command)
        self.assertLess(network_up, snapshot)
        self.assertLess(snapshot, pasta_up)
        self.assertLess(pasta_up, namespace_up)
        self.assertLess(namespace_up, components_up)
        self.assertLess(pasta_up, components_up)

    def test_remote_exposure_is_passed_to_component_manager(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = LabRunner(Path(directory), expose_address="0.0.0.0")
            commands = runner._commands("start", "main")
        component_commands = [command for command in commands if "saslik.components" in command]
        self.assertTrue(component_commands)
        self.assertTrue(all("--expose-address" in command and "0.0.0.0" in command
                            for command in component_commands))

    def test_spider_update_builds_and_restarts_only_spider_group(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = LabRunner(Path(directory), instance="lab1")
            commands = [" ".join(command) for command in
                        runner._commands("update-component", "master", component="spider")]
        self.assertEqual(3, len(commands))
        self.assertIn("component-sync", commands[0])
        self.assertIn("--component spider", commands[0])
        self.assertIn("component-build", commands[1])
        self.assertIn("restart-component", commands[2])
        self.assertFalse(any("smithproxy" in command for command in commands))

    def test_viewer_update_stops_pair_before_installing_into_venv(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = LabRunner(Path(directory), instance="lab1")
            commands = [" ".join(command) for command in
                        runner._commands("update-component", "master",
                                         component="pcap-viewer")]
        stop = next(index for index, command in enumerate(commands)
                    if "stop-component" in command)
        install = next(index for index, command in enumerate(commands)
                       if "component-build" in command)
        restart = next(index for index, command in enumerate(commands)
                       if "restart-component" in command)
        self.assertLess(stop, install)
        self.assertLess(install, restart)

    def test_component_control_uses_guardian_without_fresh_sudo(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = LabRunner(Path(directory), instance="lab1")
            calls = []
            runner.component_action = lambda action, component: calls.append(
                (action, component)) or True
            command = ["sudo", "-n", sys.executable, "-m", "saslik.components",
                       "stop-component", runner.lab.as_posix(), "--instance", "lab1",
                       "--component", "pcap-viewer"]
            output = []
            result = runner._run_commands([command], output.append)
        self.assertEqual(0, result)
        self.assertEqual([("stop-component", "pcap-viewer")], calls)
        self.assertEqual(["$ guardian stop-component pcap-viewer"], output)

    @patch("saslik.runner.threading.Thread")
    def test_component_update_keeps_existing_connection_cards(self, thread):
        with tempfile.TemporaryDirectory() as directory:
            runner = LabRunner(Path(directory), instance="lab1")
            runner._job = Job()
            runner._job.lines.extend([
                "Spider:", "  UI: http://127.0.0.1:15173/",
                "  HTTP CONNECT: http://127.0.0.1:33128",
            ])
            runner.start_job("update-component", component="spider")
        self.assertEqual("http://127.0.0.1:15173/", runner._job.endpoints["spider_ui"])
        thread.return_value.start.assert_called_once()

    def test_existing_config_is_never_prepared_or_rewritten(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = LabRunner(Path(directory))
            runner.spider.mkdir(parents=True)
            (runner.lab / "state").mkdir(parents=True)
            (runner.lab / "state/smithproxy.cfg").write_text("user config")
            for action in ("start", "reset"):
                commands = [" ".join(command) for command in runner._commands(action, "main")]
                self.assertFalse(any("saslik.routing prepare" in command for command in commands))
                self.assertFalse(any("run-test-" in command for command in commands))


if __name__ == "__main__":
    unittest.main()
