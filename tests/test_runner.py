import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from saslik.runner import LabRunner, ensure_friendly_data_link, parse_endpoints, runtime_state, validate_ref


class RunnerTests(unittest.TestCase):
    def test_runtime_state_requires_the_dataplane(self):
        healthy = {name: {"state": "running"} for name in
                   ("smithproxy", "spider", "sift")}
        self.assertEqual(("running", []), runtime_state(healthy))
        healthy["smithproxy"] = {"state": "failed"}
        self.assertEqual(("degraded", ["smithproxy"]), runtime_state(healthy))
        healthy["smithproxy"] = {"state": "starting"}
        self.assertEqual(("recovering", ["smithproxy"]), runtime_state(healthy))

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
            "Spider:", "  UI:      http://helmut:15173/", "  Token:   secret",
            "  HTTP CONNECT: http://10.254.77.2:33128", "  CLI: 10.254.77.2:55000",
            "  PCAP Viewer: http://127.0.0.1:15174/",
        ])
        self.assertEqual("http://helmut:15173/", result["spider_ui"])
        self.assertEqual("http://helmut:15173/test-ca.pem", result["ca_download"])
        self.assertNotIn("spider_token", result)
        self.assertEqual("http://10.254.77.2:33128", result["proxy"])
        self.assertEqual("http://127.0.0.1:15174/", result["pcap_viewer"])

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

    def test_binary_bundle_still_refreshes_pcap_viewer(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = LabRunner(Path(directory))
            marker = runner.lab / "state/binary-bundle.json"
            marker.parent.mkdir(parents=True)
            marker.write_text("{}", encoding="utf-8")
            commands = [" ".join(command) for command in runner._commands("start", "main")]
        self.assertTrue(any("saslik.workspace viewer-sync" in command for command in commands))
        self.assertTrue(any("saslik.workspace viewer-install" in command for command in commands))
        self.assertFalse(any("saslik.workspace build" in command for command in commands))

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
        namespace_up = next(i for i, command in enumerate(joined) if "saslik.routing namespace-up" in command)
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
