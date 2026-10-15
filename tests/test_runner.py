import tempfile
import unittest
from pathlib import Path

from saslik.runner import LabRunner, parse_endpoints, validate_ref


class RunnerTests(unittest.TestCase):
    def test_refs(self):
        self.assertEqual("feature/api-ng", validate_ref("feature/api-ng"))
        for value in ("", "../main", "main;id", " main branch "):
            with self.assertRaises(ValueError):
                validate_ref(value)

    def test_endpoint_parser(self):
        result = parse_endpoints([
            "Spider:", "  UI:      http://helmut:15173/", "  Token:   secret",
            "  HTTP CONNECT: http://10.254.77.2:33128", "  CLI: 10.254.77.2:55000",
        ])
        self.assertEqual("http://helmut:15173/", result["spider_ui"])
        self.assertEqual("http://helmut:15173/test-ca.pem", result["ca_download"])
        self.assertEqual("secret", result["spider_token"])
        self.assertEqual("http://10.254.77.2:33128", result["proxy"])

    def test_nat_is_default_and_does_not_start_pasta(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = LabRunner(Path(directory))
            runner.spider.mkdir(parents=True)
            commands = runner._commands("start", "main")
        joined = [" ".join(command) for command in commands]
        self.assertFalse(any("saslik.pasta snapshot" in command for command in joined))
        self.assertFalse(any("saslik.pasta up" in command for command in joined))
        self.assertFalse(any("run-test-" in command for command in joined))

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
