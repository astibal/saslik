import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from saslik.components import Component, SystemdComponents, unit_name


class ComponentTests(unittest.TestCase):
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

    def test_runtime_has_no_profile_dimension(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = SystemdComponents(Path(directory), "lab1")
        self.assertFalse(hasattr(manager, "profile"))

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
        self.assertIn("15174", component.command)
        self.assertIn("--no-browser", component.command)
        self.assertIn(str(state), storage.command)
        self.assertIn("--watch-root", storage.command)
        self.assertIn("15175", storage.command)

    @patch("saslik.components._run")
    def test_component_is_started_as_transient_service_in_lab_slice(self, run):
        with tempfile.TemporaryDirectory() as directory:
            manager = SystemdComponents(Path(directory), "lab1")
            manager._start_component(Component(
                "smithproxy", ("/bin/true",), Path(directory) / "smithproxy.log",
                network_namespace="sxp-test",
            ))
        command = run.call_args_list[-1].args[0]
        self.assertIn("--unit=saslik-lab1-smithproxy.service", command)
        self.assertIn("--slice=saslik-lab1.slice", command)
        self.assertIn("--property=KillMode=control-group", command)
        self.assertIn("--property=NetworkNamespacePath=/run/netns/sxp-test", command)


if __name__ == "__main__":
    unittest.main()
