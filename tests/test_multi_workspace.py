import tempfile
import unittest
from pathlib import Path

from saslik.components import SystemdComponents


class MultiWorkspaceTopologyTests(unittest.TestCase):
    def _workspace(self, root: Path, name: str, workspace_id: int) -> Path:
        lab = root / name
        state = lab / "state"
        state.mkdir(parents=True)
        (lab / "workspace-id").write_text(f"{workspace_id}\n", encoding="ascii")
        (state / "state.env").write_text(
            f"SMITHPROXY_API_URL=https://10.240.0.{2 + (workspace_id - 1) * 8}:55580\n"
            "SMITHPROXY_CALLBACK_URL=http://127.0.0.1:18080/webhook\n"
            "SMITHPROXY_API_KEY=test\nSPIDER_TOKEN=test\n",
            encoding="utf-8",
        )
        return lab

    def test_two_workspaces_have_disjoint_host_ingress_and_runtime_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = SystemdComponents(self._workspace(root, "one", 1), "one")
            second = SystemdComponents(self._workspace(root, "two", 2), "two")
            first_components = first.components()
            second_components = second.components()

        def listeners(components):
            return {
                item.command[1].split("TCP4-LISTEN:", 1)[1].split(",", 1)[0]
                for item in components
                if item.name.startswith("expose-")
            }

        self.assertTrue(listeners(first_components).isdisjoint(
            listeners(second_components)))
        self.assertEqual("ws-001.slice", first.slice_name)
        self.assertEqual("ws-002.slice", second.slice_name)
        self.assertTrue(all(
            item.network_namespace in {None, "ws-001", "ws-001-probe"}
            for item in first_components
        ))
        self.assertTrue(all(
            item.network_namespace in {None, "ws-002", "ws-002-probe"}
            for item in second_components
        ))


if __name__ == "__main__":
    unittest.main()
