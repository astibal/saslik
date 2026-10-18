import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from saslik.debug import (component_binary, debug_unit, gdb_client_arguments,
                          start_gdbserver)


class DebugTests(unittest.TestCase):
    def test_debug_unit_is_stable(self):
        self.assertEqual("saslik-lab-1-gdb-smithproxy.service",
                         debug_unit("lab.1", "smithproxy"))

    def test_component_binary_requires_existing_workspace_file(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            binary = lab / "build/smithproxy/smithproxy"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"binary")
            self.assertEqual(binary, component_binary(lab, "smithproxy"))

    def test_gdb_client_uses_non_disruptive_lab_defaults(self):
        command = gdb_client_arguments("gdb", Path("/tmp/smithproxy"), 23450)
        expressions = [command[index + 1] for index, value in enumerate(command[:-1])
                       if value == "-ex"]
        self.assertIn("set pagination off", expressions)
        self.assertIn("set confirm off", expressions)
        self.assertIn("set print pretty on", expressions)
        self.assertIn("handle SIGPIPE nostop noprint pass", expressions)
        self.assertEqual("target remote 127.0.0.1:23450", expressions[-1])

    @patch("saslik.debug.subprocess.run")
    @patch("saslik.debug.shutil.which", return_value="/usr/bin/gdbserver")
    @patch("saslik.debug.SystemdComponents.status")
    def test_starts_loopback_only_gdbserver_for_component_pid(
            self, status, which, run):
        status.return_value = {"smithproxy": {"state": "running", "pid": 4321}}
        run.return_value.returncode = 0
        run.return_value.stderr = ""
        with tempfile.TemporaryDirectory() as directory:
            lab = Path(directory)
            binary = lab / "build/smithproxy/smithproxy"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"binary")
            start_gdbserver(lab, "lab1", "127.0.0.1", "smithproxy")
        command = run.call_args_list[-1].args[0]
        self.assertIn("127.0.0.1:23450", command)
        self.assertEqual("4321", command[-1])


if __name__ == "__main__":
    unittest.main()
