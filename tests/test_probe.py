import socket
import struct
import unittest
from unittest.mock import patch

from saslik.probe import parse_a_response, proxy_probe


class ProbeTests(unittest.TestCase):
    def test_parses_compressed_a_answer(self):
        query_id = 0x5341
        question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("192.0.2.9")
        packet = struct.pack("!HHHHHH", query_id, 0x8180, 1, 1, 0, 0) + question + answer
        self.assertEqual(["192.0.2.9"], parse_a_response(packet, query_id))

    def test_rejects_wrong_transaction(self):
        packet = struct.pack("!HHHHHH", 1, 0x8180, 0, 0, 0, 0)
        with self.assertRaisesRegex(ValueError, "neodpovídá"):
            parse_a_response(packet, 2)

    @patch("saslik.probe.subprocess.run")
    def test_explicit_proxy_probe_uses_requested_proxy(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = "200"
        run.return_value.stderr = ""
        result = proxy_probe("https://example.com/", "socks5h://10.254.78.1:1080",
                             "SOCKS5", insecure=True)
        command = run.call_args.args[0]
        self.assertEqual("ok", result["state"])
        self.assertEqual("socks5h://10.254.78.1:1080",
                         command[command.index("--proxy") + 1])
        self.assertIn("--insecure", command)


if __name__ == "__main__":
    unittest.main()
