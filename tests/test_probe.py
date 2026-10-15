import socket
import struct
import unittest

from saslik.probe import parse_a_response


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


if __name__ == "__main__":
    unittest.main()
