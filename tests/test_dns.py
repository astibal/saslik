import struct
import unittest

from saslik.dns import DnsLookupError, parse_txt_response


class DnsTests(unittest.TestCase):
    def test_parses_split_txt_strings(self):
        query_id = 0x1234
        question = b"\x07_saslik\x07example\x00" + struct.pack("!HH", 16, 1)
        value = b"v=saslik1;issuer=smithproxy"
        rdata = bytes([10]) + value[:10] + bytes([len(value) - 10]) + value[10:]
        answer = (b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(rdata)) +
                  rdata)
        packet = struct.pack("!HHHHHH", query_id, 0x8180, 1, 1, 0, 0) + question + answer
        self.assertEqual([value.decode()], parse_txt_response(packet, query_id))

    def test_rejects_mismatched_transaction(self):
        packet = struct.pack("!HHHHHH", 2, 0x8180, 0, 0, 0, 0)
        with self.assertRaises(DnsLookupError):
            parse_txt_response(packet, 1)


if __name__ == "__main__":
    unittest.main()
