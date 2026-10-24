import io
import unittest
import urllib.error
from email.message import Message
from unittest.mock import patch

from saslik.dev_queries import run_query


class Response:
    status = 200
    headers = Message()

    def __init__(self, body: bytes):
        self.body = io.BytesIO(body)
        self.headers["Content-Type"] = "application/json"

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size: int) -> bytes:
        return self.body.read(size)


class DevQueryTests(unittest.TestCase):
    @patch("saslik.dev_queries.urllib.request.urlopen")
    def test_json_response_is_returned_as_a_structure(self, urlopen):
        urlopen.return_value = Response(b'{"flows": 12, "nested": {"ok": true}}')

        value = run_query("sift-stats")

        self.assertTrue(value["ok"])
        self.assertEqual("json", value["kind"])
        self.assertEqual(12, value["result"]["flows"])
        self.assertEqual("http://127.0.0.1:18081/api/stats",
                         urlopen.call_args.args[0].full_url)

    def test_unknown_query_cannot_select_an_arbitrary_url(self):
        with self.assertRaisesRegex(ValueError, "Neznámý"):
            run_query("http://example.test/private")

    @patch("saslik.dev_queries.urllib.request.urlopen")
    def test_plain_text_response_is_preserved(self, urlopen):
        response = Response(b"ready\n")
        response.headers.replace_header("Content-Type", "text/plain")
        urlopen.return_value = response

        value = run_query("lored-health")

        self.assertEqual("text", value["kind"])
        self.assertEqual("ready\n", value["result"])


if __name__ == "__main__":
    unittest.main()
