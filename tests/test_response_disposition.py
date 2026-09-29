"""HTTP Content-Disposition syntax, decoding, and filename admission."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cmd/ax-mcp-proxy"))
import ax_mcp_proxy as proxy
from test_http_protocol import FakeOpener, FakeResponse, WireSocket

CASES = json.loads((ROOT / "pkg/security/egress/testdata/content_disposition_cases.json").read_text())["cases"]


class TestResponseDisposition(unittest.TestCase):
    def server(self, opener):
        engine = proxy.SnortEngine()
        engine.load_rules('drop tcp any any -> any any (content:"forbidden-marker"; sid:1;)')
        server = proxy.MCPServer(engine, allowed_origins=["https://api.example.com"], opener=opener)
        captured = []
        server._send_response = lambda request_id, result: captured.append(result)
        return server, captured

    def test_parsed_disposition_contract(self):
        for case in CASES:
            with self.subTest(name=case["name"]):
                response = FakeResponse(headers=[*case["headers"], ("Content-Length", "2")])
                server, _ = self.server(FakeOpener(response))
                try:
                    result = server._response_data(response, method="GET")
                    accepted = True
                except ValueError:
                    accepted = False
                self.assertEqual(accepted, case["accepted"])
                if accepted:
                    self.assertEqual(result["body"], "ok")
                else:
                    self.assertFalse(response.reads, "invalid headers reached the body reader")
                    self.assertEqual(server.response_bytes, 0)

    def test_wire_disposition_before_mcp_delivery(self):
        for case in CASES:
            fields = "".join(name + ": " + value + "\r\n" for name, value in case["headers"])
            for stage in ("final", "interim"):
                with self.subTest(name=case["name"], stage=stage):
                    wire = "HTTP/1.1 200 OK\r\n" + fields + "Content-Length: 2\r\n\r\nok"
                    if stage == "interim":
                        wire = "HTTP/1.1 103 Early Hints\r\n" + fields + "\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                    class Opener:
                        def open(self, request, timeout):
                            response = proxy.StrictHTTPResponse(WireSocket(wire.encode("ascii")), method="GET")
                            response.begin()
                            response.code = response.status
                            return response
                    server, captured = self.server(Opener())
                    server._execute_http_request(1, {"url": "https://api.example.com/v1"})
                    self.assertEqual(not captured[-1]["isError"], case["accepted"])
                    if case["accepted"]:
                        result = json.loads(captured[-1]["content"][0]["text"])
                        self.assertEqual(result["body"], "ok")
                        self.assertEqual(server.response_bytes, 2)
                    else:
                        self.assertEqual(server.response_bytes, 0)

    def test_mime_part_disposition_is_separate(self):
        for value in ("attachment; filename*0*=UTF-8''report; filename*1*=.txt", "x-mime-extension; opaque"):
            with self.subTest(value=value):
                body = ("--b\r\nContent-Range: bytes 0-0/1\r\nContent-Disposition: " + value + "\r\n\r\na\r\n--b--\r\n").encode("ascii")
                proxy.validate_multipart_ranges(body, b"b")


if __name__ == "__main__":
    unittest.main()
