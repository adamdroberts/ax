"""RFC 3986 / RFC 9110 URI-reference metadata admission and preservation."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cmd/ax-mcp-proxy"))
import ax_mcp_proxy as proxy
from test_http_protocol import FakeOpener, FakeResponse, WireSocket

CASES = json.loads((ROOT / "pkg/security/egress/testdata/uri_reference_cases.json").read_text())["responses"]


class TestURIReferences(unittest.TestCase):
    def server(self, opener):
        engine = proxy.SnortEngine()
        engine.load_rules('drop tcp any any -> any any (content:"forbidden-marker"; sid:1;)')
        server = proxy.MCPServer(engine, allowed_origins=["https://api.example.com"], opener=opener)
        captured = []
        server._send_response = lambda request_id, result: captured.append(result)
        return server, captured

    def test_parsed_uri_contract(self):
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
                    for field, value in case["headers"]:
                        self.assertEqual(result["header_values"][field.lower()], [value])
                else:
                    self.assertFalse(response.reads, "invalid headers reached the body reader")
                    self.assertEqual(server.response_bytes, 0)

    def test_wire_uri_before_mcp_delivery(self):
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

    def test_mime_uri_metadata_is_separate(self):
        for field in ("Location", "Content-Location"):
            with self.subTest(field=field):
                body = ("--b\r\nContent-Range: bytes 0-0/1\r\n" + field + ": (comment) /part (comment)\r\n\r\na\r\n--b--\r\n").encode("ascii")
                proxy.validate_multipart_ranges(body, b"b")

    def test_empty_internal_uri_fields(self):
        for field in ("location", "content-location"):
            with self.subTest(field=field), self.assertRaises(proxy.ProtocolPolicyError):
                proxy.validate_response_metadata({field: []})

    def test_request_uri_before_inspection(self):
        corpus = json.loads((ROOT / "pkg/security/egress/testdata/uri_reference_cases.json").read_text())
        for case in corpus["requests"]:
            with self.subTest(name=case["name"]):
                opener = FakeOpener()
                server, captured = self.server(opener)
                server._execute_http_request(1, case["arguments"])
                self.assertEqual(not captured[-1]["isError"], case["accepted"])
                self.assertEqual(len(opener.calls), int(case["accepted"]))
                if case["accepted"]:
                    request = opener.calls[0][0]
                    self.assertEqual(request.full_url, case["arguments"]["url"])
                    self.assertEqual({k.lower(): v for k, v in request.header_items()}["content-location"], case["arguments"]["headers"]["Content-Location"])
                server._execute_check_payload(2, case["arguments"])
                self.assertEqual(not json.loads(captured[-1]["content"][0]["text"])["blocked"], case["accepted"])
                if not case["accepted"]:
                    self.assertEqual(server.inspected_bytes, 0)


if __name__ == "__main__":
    unittest.main()
