"""Representation digests cover selected bytes, not transfer or MIME framing."""
import base64
import hashlib
import json
import unittest
from unittest.mock import patch
from test_http_protocol import ROOT, FakeOpener, FakeResponse, WireSocket, proxy


def corpus():
    return json.loads((ROOT / "pkg/security/egress/testdata/representation_digest_cases.json").read_text())


class RepresentationDigestTests(unittest.TestCase):
    def test_representation_capacity_and_preserved_fields(self):
        body = b"x" * proxy.MAX_RESPONSE_BYTES
        value = "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"
        server = proxy.MCPServer(proxy.SnortEngine(), opener=FakeOpener())
        result = server._response_data(FakeResponse(body, headers=[("Repr-Digest", value)]), method="GET")
        self.assertEqual(result["body"].encode(), body)
        with self.assertRaises(proxy.ProtocolPolicyError):
            server._response_data(FakeResponse(body[:-1] + b"y", headers=[("Repr-Digest", value)]), method="GET")
        with self.assertRaises(proxy.ProtocolPolicyError):
            proxy.validate_response_metadata({"repr-digest": []})
        body = b"ok"
        values = [algorithm + "=:" + base64.b64encode(factory(body).digest()).decode() + ":"
                  for algorithm, factory in [("sha-256", hashlib.sha256), ("sha-512", hashlib.sha512)]]
        response = FakeResponse(body, headers=[("Repr-Digest", values[0]), ("rEpR-DiGeSt", values[1])])
        result = server._response_data(response, method="GET")
        self.assertEqual([v for k, v in result["headers"].items() if k.lower() == "repr-digest"], [", ".join(values)])
        self.assertEqual(result["header_values"]["repr-digest"], values)

    def test_request_representation_before_inspection(self):
        for case in corpus()["requests"]:
            with self.subTest(name=case["name"]):
                opener, captured = FakeOpener(), []
                server = proxy.MCPServer(proxy.SnortEngine(), allowed_origins=["https://api.example.com"], opener=opener)
                server._send_response = lambda request_id, result: captured.append(result)
                with patch.object(server.engine, "inspect", wraps=server.engine.inspect) as inspect:
                    server._execute_http_request(1, case["arguments"])
                    self.assertEqual(not captured[-1]["isError"], case["accepted"])
                    self.assertEqual(len(opener.calls), int(case["accepted"]))
                    if case["accepted"]:
                        self.assertEqual(opener.calls[0][0].data or b"", case["arguments"]["body"].encode())
                    server._execute_check_payload(2, case["arguments"])
                    self.assertEqual(not json.loads(captured[-1]["content"][0]["text"])["blocked"], case["accepted"])
                    self.assertEqual(inspect.call_count, 2 * int(case["accepted"]))

    def test_response_representation_before_delivery(self):
        for case in corpus()["responses"]:
            with self.subTest(name=case["name"]):
                wire, body = base64.b64decode(case["wire_base64"]), base64.b64decode(case["body_base64"])
                calls, captured = [], []
                class Opener:
                    def open(self, request, timeout):
                        calls.append(request)
                        response = proxy.StrictHTTPResponse(WireSocket(wire), method=request.get_method())
                        response.begin()
                        response.code = response.status
                        return response
                server = proxy.MCPServer(proxy.SnortEngine(), allowed_origins=["https://api.example.com"], opener=Opener())
                server._send_response = lambda request_id, result: captured.append(result)
                server._execute_http_request(1, {"url": "https://api.example.com/digest",
                                                "method": case["method"], "headers": case["request_headers"]})
                self.assertEqual(len(calls), 1)
                try:
                    result = json.loads(captured[-1]["content"][0]["text"])
                    delivered = result.get("status_code") == case["status"]
                except ValueError:
                    delivered = False
                self.assertEqual(delivered, case["accepted"])
                if delivered:
                    self.assertEqual(result["body"].encode(), body)
                if case["rejection_stage"] == "headers":
                    self.assertEqual(server.response_bytes, 0)
                elif not case["interim"] and case["method"] != "HEAD" and case["status"] not in (204, 304):
                    self.assertEqual(server.response_bytes, len(wire.split(b"\r\n\r\n", 1)[1]))


if __name__ == "__main__":
    unittest.main()
