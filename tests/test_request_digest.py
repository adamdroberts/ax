"""Request integrity must be checked before inspection and transport."""
import base64
import hashlib
import json
import unittest
from unittest.mock import patch
from test_http_protocol import ROOT, FakeOpener, proxy


class RequestDigestTests(unittest.TestCase):
    def test_request_digest_capacity_and_signatures(self):
        def arguments(body, hashed=None):
            raw = (body if hashed is None else hashed).encode()
            value = "sha-256=:" + base64.b64encode(hashlib.sha256(raw).digest()).decode() + ":"
            return {"url": "https://api.example.com", "method": "POST", "body": body,
                    "headers": {"Content-Type": "text/plain", "Content-Digest": value}}

        maximum = "x" * proxy.MAX_BODY_BYTES
        for name, args, accepted in [
            ("maximum", arguments(maximum), True),
            ("altered-last-byte", arguments(maximum[:-1] + "y", maximum), False),
            ("oversized", arguments(maximum + "x"), False),
        ]:
            with self.subTest(name=name):
                if accepted:
                    self.assertEqual(proxy._strict_request_args(args)[3], maximum)
                else:
                    with self.assertRaises(proxy.ProtocolPolicyError):
                        proxy._strict_request_args(args)
        opener, captured = FakeOpener(), []
        engine = proxy.SnortEngine()
        engine.load_rules('drop tcp any any -> any any (content:"forbidden-marker"; sid:1;)')
        server = proxy.MCPServer(engine, allowed_origins=["https://api.example.com"], opener=opener)
        server._send_response = lambda request_id, result: captured.append(result)
        args = arguments("forbidden-marker")
        server._execute_http_request(1, args)
        self.assertTrue(captured[-1]["isError"])
        self.assertEqual(opener.calls, [])
        server._execute_check_payload(2, args)
        diagnostic = json.loads(captured[-1]["content"][0]["text"])
        self.assertTrue(diagnostic["blocked"])
        self.assertEqual(diagnostic["rule_sid"], 1)

    def test_request_digest_before_inspection_and_dispatch(self):
        cases = json.loads((ROOT / "pkg/security/httpguard/testdata/request_digest_cases.json").read_text())["cases"]
        for case in cases:
            with self.subTest(name=case["name"]):
                opener, captured = FakeOpener(), []
                server = proxy.MCPServer(proxy.SnortEngine(), allowed_origins=["https://api.example.com"], opener=opener)
                server._send_response = lambda request_id, result: captured.append(result)
                with patch.object(server.engine, "inspect", wraps=server.engine.inspect) as inspect:
                    server._execute_http_request(1, case["arguments"])
                    self.assertEqual(not captured[-1]["isError"], case["accepted"])
                    self.assertEqual(len(opener.calls), int(case["accepted"]))
                    if case["accepted"]:
                        request = opener.calls[0][0]
                        self.assertEqual(request.data or b"", case["arguments"]["body"].encode())
                    server._execute_check_payload(2, case["arguments"])
                    diagnostic = json.loads(captured[-1]["content"][0]["text"])
                    self.assertEqual(not diagnostic["blocked"], case["accepted"])
                    self.assertEqual(inspect.call_count, 2 * int(case["accepted"]))


if __name__ == "__main__":
    unittest.main()
