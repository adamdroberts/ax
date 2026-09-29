"""W3C XML grammar and bounded response admission through MCP delivery."""
import base64
import io
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cmd/ax-mcp-proxy"))
import ax_mcp_proxy as proxy


class WireSocket:
    def __init__(self, wire):
        self.wire = wire

    def makefile(self, mode):
        return io.BytesIO(self.wire)


def response_wire(document, layout):
    status, fields, body, headers = 200, "Content-Type: application/xml\r\n", document, {}
    if layout != "ordinary":
        status, headers["Range"] = 206, "bytes=0-"
        fields += f"Content-Range: bytes 0-{len(document)-1}/{len(document)}\r\n"
    if layout == "multipart":
        cut = len(document)//2
        while document[cut] & 0xC0 == 0x80:
            cut += 1
        parts = []
        for first, chunk in ((0, document[:cut]), (cut, document[cut:])):
            parts.append(f"--xmlparts\r\nContent-Type: application/xml\r\nContent-Range: bytes {first}-{first+len(chunk)-1}/{len(document)}\r\n\r\n".encode()+chunk+b"\r\n")
        body = b"".join(parts)+b"--xmlparts--\r\n"
        fields, headers["Range"] = "Content-Type: multipart/byteranges; boundary=xmlparts\r\n", "bytes=0-0,1-"
    wire = f"HTTP/1.1 {status} OK\r\n{fields}Content-Length: {len(body)}\r\n\r\n".encode()+body
    return wire, body, headers


class TestXMLResponses(unittest.TestCase):
    def test_xml_media_and_range_selection(self):
        cases = json.loads((ROOT/"pkg/security/egress/testdata/xml_response_flow_cases.json").read_text())["cases"]
        for case in cases:
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
                engine = proxy.SnortEngine()
                engine.load_rules('drop tcp any any -> any any (content:"forbidden-marker"; sid:1;)')
                server = proxy.MCPServer(engine, allowed_origins=["https://api.example.com"], opener=Opener())
                server._send_response = lambda request_id, result: captured.append(result)
                server._execute_http_request(1, {"url":"https://api.example.com/xml", "method":case["method"], "headers":case["request_headers"]})
                self.assertEqual(len(calls),1)
                self.assertEqual(not captured[-1]["isError"],case["accepted"],captured[-1])
                if case["accepted"]:
                    result=json.loads(captured[-1]["content"][0]["text"])
                    self.assertEqual(result["body"].encode(),body)
                self.assertEqual(server.response_bytes,len(wire.split(b"\r\n\r\n",1)[1]))

    def test_large_xml_and_early_budget(self):
        for name, prefix, suffix in (("text",b"<r>",b"</r>"),("cdata",b"<r><![CDATA[",b"]]></r>")):
            data=prefix+b"a"*(proxy.MAX_RESPONSE_BYTES-len(prefix)-len(suffix))+suffix
            with self.subTest(name=name,valid=True):
                proxy.validate_response_xml(data)
            with self.subTest(name=name,valid=False):
                with self.assertRaisesRegex(proxy.ProtocolPolicyError,"XML interoperability policy"):
                    proxy.validate_response_xml(data[:-1]+b"!")
        class Oversized(bytes):
            def decode(self,*args,**kwargs):
                raise AssertionError("oversized XML was decoded before admission")
        with self.subTest(name="oversized-before-decode"):
            with self.assertRaisesRegex(proxy.ProtocolPolicyError,"XML interoperability policy"):
                proxy.validate_response_xml(Oversized(b"x"*(proxy.MAX_RESPONSE_BYTES+1)))

    def test_xml_before_tool_delivery(self):
        cases = json.loads((ROOT/"pkg/security/egress/testdata/xml_response_cases.json").read_text())["cases"]
        for case in cases:
            document = base64.b64decode(case["document_base64"])
            for layout in ("ordinary", "single", "multipart"):
                if layout != "ordinary" and len(document) < 2:
                    continue
                with self.subTest(name=case["name"], layout=layout):
                    wire, body, headers = response_wire(document, layout)
                    calls, captured = [], []
                    class Opener:
                        def open(self, request, timeout):
                            calls.append(request)
                            response = proxy.StrictHTTPResponse(WireSocket(wire), method=request.get_method())
                            response.begin()
                            response.code = response.status
                            return response
                    engine = proxy.SnortEngine()
                    engine.load_rules('drop tcp any any -> any any (content:"forbidden-marker"; sid:1;)')
                    server = proxy.MCPServer(engine, allowed_origins=["https://api.example.com"], opener=Opener())
                    server._send_response = lambda request_id, result: captured.append(result)
                    server._execute_http_request(1, {"url":"https://api.example.com/xml", "headers":headers})
                    self.assertEqual(len(calls),1)
                    self.assertEqual(not captured[-1]["isError"], case["accepted"], captured[-1]["content"][0]["text"][:200])
                    if case["accepted"]:
                        result=json.loads(captured[-1]["content"][0]["text"])
                        self.assertEqual(result["body"].encode(),body)
                    else:
                        self.assertIn("XML interoperability policy", captured[-1]["content"][0]["text"])
                    self.assertEqual(server.response_bytes,len(body))


if __name__ == '__main__':
    unittest.main()
