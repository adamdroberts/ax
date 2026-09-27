"""Strict dispatch, RPC, DNS pinning and HTTP wire-boundary regressions."""
import email.message
import io
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cmd/ax-mcp-proxy"))
import ax_mcp_proxy as proxy


class FakeResponse:
    def __init__(self, body=b"ok", headers=None, status=200):
        self.code = status
        self.version = 11
        self.headers = email.message.Message()
        for name, value in headers or [("Content-Length", str(len(body)))]:
            self.headers[name] = value
        self.stream = io.BytesIO(body)
        self.reads = []

    def read(self, size):
        self.reads.append(size)
        return self.stream.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stream.close()


class FakeOpener:
    def __init__(self, response=None):
        self.response = response or FakeResponse()
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        return self.response


class WireSocket:
    def __init__(self, wire):
        self.wire = wire
        self.sent = []
        self.closed = False

    def makefile(self, mode):
        return io.BytesIO(self.wire)

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


class TestHTTPProtocol(unittest.TestCase):
    def server(self, allowed=None, opener=None):
        engine = proxy.SnortEngine()
        engine.load_rules('drop tcp any any -> any any (content:"forbidden-marker"; sid:1;)')
        server = proxy.MCPServer(engine, allowed_origins=allowed, opener=opener)
        captured = []
        server._send_response = lambda request_id, result: captured.append((request_id, result))
        return server, captured

    def policy(self, **kwargs):
        return proxy._strict_request_args({"url": "https://api.example.com/v1", **kwargs})

    def result(self, captured):
        return captured[-1][1]

    def test_shared_cross_runtime_request_policy_cases(self):
        corpus = json.loads((ROOT / "pkg/security/httpguard/testdata/request_cases.json").read_text())
        for case in corpus["cases"]:
            with self.subTest(name=case["name"]):
                try:
                    proxy._strict_request_args(case["arguments"])
                    accepted = True
                except (ValueError, TypeError, OverflowError):
                    accepted = False
                self.assertEqual(accepted, case["accepted"])

    def test_shared_cross_runtime_response_metadata_cases(self):
        corpus = json.loads((ROOT / "pkg/security/egress/testdata/response_metadata_cases.json").read_text())
        self.assertEqual(corpus["version"], 1)
        self.assertEqual(set(corpus["protected_connection_names"]), proxy.RESPONSE_CONNECTION_PROTECTED)
        self.assertEqual(corpus["protected_connection_prefixes"], list(proxy.RESPONSE_CONNECTION_PREFIXES))
        self.assertEqual(set(corpus["singletons"]), proxy.RESPONSE_SINGLETON_HEADERS)
        self.assertEqual(corpus["max_parts"], proxy.MAX_RESPONSE_METADATA_PARTS)
        for case in corpus["cases"]:
            fields = {}
            for name, value in case["headers"]:
                fields.setdefault(name.lower(), []).append(value)
            with self.subTest(name=case["name"]):
                try:
                    proxy.validate_response_metadata(fields)
                    accepted = True
                except ValueError:
                    accepted = False
                self.assertEqual(accepted, case["accepted"])

    def test_methods_bodies_and_unknown_arguments(self):
        for kwargs in ({"method": "get"}, {"method": "CONNECT"}, {"method": []}, {"method": "TRACE"},
                       {"body": "x"}, {"method": "HEAD", "body": "x"}, {"method": "POST", "body": b"x"},
                       {"follow_redirects": True}, {"timeout_seconds": 0.5}):
            with self.subTest(kwargs=kwargs), self.assertRaises((ValueError, TypeError)):
                self.policy(**kwargs)
        for method in proxy.METHODS:
            self.assertEqual(self.policy(method=method)[0], method)

    def test_strict_uri_rejects_ambiguous_forms(self):
        urls = [
            "http://127.1/", "http://2130706433/", "http://0177.0.0.1/", "http://0x7f000001/",
            "http://0x7f.0.0.1/", "http://example.com:080/", "http://example.com:0/",
            "http://example.com:65536/", "http://example.com:/", "http://example.com./",
            "http://[fe80::1%25lo0]/", "http://[2001:DB8::1]/", "http://[2001:0db8::1]/",
            "http://u:p@example.com/", "http://example.com/#", "http://example.com/a\\b",
            "http://example.com/a b", "http://example.com/?a=[]", "http://example.com/{a}",
            "http://example.com/\"x\"", "http://example.com/|", "http://example.com/é",
            "http://example.com/%", "http://example.com/%0a", "http://example.com/%5c",
            "http://example.com/%ff", "http://example.com/%c0%af", "http://example.com/%ed%a0%80",
            "http://example.com/?x=%ff", "http://example%2ecom/", "HTTP://example.com/",
        ]
        for url in urls:
            with self.subTest(url=url), self.assertRaises(ValueError):
                proxy.strict_http_url(url)
        _, origin = proxy.strict_http_url("https://API.Example.com:443/a?x=%E2%9C%93")
        self.assertEqual(origin, ("https", "api.example.com", 443))

    def test_exact_allowed_origins_and_default_deny(self):
        server, captured = self.server()
        with patch.object(server.opener, "open") as opened:
            server._execute_http_request(1, {"url": "https://api.example.com/"})
            opened.assert_not_called()
        self.assertIn("not explicitly allowed", self.result(captured)["content"][0]["text"])
        for url, allowed in (("https://api.example.com/x", True), ("https://API.EXAMPLE.COM:443/x", True),
                             ("http://api.example.com/x", False), ("https://api.example.com:444/x", False),
                             ("https://api.example.com.evil.invalid/x", False)):
            opener = FakeOpener()
            server, captured = self.server(["https://api.example.com"], opener)
            server._execute_http_request(1, {"url": url})
            self.assertEqual(bool(opener.calls), allowed, url)
        for origin in ("https://*.example.com", "https://example.com/", "https://example.com/a", "https://example.com?x=1", "https://localhost", "https://a.local", "https://a.internal", "https://a.home.arpa", "https://a.onion", "https://127.0.0.1", "https://169.254.169.254"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                self.server([origin])

    def test_signature_precedes_origin_denial_and_diagnostics_are_offline(self):
        server, captured = self.server()
        with patch.object(proxy.socket, "getaddrinfo") as resolve:
            server._execute_check_payload(1, {"url": "https://api.example.com/", "method": "POST", "body": "forbidden-marker"})
            resolve.assert_not_called()
        result = json.loads(self.result(captured)["content"][0]["text"])
        self.assertEqual(result["rule_sid"], 1)
        server._execute_check_payload(2, {"url": "https://api.example.com/"})
        result = json.loads(self.result(captured)["content"][0]["text"])
        self.assertTrue(result["blocked"])
        self.assertFalse(result["dns_checked"])

    def test_trusted_opener_is_explicit_and_does_not_bypass_protocol(self):
        opener = FakeOpener()
        server, captured = self.server(opener=opener)
        server._execute_http_request(1, {"url": "http://127.0.0.1/"})
        self.assertFalse(self.result(captured)["isError"])
        server._execute_http_request(2, {"url": "http://127.0.0.1/", "headers": {"Connection": "upgrade"}})
        self.assertEqual(len(opener.calls), 1)
        self.assertTrue(self.result(captured)["isError"])

    def test_header_policy_and_identity_encoding(self):
        names = list(proxy.DENIED_HEADERS) + ["Proxy-Custom", "X-Forwarded-Test", "Sec-Fetch-Site", "Sec-CH-UA"]
        for name in names:
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.policy(headers={name: "value"})
        for headers in ({"X-A": "1", "x-a": "2"}, {"X-A": " value"}, {"X-A": "value "}, {"X-A": "a\tb"},
                        {"X-A": "a\nb"}, {"X-A": "é"}, {"X-A": "x" * proxy.MAX_FIELD_BYTES},
                        {"Accept-Encoding": "gzip"}, {"Content-Encoding": "br"}):
            with self.subTest(headers=list(headers)), self.assertRaises(ValueError):
                self.policy(headers=headers)
        prepared = self.policy(headers={"Authorization": "Bearer test", "Accept-Encoding": "IDENTITY"})
        self.assertEqual(prepared[2]["accept-encoding"], "identity")
        self.assertEqual(prepared[2]["authorization"], "Bearer test")

    def test_content_type_json_and_form_policy(self):
        for media in ("application/octet-stream", "multipart/form-data; boundary=x", "text/plain; charset=latin1", "text/plain; charset=utf-8; charset=utf-8"):
            with self.subTest(media=media), self.assertRaises(ValueError):
                self.policy(method="POST", body="hello", headers={"Content-Type": media})
        for media in ("application/json", "application/problem+json", 'application/json; charset="UTF-8"'):
            self.assertEqual(self.policy(method="POST", body='{"hello":"world"}', headers={"Content-Type": media})[3], '{"hello":"world"}')
        self.assertEqual(self.policy(method="POST", body=' {"hello":1}')[2]["content-type"], "application/json")
        self.assertEqual(self.policy(method="POST", body="hello")[2]["content-type"], "text/plain; charset=utf-8")
        for body in ("a=%ff", "a=%", "a=%00", "a=\t", "a=%ed%a0%80"):
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.policy(method="POST", body=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.policy(method="POST", body="message=hello+world&unicode=%E2%9C%93", headers={"Content-Type": "application/x-www-form-urlencoded"})

    def test_malformed_request_media_parameters_never_dispatch(self):
        opener = FakeOpener()
        server, captured = self.server(allowed=["https://api.example.com"], opener=opener)
        for media in ("text/plain; charset =utf-8", "text/plain; charset= utf-8",
                      'application/json; charset = "utf-8"'):
            with self.subTest(media=media):
                server._execute_http_request(1, {
                    "url": "https://api.example.com/v1", "method": "POST", "body": "{}",
                    "headers": {"Content-Type": media},
                })
                self.assertTrue(self.result(captured)["isError"])
        self.assertEqual(opener.calls, [])

    def test_ijson_duplicates_unicode_numeric_and_complexity(self):
        invalid = [r'{"name":1,"na\u006de":2}', r'{"x":"\ud800"}', r'{"x":"\udfff"}',
                   r'{"x":"\ufdd0"}', r'{"x":"\uffff"}', r'{"\ufffe":1}', r'{"x":"\udbff\udfff"}',
                   '{"x":NaN}', '{"x":Infinity}', '{"x":1e400}', '{"x":1e20}', '{"x":9007199254740992}',
                   "[" * 65 + "0" + "]" * 65]
        for body in invalid:
            with self.subTest(body=body), self.assertRaises(ValueError):
                proxy.strict_json_loads(body)
        self.assertEqual(proxy.strict_json_loads(r'{"x":"\ud83d\ude42"}'), {"x": "🙂"})
        with patch.object(proxy, "MAX_JSON_TOKENS", 3), self.assertRaises(ValueError):
            proxy.strict_json_loads('[1,2,3,4]')
        proxy.strict_json_loads('["quoted \\\" brace } is not nesting"]')

    def test_invalid_rpc_never_dispatches(self):
        invalid = [
            {"jsonrpc": "1.0", "id": 1, "method": "tools/call"},
            {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "http_request"}},
            {"jsonrpc": "2.0", "id": True, "method": "tools/call"},
            {"jsonrpc": "2.0", "id": None, "method": "tools/call"},
            {"jsonrpc": "2.0", "id": 0.5, "method": "tools/call"},
            {"jsonrpc": "2.0", "id": 1.0, "method": "tools/call"},
            {"jsonrpc": "2.0", "id": 1, "method": ""},
            {"jsonrpc": "2.0", "id": 9007199254740992, "method": "tools/call"},
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": []},
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "http_request", "_meta": []}},
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "http_request", "extra": True}},
        ]
        for request in invalid:
            server, _ = self.server(opener=FakeOpener())
            with patch.object(server, "_handle_tool_call") as dispatch, patch.object(server, "_send_error"):
                server._handle_message(request)
                dispatch.assert_not_called()

    def test_rpc_duplicate_keys_and_budgets(self):
        server, _ = self.server(opener=FakeOpener())
        requests = '{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"ping"}\n'
        with patch.object(proxy.sys, "stdin", io.StringIO(requests)), patch.object(server, "_handle_message") as dispatch, patch.object(server, "_send_error") as error:
            server.run()
            dispatch.assert_not_called()
            error.assert_called_once()
        for limit, value, wire in (("MAX_RPC_MESSAGES", 1, "\n\n\n"), ("MAX_RPC_BYTES", 2, "   \n")):
            server, _ = self.server(opener=FakeOpener())
            with patch.object(proxy, limit, value), patch.object(proxy.sys, "stdin", io.StringIO(wire)), patch.object(server, "_send_error") as error:
                server.run()
                error.assert_called_once()
                self.assertIn("budget", error.call_args.args[2])

    def test_attempt_byte_and_response_budgets_precede_work(self):
        opener = FakeOpener()
        server, captured = self.server(opener=opener)
        with patch.object(proxy, "MAX_INSPECTION_ATTEMPTS", 1), patch.object(server.engine, "inspect", wraps=server.engine.inspect) as inspect:
            server._execute_check_payload(1, {"url": "https://api.example.com/"})
            server._execute_http_request(2, {"url": "https://api.example.com/"})
            self.assertEqual(inspect.call_count, 1)
            self.assertFalse(opener.calls)
        for field, count in (("inspected_bytes", proxy.MAX_SESSION_INSPECTION_BYTES), ("response_bytes", proxy.MAX_SESSION_RESPONSE_BYTES)):
            server, captured = self.server(opener=FakeOpener())
            setattr(server, field, count)
            with patch.object(server.engine, "inspect") as inspect:
                server._execute_http_request(1, {"url": "https://api.example.com/"})
                inspect.assert_not_called()
            self.assertTrue(self.result(captured)["isError"])

    def test_response_budget_accounts_overflow_reads(self):
        response = FakeResponse(b"12345", headers=[("Content-Type", "text/plain")])
        server, _ = self.server(opener=FakeOpener())
        with patch.object(proxy, "MAX_SESSION_RESPONSE_BYTES", 4), self.assertRaises(ValueError):
            server._response_data(response)
        self.assertEqual(server.response_bytes, 5)
        self.assertEqual(response.reads, [5])

    def test_resolved_private_mixed_and_special_addresses_never_connect(self):
        denied = ["127.0.0.1", "169.254.169.254", "168.63.129.16", "192.0.0.9", "192.31.196.1",
                  "192.52.193.1", "192.175.48.1", "100.64.0.1", "224.0.0.1", "240.0.0.1", "::1",
                  "::ffff:8.8.8.8", "64:ff9b::808:808", "2001:db8::1", "2002::1", "3fff::1"]
        for address in denied:
            self.assertFalse(proxy.is_public_address(address), address)
        answers = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443)),
                   (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))]
        with patch.object(proxy, "_resolve_once", return_value=answers), patch.object(proxy.socket, "socket") as create, self.assertRaises(ValueError):
            proxy._public_connect("api.example.com", 443, 30)
        create.assert_not_called()

    def test_dns_names_are_absolute_and_ip_literals_skip_dns(self):
        answer = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))]
        with patch.object(proxy.socket, "getaddrinfo", return_value=answer) as resolver:
            self.assertEqual(proxy._resolve_once("api.example.com", 443, 30), answer)
            resolver.assert_called_once_with("api.example.com.", 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
            resolver.reset_mock()
            self.assertEqual(proxy._resolve_once("8.8.8.8", 443, 30), answer)
            resolver.assert_not_called()

    def test_dns_connection_is_pinned_and_tls_keeps_hostname(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))]
        connection = MagicMock()
        with patch.object(proxy, "_resolve_once", return_value=answers) as resolve, patch.object(proxy.socket, "socket", return_value=connection):
            self.assertIs(proxy._public_connect("api.example.com", 443, 30), connection)
            resolve.assert_called_once_with("api.example.com", 443, 30)
            connection.connect.assert_called_once_with(("8.8.8.8", 443))
        context = ssl.create_default_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        with patch.object(proxy, "_public_connect", return_value=connection), patch.object(context, "wrap_socket", return_value=connection) as wrap:
            secure = proxy.PinnedHTTPSConnection("api.example.com", context=context, timeout=30)
            secure.connect()
            wrap.assert_called_once_with(connection, server_hostname="api.example.com")

    def test_secure_transport_ignores_environment_proxy_and_uses_origin_form(self):
        wire = WireSocket(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        server, captured = self.server(["http://api.example.com"])
        with patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:4444", "http_proxy": "http://127.0.0.1:4444"}), patch.object(proxy, "_public_connect", return_value=wire) as connect:
            server._execute_http_request(1, {"url": "http://api.example.com/path?x=1"})
        self.assertFalse(self.result(captured)["isError"], self.result(captured))
        connect.assert_called_once_with("api.example.com", 80, 30)
        sent = b"".join(wire.sent)
        self.assertTrue(sent.startswith(b"GET /path?x=1 HTTP/1.1\r\n"), sent)
        self.assertIn(b"Accept-Encoding: identity\r\n", sent)

    def wire_response(self, wire, method="GET"):
        response = proxy.StrictHTTPResponse(WireSocket(wire), method=method)
        response.begin()
        response.code = response.status
        return response

    def test_response_wire_rejects_bad_lines_folding_and_size(self):
        wires = [
            b"HTTP/1.0 200 OK\r\n\r\n", b"HTTP/1.1 200 OK\n\n", b"HTTP/1.1 200\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX: ok\r\n continuation\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nBad Name: value\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX: a\tb\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX: " + b"x" * proxy.MAX_FIELD_BYTES + b"\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n" + b"X: " + b"x" * 8000 + b"\r\n" + (b"Y: " + b"x" * 8000 + b"\r\n") * 8 + b"\r\n",
        ]
        for wire in wires:
            with self.subTest(prefix=wire[:70]), self.assertRaises(ValueError):
                self.wire_response(wire)

    def test_informational_responses_are_bounded_and_never_upgrade(self):
        server, _ = self.server(opener=FakeOpener())
        final = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        response = self.wire_response(b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n" + final)
        self.assertEqual(server._response_data(response)["body"], "ok")
        for prefix in (b"HTTP/1.1 100 Continue\r\n\r\n" * 5, b"HTTP/1.1 101 Switching Protocols\r\n\r\n"):
            with self.assertRaises(ValueError):
                self.wire_response(prefix + final)

    def test_informational_and_204_responses_cannot_declare_framing(self):
        for status in (100, 102, 103, 204):
            for field in (b"Content-Length: 0", b"Transfer-Encoding: chunked"):
                wire = f"HTTP/1.1 {status} Status\r\n".encode() + field + b"\r\n\r\n"
                with self.subTest(status=status, field=field), self.assertRaises(ValueError):
                    self.wire_response(wire)
        server, _ = self.server(opener=FakeOpener())
        with self.assertRaises(ValueError):
            server._response_data(FakeResponse(b"", headers=[("Content-Length", "0")], status=204))

    def test_response_policy_rejects_ambiguous_framing_encodings_upgrade(self):
        header_sets = [
            [("Content-Length", "2"), ("Content-Length", "2")],
            [("Content-Length", "2"), ("Transfer-Encoding", "chunked")],
            [("Content-Encoding", "gzip")], [("Upgrade", "websocket")], [("Connection", "upgrade")], [("Trailer", "X-A")],
            [("Transfer-Encoding", "gzip, chunked")], [("Content-Length", "+2")],
            [("Content-Length", "02")], [("HTTP2-Settings", "AAEAAABk")],
        ]
        for headers in header_sets:
            server, _ = self.server(opener=FakeOpener())
            response = FakeResponse(headers=headers)
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                server._response_data(response)
            self.assertFalse(response.reads)
        server, _ = self.server(opener=FakeOpener())
        for status in (101, 600, 999):
            with self.subTest(status=status), self.assertRaises(ValueError):
                server._response_data(FakeResponse(status=status))
        with self.assertRaises(ValueError):
            server._response_data(FakeResponse(b"\xff"))
        with self.assertRaises(ValueError):
            server._response_data(FakeResponse(b"x", headers=[("Content-Length", "5")]))

    def test_response_chunks_trailers_and_cookie_arrays(self):
        server, _ = self.server(opener=FakeOpener())
        base = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        response = self.wire_response(base + b"2\r\nok\r\n0\r\n\r\n")
        self.assertEqual(server._response_data(response)["body"], "ok")
        for chunks in (b"2\r\nokXX0\r\n\r\n", b"2;x=\r\nok\r\n0\r\n\r\n", b"2\r\nok\r\n0\r\nX-A: value\r\n\r\n"):
            with self.subTest(chunks=chunks), self.assertRaises(ValueError):
                server._response_data(self.wire_response(base + chunks))
        result = server._response_data(FakeResponse(headers=[("Set-Cookie", "a=1"), ("Set-Cookie", "b=2"), ("Content-Length", "2")]))
        self.assertEqual(result["headers"]["Set-Cookie"], ["a=1", "b=2"])
        self.assertEqual(result["header_values"]["set-cookie"], ["a=1", "b=2"])

    def test_response_connection_options_protect_metadata_and_bound_lists(self):
        denied = sorted(proxy.RESPONSE_CONNECTION_PROTECTED) + [
            "Proxy-Unknown", "Sec-Unknown", "X-Forwarded-Unknown", '"close"',
            "close;bad", "close=value", "not a token", "," * proxy.MAX_RESPONSE_METADATA_PARTS,
        ]
        final = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        for value in denied:
            fields = [("Connection", value), ("Content-Length", "2")]
            server, _ = self.server(opener=FakeOpener())
            response = FakeResponse(headers=fields)
            with self.subTest(value=value), self.assertRaises(ValueError):
                server._response_data(response)
            self.assertFalse(response.reads)
            for status in (200, 103):
                wire = f"HTTP/1.1 {status} Status\r\nConnection: {value}\r\n\r\n".encode()
                with self.subTest(value=value, status=status), self.assertRaises(ValueError):
                    self.wire_response(wire + final)
        for value in ("", ",", "close", "KEEP-ALIVE", "close,, x-extension", ",".join(["x"] * 128)):
            server, _ = self.server(opener=FakeOpener())
            result = server._response_data(FakeResponse(headers=[("Connection", value), ("Content-Length", "2")]))
            self.assertEqual(result["body"], "ok")
        # Multiple Connection lines share a single bounded list budget.
        server, _ = self.server(opener=FakeOpener())
        with self.assertRaises(ValueError):
            server._response_data(FakeResponse(headers=[("Connection", ",".join(["x"] * 65)),
                                                        ("Connection", ",".join(["y"] * 64))]))

    def test_response_known_singletons_reject_duplicates_but_list_fields_remain(self):
        for name in sorted(proxy.RESPONSE_SINGLETON_HEADERS):
            value = "text/plain" if name == "content-type" else "2"
            fields = [(name, value), (name.upper(), value)]
            server, _ = self.server(opener=FakeOpener())
            response = FakeResponse(headers=fields)
            with self.subTest(name=name), self.assertRaises(ValueError):
                server._response_data(response)
            self.assertFalse(response.reads)
            wire = f"HTTP/1.1 200 OK\r\n{name}: {value}\r\n{name.upper()}: {value}\r\n\r\n".encode()
            with self.subTest(name=name, source="wire"), self.assertRaises(ValueError):
                self.wire_response(wire)
        for name in ("WWW-Authenticate", "Authentication-Info", "Cache-Control", "Link", "Set-Cookie", "X-Extension"):
            server, _ = self.server(opener=FakeOpener())
            result = server._response_data(FakeResponse(headers=[(name, "one"), (name, "two"), ("Content-Length", "2")]))
            self.assertEqual(result["header_values"][name.lower()], ["one", "two"])

    def test_response_media_type_grammar_charset_and_parameter_limits(self):
        valid = ['text/plain', 'Text/HTML;Charset="UTF-8"', 'application/octet-stream',
                 'application/problem+json', 'text/plain; title="comma,semicolon;ok"',
                 'text/plain; title="escaped\\\"quote"', 'text/plain; charset="u\\tf-8"',
                 'text/plain; title=""', 'text/plain ; ; charset=utf-8;', 'text/plain' + ';' * 128]
        invalid = ['', 'text', 'text/plain,application/json', 'text/plain; charset=utf-16',
                   'text/plain; charset=""', 'text/plain; charset=utf-8; CHARSET=utf-8',
                   "text/plain; charset*=utf-8''UTF-8", 'text/plain; charset*0=utf-8',
                   'text/plain; charset =utf-8', 'text/plain; charset= utf-8',
                   'text/plain; title="unterminated', 'text/plain; title=x junk',
                   'text/plain; title="ok"junk', 'text/plain; title=x; title=x', 'text/plain' + ';' * 129]
        for media in valid:
            server, _ = self.server(opener=FakeOpener())
            result = server._response_data(FakeResponse(headers=[("Content-Type", media), ("Content-Length", "2")]))
            self.assertEqual(result["body"], "ok")
        for media in invalid:
            server, _ = self.server(opener=FakeOpener())
            response = FakeResponse(headers=[("Content-Type", media), ("Content-Length", "2")])
            with self.subTest(media=media), self.assertRaises(ValueError):
                server._response_data(response)
            self.assertFalse(response.reads)
            for status in (200, 103):
                wire = f"HTTP/1.1 {status} Status\r\nContent-Type: {media}\r\n\r\n".encode()
                with self.subTest(media=media, status=status), self.assertRaises(ValueError):
                    self.wire_response(wire + b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    def test_rfc_chunk_extension_grammar_and_opaque_values(self):
        valid = [b'2', b'0002;flag', b'2;name=value', b'2 ; name = value;flag',
                 b'2\t;\tname\t=\t"a b"', b'2;x=""', b'2;x="a\\"b\\\\c"',
                 b'2;x="\x80\xff"', b'2;x="\\\x80"', b'2;x="a\tb"']
        # Byte literals above intentionally spell wire escapes for readability.
        valid = [value.replace(b"\\t", b"\t") for value in valid]
        server, _ = self.server(opener=FakeOpener())
        header = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        for line in valid:
            with self.subTest(line=line):
                result = server._response_data(self.wire_response(header + line + b"\r\nok\r\n0;end=yes\r\n\r\n"))
                self.assertEqual(result["body"], "ok")
        invalid = [b'2 ', b'2;', b'2;=x', b'2;x=', b'2;x="unterminated', b'2;x="a\x00b"',
                   b'2;x="a\x7fb"', b'2;x="a\\\r"', b'2;x=y trailing', b'2;x="a"junk', b'2;x="a" ',
                   b'+2', b'0x2', b'2;;x']
        for line in invalid:
            with self.subTest(line=line), self.assertRaises(ValueError):
                proxy.parse_chunk_line(line + b"\r\n")

    def test_chunk_resource_limits_are_independent(self):
        header = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        scenarios = [
            ("MAX_DATA_CHUNKS", 1, b"1\r\na\r\n1\r\nb\r\n0\r\n\r\n"),
            ("MAX_CHUNK_EXTENSION_BYTES", 3, b"1;x=y\r\na\r\n0\r\n\r\n"),
            ("MAX_CHUNK_FRAMING_BYTES", 8, b"000000001\r\na\r\n0\r\n\r\n"),
            ("MAX_CHUNK_LINE_BYTES", 5, b"1;long=value\r\na\r\n0\r\n\r\n"),
        ]
        for name, limit, chunks in scenarios:
            server, _ = self.server(opener=FakeOpener())
            with self.subTest(name=name), patch.object(proxy, name, limit), self.assertRaises(ValueError):
                server._response_data(self.wire_response(header + chunks))
            self.assertGreater(server.response_bytes, 0)
        server, _ = self.server(opener=FakeOpener())
        with patch.object(proxy, "MAX_DATA_CHUNKS", 1):
            self.assertEqual(server._response_data(self.wire_response(header + b"1\r\na\r\n0\r\n\r\n"))["body"], "a")

    def test_bodyless_responses_do_not_read_transfer_metadata(self):
        for method, status in (("HEAD", 200), ("GET", 304)):
            for field in (b"Content-Length: 999999999999", b"Transfer-Encoding: chunked"):
                with self.subTest(method=method, status=status, field=field):
                    server, _ = self.server(opener=FakeOpener())
                    wire = f"HTTP/1.1 {status} Status\r\n".encode() + field + b"\r\n\r\n"
                    response = self.wire_response(wire, method)
                    result = server._response_data(response, method)
                    self.assertEqual(result["body"], "")
                    self.assertEqual(server.response_bytes, 0)
                    response.close()
        server, _ = self.server(opener=FakeOpener())
        response = FakeResponse(b"ignored", status=204, headers=[("X-Trace", "test")])
        self.assertEqual(server._response_data(response)["body"], "")
        self.assertFalse(response.reads)

    def test_reset_content_205_must_be_empty(self):
        valid = [b"Content-Length: 0\r\n\r\n", b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n", b"Connection: close\r\n\r\n"]
        for ending in valid:
            server, _ = self.server(opener=FakeOpener())
            result = server._response_data(self.wire_response(b"HTTP/1.1 205 Reset Content\r\n" + ending))
            self.assertEqual(result["body"], "")
        for ending in (b"Content-Length: 1\r\n\r\nx", b"Transfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n", b"Connection: close\r\n\r\nx"):
            server, _ = self.server(opener=FakeOpener())
            with self.subTest(ending=ending), self.assertRaises(ValueError):
                server._response_data(self.wire_response(b"HTTP/1.1 205 Reset Content\r\n" + ending))

    def test_interim_blocks_cannot_bypass_encoding_or_upgrade_policy(self):
        for field in (b"Content-Encoding: gzip", b"Content-Encoding: identity\r\nContent-Encoding: identity", b"Upgrade: websocket", b"Connection: upgrade", b"Trailer: x-extra"):
            wire = b"HTTP/1.1 103 Early Hints\r\n" + field + b"\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.wire_response(wire)

    def test_truncated_chunk_body_and_delimiters_charge_consumed_bytes(self):
        header = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        for ending in (b"3\r\nab", b"2\r\nab", b"2\r\nab\r", b"2\r\nab\r\n", b"0\r\n"):
            server, _ = self.server(opener=FakeOpener())
            with self.subTest(ending=ending), self.assertRaises((ValueError, OSError)):
                server._response_data(self.wire_response(header + ending))
            self.assertGreaterEqual(server.response_bytes, len(ending))

    def test_timeout_after_partial_body_or_chunk_line_counts_consumed_bytes(self):
        class InterruptedInput(io.RawIOBase):
            def __init__(self, data):
                self.available = bytearray(data)

            def readable(self):
                return True

            def readinto(self, target):
                if not self.available:
                    raise TimeoutError("simulated stalled response")
                count = min(len(target), len(self.available))
                target[:count] = self.available[:count]
                del self.available[:count]
                return count

        for field, body in ((b"Content-Length: 8192", b"x" * 4096),
                            (b"Transfer-Encoding: chunked", b"2000\r\n" + b"x" * 4096),
                            (b"Transfer-Encoding: chunked", b"1234")):
            wire = b"HTTP/1.1 200 OK\r\n" + field + b"\r\n\r\n" + body
            sock = MagicMock()
            sock.makefile.return_value = io.BufferedReader(InterruptedInput(wire))
            response = proxy.StrictHTTPResponse(sock)
            self.addCleanup(response.close)
            response.begin()
            response.code = response.status
            opener = FakeOpener()
            server, captured = self.server(opener=opener)
            with self.subTest(field=field, body_length=len(body)), self.assertRaises(TimeoutError):
                server._response_data(response)
            self.assertEqual(server.response_bytes, len(body))
            with patch.object(proxy, "MAX_SESSION_RESPONSE_BYTES", len(body)), patch.object(server.engine, "inspect") as inspect:
                server._execute_http_request(1, {"url": "https://api.example.com/"})
                inspect.assert_not_called()
                self.assertFalse(opener.calls)
                self.assertTrue(self.result(captured)["isError"])

    def test_dns_thread_start_failure_releases_capacity(self):
        capacity = proxy.threading.BoundedSemaphore(1)
        with patch.object(proxy, "DNS_SLOTS", capacity), patch.object(proxy.threading.Thread, "start", side_effect=RuntimeError), self.assertRaises(ValueError):
            proxy._resolve_once("api.example.com", 443, 1)
        self.assertTrue(capacity.acquire(blocking=False))
        capacity.release()

    def test_rejected_chunk_reads_are_charged_to_session_budget(self):
        server, _ = self.server(opener=FakeOpener())
        wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n0\r\nX-A: forbidden\r\n\r\n"
        with self.assertRaises(ValueError):
            server._response_data(self.wire_response(wire))
        self.assertGreaterEqual(server.response_bytes, 4)
        server, _ = self.server(opener=FakeOpener())
        with patch.object(proxy, "MAX_SESSION_RESPONSE_BYTES", 5), self.assertRaises(ValueError):
            server._response_data(self.wire_response(wire))
        self.assertGreater(server.response_bytes, 5)

    def test_transport_deadline_restores_caller_handler(self):
        previous = signal.getsignal(signal.SIGALRM)
        with self.assertRaises(proxy.ProtocolPolicyError):
            with proxy.transport_budget(0.02):
                time.sleep(0.1)
        self.assertIs(signal.getsignal(signal.SIGALRM), previous)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_normalization_rejects_unfinished_fourth_decode(self):
        engine = proxy.SnortEngine()
        engine.load_rules('drop tcp any any -> any any (content:"needle"; sid:1;)')
        with self.assertRaises(ValueError):
            engine.inspect("POST", "https://api.example.com/", {}, "%2525256eeedle")


if __name__ == "__main__":
    unittest.main()
