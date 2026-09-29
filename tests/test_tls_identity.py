"""Real TLS identity checks through the production Python HTTPS opener."""
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import sys
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cmd/ax-mcp-proxy"))
import ax_mcp_proxy as proxy

FIXTURES = ROOT / "pkg/security/egress/testdata/tls-identity"
CORPUS = json.loads((FIXTURES / "cases.json").read_text())


class TestTLSIdentity(unittest.TestCase):
    def test_service_identity_before_http_delivery(self):
        original_context = ssl.create_default_context
        for case in CORPUS["cases"]:
            for version in CORPUS["tls_versions"]:
                with self.subTest(name=case["name"], version=version):
                    protocol = {"TLSv1.2": ssl.TLSVersion.TLSv1_2, "TLSv1.3": ssl.TLSVersion.TLSv1_3}[version]
                    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    server_context.minimum_version = server_context.maximum_version = protocol
                    server_context.load_cert_chain(FIXTURES / case["certificate"], FIXTURES / "server-key.pem")
                    server_context.set_alpn_protocols(["h2", "http/1.1"])
                    server_names, requests, protocols, errors, dials, certificate_errors = [], [], [], [], [], []
                    server_context.set_servername_callback(lambda _sock, name, _context: server_names.append(name))
                    left, right = socket.socketpair()
                    class PinnedSocket(socket.socket):
                        def connect(self, address):
                            dials.append(address)  # Already connected to the local socket pair.
                    connected = PinnedSocket(fileno=left.detach())
                    connected.settimeout(3)
                    right.settimeout(3)

                    def serve():
                        try:
                            with server_context.wrap_socket(right, server_side=True) as secure:
                                data = b""
                                while b"\r\n\r\n" not in data and len(data) < 8192:
                                    chunk = secure.recv(4096)
                                    if not chunk:
                                        break
                                    data += chunk
                                if data:
                                    requests.append(data)
                                    protocols.append(secure.selected_alpn_protocol())
                                    secure.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        except (OSError, ssl.SSLError) as exc:
                            errors.append(exc)
                        finally:
                            right.close()

                    worker = threading.Thread(target=serve, daemon=True)
                    worker.start()
                    host = case["host"]
                    authority = "[" + host + "]" if ":" in host else host
                    origin = "https://" + authority
                    try:
                        literal = ipaddress.ip_address(host)
                    except ValueError:
                        literal = None
                    dial_ip = str(literal) if literal is not None else "8.8.8.8"
                    answers = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))]
                    def client_context(*args, **kwargs):
                        context = original_context(*args, **kwargs)
                        if case["trusted"]:
                            context.load_verify_locations(cafile=FIXTURES / "ca.pem")
                        wrap_socket = context.wrap_socket
                        def record_verification(*args, **kwargs):
                            try:
                                return wrap_socket(*args, **kwargs)
                            except ssl.SSLCertVerificationError as exc:
                                certificate_errors.append(exc)
                                raise
                        context.wrap_socket = record_verification
                        return context
                    engine = proxy.SnortEngine()
                    engine.load_rules('drop tcp any any -> any any (content:"forbidden-marker"; sid:1;)')
                    captured = []
                    try:
                        with patch.object(proxy.ssl, "create_default_context", side_effect=client_context), \
                                patch.object(proxy.socket, "getaddrinfo", return_value=answers), \
                                patch.object(proxy.socket, "socket", return_value=connected):
                            server = proxy.MCPServer(engine, allowed_origins=[origin])
                            server._send_response = lambda request_id, result: captured.append(result)
                            server._execute_http_request(1, {"url": origin + "/identity", "timeout_seconds": 3,
                                                            "headers": {"Authorization": "Bearer tls-identity-fixture"}})
                    finally:
                        connected.close()
                        worker.join(4)
                    self.assertFalse(worker.is_alive(), "TLS fixture worker did not finish")
                    self.assertEqual([address[0] for address in dials], [dial_ip])
                    self.assertTrue(all(address[1] == 443 for address in dials))
                    self.assertEqual(server_names, [host if literal is None else None])
                    self.assertEqual(not captured[-1]["isError"], case["accepted"], captured[-1])
                    self.assertEqual(bool(requests), case["accepted"], "HTTP data reached an unaccepted identity")
                    if case["accepted"]:
                        self.assertFalse(errors)
                        self.assertFalse(certificate_errors)
                        self.assertEqual(protocols, ["http/1.1"])
                        self.assertIn(("Host: " + authority + "\r\n").encode(), requests[0])
                        self.assertIn(b"Authorization: Bearer tls-identity-fixture\r\n", requests[0])
                        result = json.loads(captured[-1]["content"][0]["text"])
                        self.assertEqual(result["body"], "ok")
                        self.assertEqual(server.response_bytes, 2)
                    else:
                        self.assertEqual(server.response_bytes, 0)
                        self.assertEqual(len(certificate_errors), 1, "expected a certificate verification failure")

    def test_unavailable_san_only_capability_fails_before_opener_creation(self):
        for mode in ("false", "missing", "old-openssl"):
            version = (1, 1, 1, 11, 15) if mode == "old-openssl" else ssl.OPENSSL_VERSION_INFO
            with self.subTest(capability=mode), patch.object(proxy.ssl, "HAS_NEVER_CHECK_COMMON_NAME", mode != "false"), \
                    patch.object(proxy.ssl, "OPENSSL_VERSION_INFO", version), \
                    patch.object(proxy.urllib.request, "build_opener") as build:
                if mode == "missing":
                    del proxy.ssl.HAS_NEVER_CHECK_COMMON_NAME
                with self.assertRaisesRegex(proxy.ProtocolPolicyError, "certificate identity"):
                    proxy.MCPServer(proxy.SnortEngine(), allowed_origins=["https://api.example.com"])
                build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
