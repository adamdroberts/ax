"""Deadline signals must survive ordinary error handling until the budget boundary."""
from pathlib import Path
import signal
import socket
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cmd/ax-mcp-proxy"))
import ax_mcp_proxy as proxy
from test_http_protocol import FakeResponse


class TestDeadlineBudget(unittest.TestCase):
    def setUp(self):
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.previous_handler = signal.getsignal(signal.SIGALRM)

    def tearDown(self):
        self.assertIs(signal.getsignal(signal.SIGALRM), self.previous_handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def budget(self, kind):
        return proxy.inspection_budget() if kind == "inspection" else proxy.transport_budget(1)

    def error_type(self, kind):
        return proxy.InspectionBudgetError if kind == "inspection" else proxy.ProtocolPolicyError

    @staticmethod
    def fire_alarm(*_):
        signal.getsignal(signal.SIGALRM)(signal.SIGALRM, None)

    def test_budget_signal_escapes_ordinary_handlers(self):
        for kind in ("inspection", "transport"):
            for caught in (ValueError, Exception, OSError):
                with self.subTest(budget=kind, handler=caught.__name__):
                    continued = []
                    with self.assertRaises(self.error_type(kind)):
                        with self.budget(kind):
                            try:
                                self.fire_alarm()
                            except caught:
                                continued.append(True)
                    self.assertFalse(continued, "ordinary error handling swallowed the budget signal")

    def test_swallowed_signal_cannot_return_success(self):
        for kind in ("inspection", "transport"):
            with self.subTest(budget=kind):
                with self.assertRaises(self.error_type(kind)):
                    with self.budget(kind):
                        try:
                            self.fire_alarm()
                        except BaseException:
                            pass  # Model an embedding callback that suppresses every error.

    def test_absolute_deadline_checked_without_signal_delivery(self):
        for kind in ("inspection", "transport"):
            seconds = proxy.MAX_INSPECTION_SECONDS if kind == "inspection" else 1
            for when, offset, allowed in (("before", -0.001, True), ("at", 0, False), ("after", 0.001, False)):
                with self.subTest(budget=kind, completion=when):
                    # No signal is delivered; simulate a delayed handler/C call.
                    # The actual interval timer is still restored by the context.
                    with patch("time.monotonic", side_effect=[100.0, 100.0, 100.0 + seconds + offset]):
                        if allowed:
                            with self.budget(kind):
                                pass
                        else:
                            with self.assertRaises(self.error_type(kind)):
                                with self.budget(kind):
                                    pass

    def test_expiry_before_timer_arming_rejects_body(self):
        for kind in ("inspection", "transport"):
            seconds = proxy.MAX_INSPECTION_SECONDS if kind == "inspection" else 1
            with self.subTest(budget=kind):
                entered = []
                with patch("time.monotonic", side_effect=[100.0, 100.0 + seconds]):
                    with self.assertRaises(self.error_type(kind)):
                        with self.budget(kind):
                            entered.append(True)
                self.assertFalse(entered)

    def test_kernel_alarm_during_dns_literal_parse_stops_lookup(self):
        entered = []
        def slow_literal(_):
            entered.append(True)
            time.sleep(0.1)
            raise ValueError("not an IP literal")

        answers = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))]
        with self.subTest(case="kernel-alarm-in-dns-parser"):
            with patch.object(proxy.ipaddress, "ip_address", side_effect=slow_literal), patch.object(proxy.socket, "getaddrinfo", return_value=answers) as lookup:
                with self.assertRaises(proxy.ProtocolPolicyError):
                    with proxy.transport_budget(0.02):
                        proxy._resolve_once("api.example.com", 443, 1)
                self.assertEqual(entered, [True])
                lookup.assert_not_called()

    def test_resolver_alarm_blocks_mcp_delivery(self):
        class Opener:
            def open(inner, request, timeout):
                with patch.object(proxy.ipaddress, "ip_address", side_effect=self.fire_alarm):
                    proxy._resolve_once("api.example.com", 443, timeout)
                return FakeResponse(body=b"ok")

        engine = proxy.SnortEngine()
        engine.load_rules('drop tcp any any -> any any (content:"forbidden-marker"; sid:1;)')
        server = proxy.MCPServer(engine, allowed_origins=["https://api.example.com"], opener=Opener())
        captured = []
        server._send_response = lambda request_id, result: captured.append(result)
        answers = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))]
        with self.subTest(case="mcp-delivery-after-dns-parser-alarm"):
            with patch.object(proxy.socket, "getaddrinfo", return_value=answers) as lookup:
                server._execute_http_request(1, {"url": "https://api.example.com/v1"})
                self.assertTrue(captured[-1]["isError"], "expired request delivered a successful tool result")
                self.assertIn("total deadline", captured[-1]["content"][0]["text"])
                lookup.assert_not_called()
                self.assertEqual(server.response_bytes, 0)

    def test_ordinary_errors_keep_their_identity(self):
        for kind in ("inspection", "transport"):
            with self.subTest(budget=kind):
                error = ValueError("ordinary parse rejection")
                try:
                    with self.budget(kind):
                        raise error
                except ValueError as caught:
                    self.assertIs(caught, error)
                else:
                    self.fail("ordinary error was lost")


if __name__ == "__main__":
    unittest.main()
