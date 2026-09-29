"""DNS worker capacity must survive cancellation at either side of handoff."""
from contextlib import contextmanager
from pathlib import Path
import signal
import socket
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cmd/ax-mcp-proxy"))
import ax_mcp_proxy as proxy


class TestDNSWorkerLifecycle(unittest.TestCase):
    def setUp(self):
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.previous_handler = signal.getsignal(signal.SIGALRM)

    def tearDown(self):
        self.assertIs(signal.getsignal(signal.SIGALRM), self.previous_handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    @staticmethod
    def fire_alarm():
        signal.getsignal(signal.SIGALRM)(signal.SIGALRM, None)

    def assert_capacity(self, slots, expected):
        acquired = 0
        try:
            while acquired <= expected and slots.acquire(blocking=False):
                acquired += 1
        finally:
            for _ in range(acquired):
                slots.release()
        self.assertEqual(acquired, expected, "DNS capacity leaked or was released twice")

    @contextmanager
    def resolver(self, capacity=1, blocked=False, fail=False):
        slots = threading.BoundedSemaphore(capacity)
        entered, finish = threading.Event(), threading.Event()
        threads, errors, calls = [], [], []
        answers = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))]
        if not blocked:
            finish.set()

        class TrackedThread(threading.Thread):
            def __init__(inner, *args, **kwargs):
                super().__init__(*args, **kwargs)
                threads.append(inner)

        def lookup(*args, **kwargs):
            calls.append((args, kwargs))
            entered.set()
            if not finish.wait(2):
                raise RuntimeError("test did not release its fake resolver")
            if fail:
                raise socket.gaierror("simulated resolver failure")
            return answers

        def join():
            for worker in threads:
                if worker.ident is not None:
                    worker.join(2)
                    self.assertFalse(worker.is_alive(), "test left a DNS worker running")

        state = SimpleNamespace(slots=slots, entered=entered, finish=finish,
                                threads=threads, errors=errors, calls=calls,
                                answers=answers, thread_type=TrackedThread, join=join)
        with patch.object(proxy, "DNS_SLOTS", slots), \
                patch.object(proxy.socket, "getaddrinfo", side_effect=lookup), \
                patch.object(proxy.threading, "Thread", TrackedThread), \
                patch.object(threading, "excepthook", side_effect=lambda args: errors.append(args.exc_value)):
            try:
                yield state
            finally:
                finish.set()
                join()
                self.assertFalse(errors, "worker cleanup raised an exception")

    def test_alarm_during_unstarted_setup_releases_capacity(self):
        stages = ("event-construction", "thread-construction", "after-slot-acquire", "before-thread-start")
        for stage in stages:
            with self.subTest(stage=stage), self.resolver() as state:
                if stage in ("event-construction", "thread-construction"):
                    name = "Event" if stage == "event-construction" else "Thread"
                    original = getattr(proxy.threading, name)
                    def create(*args, **kwargs):
                        self.fire_alarm()
                        return original(*args, **kwargs)
                    injection = patch.object(proxy.threading, name, side_effect=create)
                elif stage == "after-slot-acquire":
                    original_acquire = state.slots.acquire
                    def acquire(*args, **kwargs):
                        acquired = original_acquire(*args, **kwargs)
                        if acquired:
                            self.fire_alarm()
                        return acquired
                    injection = patch.object(state.slots, "acquire", side_effect=acquire)
                else:
                    original_start = state.thread_type.start
                    def start(worker):
                        self.fire_alarm()
                        original_start(worker)
                    injection = patch.object(state.thread_type, "start", start)
                with injection, self.assertRaisesRegex(proxy.ProtocolPolicyError, "total deadline"):
                    with proxy.transport_budget(1):
                        proxy._resolve_once("api.example.com", 443, 1)
                state.join()
                self.assert_capacity(state.slots, 1)

    def test_ordinary_setup_failure_releases_capacity(self):
        for stage in ("event-construction", "thread-construction", "thread-start"):
            with self.subTest(stage=stage), self.resolver() as state:
                target, name = (state.thread_type, "start") if stage == "thread-start" else \
                    (proxy.threading, "Event" if stage == "event-construction" else "Thread")
                with patch.object(target, name, side_effect=RuntimeError("simulated allocation failure")):
                    with self.assertRaises((RuntimeError, proxy.ProtocolPolicyError)):
                        proxy._resolve_once("api.example.com", 443, 1)
                self.assertFalse(state.calls)
                self.assert_capacity(state.slots, 1)

    def test_real_alarm_during_thread_construction_releases_capacity(self):
        with self.subTest(stage="kernel-alarm-in-thread-construction"), self.resolver() as state:
            def create(*args, **kwargs):
                time.sleep(0.1)
                return state.thread_type(*args, **kwargs)
            with patch.object(proxy.threading, "Thread", side_effect=create):
                with self.assertRaisesRegex(proxy.ProtocolPolicyError, "total deadline"):
                    with proxy.transport_budget(0.02):
                        proxy._resolve_once("api.example.com", 443, 1)
            self.assertFalse(state.calls)
            self.assert_capacity(state.slots, 1)

    def test_real_alarm_during_slot_acquire_releases_capacity(self):
        with self.subTest(stage="kernel-alarm-after-slot-consumption"), self.resolver() as state:
            original_acquire = state.slots.acquire
            def acquire(*args, **kwargs):
                acquired = original_acquire(*args, **kwargs)
                if acquired:
                    time.sleep(0.1)
                return acquired
            with patch.object(state.slots, "acquire", side_effect=acquire):
                with self.assertRaisesRegex(proxy.ProtocolPolicyError, "total deadline"):
                    with proxy.transport_budget(0.02):
                        proxy._resolve_once("api.example.com", 443, 1)
            state.join()
            self.assert_capacity(state.slots, 1)

    def test_alarm_after_start_retains_capacity_until_worker_finishes(self):
        for fail in (False, True):
            with self.subTest(resolver_fails=fail), self.resolver(blocked=True, fail=fail) as state:
                original_start = state.thread_type.start
                def start(worker):
                    original_start(worker)
                    self.assertTrue(state.entered.wait(1))
                    self.fire_alarm()
                with patch.object(state.thread_type, "start", start):
                    with self.assertRaisesRegex(proxy.ProtocolPolicyError, "total deadline"):
                        with proxy.transport_budget(1):
                            proxy._resolve_once("api.example.com", 443, 1)
                self.assert_capacity(state.slots, 0)
                with self.assertRaisesRegex(proxy.ProtocolPolicyError, "capacity exceeded"):
                    proxy._resolve_once("other.example.com", 443, 1)
                self.assertEqual(len(state.calls), 1)
                state.finish.set()
                state.join()
                self.assert_capacity(state.slots, 1)

    def test_alarm_during_completion_wait_retains_worker_capacity(self):
        for fail in (False, True):
            with self.subTest(resolver_fails=fail), self.resolver(blocked=True, fail=fail) as state:
                real_event = threading.Event
                completed = real_event()
                events = iter([completed])
                def create_event():
                    return next(events, None) or real_event()
                def wait(_timeout):
                    self.assertTrue(state.entered.wait(1))
                    self.fire_alarm()
                with patch.object(proxy.threading, "Event", side_effect=create_event), \
                        patch.object(completed, "wait", side_effect=wait):
                    with self.assertRaisesRegex(proxy.ProtocolPolicyError, "total deadline"):
                        with proxy.transport_budget(1):
                            proxy._resolve_once("api.example.com", 443, 1)
                self.assert_capacity(state.slots, 0)
                state.finish.set()
                state.join()
                self.assert_capacity(state.slots, 1)

    def test_start_failure_with_pending_alarm_releases_capacity(self):
        with self.subTest(stage="alarm-and-start-failure"), self.resolver() as state:
            def start(_worker):
                self.fire_alarm()
                raise RuntimeError("simulated startup failure")
            with patch.object(state.thread_type, "start", start):
                with self.assertRaisesRegex(proxy.ProtocolPolicyError, "total deadline"):
                    with proxy.transport_budget(1):
                        proxy._resolve_once("api.example.com", 443, 1)
            self.assertFalse(state.calls)
            self.assert_capacity(state.slots, 1)

    def test_repeated_setup_interruptions_do_not_exhaust_dns_capacity(self):
        with self.subTest(case="eight-interruptions-four-slots"), self.resolver(capacity=4) as state:
            errors = []
            def create(*_args, **_kwargs):
                self.fire_alarm()
            with patch.object(proxy.threading, "Thread", side_effect=create):
                for _ in range(8):
                    with self.assertRaises(proxy.ProtocolPolicyError) as caught:
                        with proxy.transport_budget(1):
                            proxy._resolve_once("api.example.com", 443, 1)
                    errors.append(str(caught.exception))
            self.assertTrue(all("total deadline" in error for error in errors), errors)
            self.assert_capacity(state.slots, 4)
            self.assertEqual(proxy._resolve_once("api.example.com", 443, 1), state.answers)
            state.join()
            self.assert_capacity(state.slots, 4)

    def test_capacity_bound_and_recovery(self):
        for case in ("ipv4-literal", "ipv6-literal", "capacity-exhausted", "lookup-error", "lookup-success"):
            with self.subTest(case=case), self.resolver(fail=case == "lookup-error") as state:
                if case.endswith("literal"):
                    host = "8.8.8.8" if case == "ipv4-literal" else "2606:4700:4700::1111"
                    self.assertEqual(proxy._resolve_once(host, 443, 1)[0][4][0], host)
                    self.assertFalse(state.calls)
                elif case == "capacity-exhausted":
                    self.assertTrue(state.slots.acquire(blocking=False))
                    try:
                        with self.assertRaisesRegex(proxy.ProtocolPolicyError, "capacity exceeded"):
                            proxy._resolve_once("api.example.com", 443, 1)
                        self.assertFalse(state.calls)
                    finally:
                        state.slots.release()
                elif case == "lookup-error":
                    with self.assertRaisesRegex(proxy.ProtocolPolicyError, "DNS resolution failed"):
                        proxy._resolve_once("api.example.com", 443, 1)
                else:
                    self.assertEqual(proxy._resolve_once("api.example.com", 443, 1), state.answers)
                    self.assertEqual(state.calls[0][0], ("api.example.com.", 443))
                state.join()
                self.assert_capacity(state.slots, 1)


if __name__ == "__main__":
    unittest.main()
