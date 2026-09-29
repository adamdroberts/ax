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

"""HTTP inspection proxy using AX's deliberately limited Snort-style rule subset.

Signatures are defense in depth, not a guarantee of prevention. The agent runtime
must enforce this proxy as its only permitted network path. Packaged copies must
include pkg/security/snort/rules beside the repository-style cmd directory.
"""

import argparse
import base64
from contextlib import contextmanager
import datetime
import hashlib
import html
import http.client
import ipaddress
import json
import logging
import math
import re
import signal
import socket
import ssl
import sys
import threading
import time
import unicodedata
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", stream=sys.stderr)

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "ax-mcp-proxy"
SERVER_VERSION = "1.1.0"
MAX_BODY_BYTES = 1024 * 1024
MAX_URL_BYTES = 16 * 1024
MAX_HEADER_BYTES = 64 * 1024
MAX_HEADERS = 128
MAX_RESPONSE_BYTES = 10 * 1024 * 1024
MAX_MESSAGE_BYTES = 8 * 1024 * 1024
MAX_NORMALIZED_VIEWS = 16
MAX_INSPECTION_SECONDS = 2.0
RULE_DIRECTORY = Path(__file__).resolve().parents[2] / "pkg/security/snort/rules"
TARGETS = {"http_uri", "http_raw_uri", "http_header", "http_client_body", "http_raw_body", "http_method"}
HEADER_FIELD_PREFIX = "http_header:field "
TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def load_profile(engine: "SnortEngine", profile: str = "default") -> int:
    if profile not in ("default", "strict"):
        raise ValueError("unknown rule profile")
    # Parse and validate the entire profile before changing the caller's engine.
    staged = SnortEngine()
    texts = [(RULE_DIRECTORY / "default.rules").read_text(encoding="utf-8")]
    if profile == "strict":
        texts.append((RULE_DIRECTORY / "strict.rules").read_text(encoding="utf-8"))
    count = staged.load_rules("\n".join(texts))
    if not count:
        raise ValueError("bundled rule profile is empty")
    if profile == "strict":
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate SID in strict action overrides")
                result[key] = value
            return result

        overrides = json.loads((RULE_DIRECTORY / "strict-actions.json").read_text(encoding="utf-8"),
                               object_pairs_hook=unique_object)
        if not isinstance(overrides, dict):
            raise ValueError("strict action overrides must be a SID-to-action object")
        by_sid = {entry.sid: entry for entry in staged.rules}
        for sid, action in overrides.items():
            if not re.fullmatch(r"[1-9][0-9]*", sid) or int(sid) > 2147483647:
                raise ValueError("strict action override requires a canonical positive SID")
            entry = by_sid.get(int(sid))
            if entry is None:
                raise ValueError("strict action override references an unknown SID")
            if action not in ("drop", "block", "reject") or entry.action != "alert":
                raise ValueError("strict action overrides may only promote alert rules to blocking actions")
        for sid, action in overrides.items():
            by_sid[int(sid)].action = action
    existing = {entry.sid for entry in engine.rules}
    if any(entry.sid in existing for entry in staged.rules):
        raise ValueError("duplicate SID while loading rule profile")
    engine.rules.extend(staged.rules)
    return count


class ContentRule:
    def __init__(self, pattern: bytes, nocase: bool = False, target: str = "all", negated: bool = False):
        self.pattern = pattern
        self.nocase = nocase
        self.target = target
        self.negated = negated
        self.offset = 0
        self.depth = 0


class PCRERule:
    def __init__(self, regex_pattern: str, flags: int = 0, target: str = "all", negated: bool = False):
        # This is the common Go RE2/Python subset, not a general PCRE engine.
        # Reject constructs with differing semantics or particularly risky costs.
        if re.search(r"\\[1-9]|\\[gk]|\(\?(?:[=!<]|P|>|\()|\(\*", regex_pattern):
            raise ValueError("unsupported regex backreference, lookaround or extension")
        if re.search(r"(?:[*+?]|\{[0-9,]+\})\+", regex_pattern):
            raise ValueError("possessive regex quantifiers are unsupported")
        try:
            self.regex = re.compile(regex_pattern, flags | re.ASCII)
        except re.error as exc:
            raise ValueError("invalid regex") from exc
        self.target = target
        self.negated = negated


class SnortRule:
    def __init__(self, action: str, msg: str, sid: int, classtype: str = ""):
        self.action = action.lower()
        self.msg = msg
        self.sid = sid
        self.rev = 1
        self.classtype = classtype
        self.contents: List[ContentRule] = []
        self.pcres: List[PCRERule] = []


def _options(text: str) -> List[str]:
    parts, current = [], []
    quoted = escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == '"':
            current.append(char)
            quoted = not quoted
        elif char == ";" and not quoted:
            if "".join(current).strip():
                parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if quoted or escaped:
        raise ValueError("unterminated quoted option")
    if "".join(current).strip():
        raise ValueError("rule options must end in a semicolon")
    return parts


def _quoted(value: str) -> str:
    if len(value) < 2 or value[0] != '"' or value[-1] != '"':
        raise ValueError("option requires a quoted value")
    inner = value[1:-1]
    escaped = False
    for char in inner:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            raise ValueError("unexpected quote")
    if escaped:
        raise ValueError("unterminated quoted escape")
    return inner


def _content(value: str) -> bytes:
    out = bytearray()
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\":
            index += 1
            if index >= len(value) or value[index] not in '\\";:|':
                raise ValueError("unsupported content escape")
            out.extend(value[index].encode("utf-8"))
        elif char == "|":
            end = value.find("|", index + 1)
            if end < 0:
                raise ValueError("unterminated content hex block")
            digits = "".join(value[index + 1:end].split())
            if not digits or len(digits) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", digits):
                raise ValueError("invalid content hex block")
            out.extend(bytes.fromhex(digits))
            index = end
        else:
            out.extend(char.encode("utf-8"))
        index += 1
    if not out:
        raise ValueError("content must not be empty")
    return bytes(out)


class _JSONPairs(list):
    pass


def _json_strings(value: str) -> Optional[str]:
    try:
        parsed = json.loads(value, object_pairs_hook=_JSONPairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except RecursionError as exc:
        raise ValueError("JSON normalization nesting limit exceeded") from exc
    except InspectionBudgetError:
        raise
    except ValueError:
        return None
    strings = []
    # Preserve both duplicate keys and the original token ordering.
    stack = [parsed]
    visited = 0
    while stack:
        item = stack.pop()
        visited += 1
        if visited > 100000:
            raise ValueError("JSON normalization limit exceeded")
        if isinstance(item, str):
            strings.append(item)
        elif isinstance(item, _JSONPairs):
            for key, child in reversed(item):
                stack.extend((child, key))
        elif isinstance(item, list):
            stack.extend(reversed(item))
    return "\n".join(strings) if strings else None


def _normalized_views(value: str, limit: int) -> List[str]:
    def candidates(current):
        result = [html.unescape(current), urllib.parse.unquote(current), urllib.parse.unquote_plus(current)]
        decoded = _json_strings(current)
        if decoded is not None:
            result.append(decoded)
            result.append(re.sub(r'"(?:[^"\\]|\\.)*"', lambda match: '"' + json.loads(match.group()) + '"', current))
        return result

    views = [value]
    seen = {value}
    used = len(value.encode("utf-8"))
    frontier = [value]
    for _ in range(3):
        following = []
        for current in frontier:
            for candidate in candidates(current):
                if candidate in seen:
                    continue
                used += len(candidate.encode("utf-8"))
                if len(views) >= MAX_NORMALIZED_VIEWS or used > 8 * limit:
                    raise ValueError("normalization expansion limit exceeded")
                seen.add(candidate)
                views.append(candidate)
                following.append(candidate)
        frontier = following
        if not frontier:
            break
    if any(candidate not in seen for current in frontier for candidate in candidates(current)):
        raise ValueError("normalization decoding depth exceeded")
    return views


def validate_request(method: str, url: str, headers: Dict[str, str], body: str, for_transport: bool = False):
    if not all(isinstance(value, str) for value in (method, url, body)) or not isinstance(headers, dict):
        raise ValueError("method, url and body must be strings; headers must be an object")
    if not method or len(method) > 32 or not TOKEN.fullmatch(method):
        raise ValueError("invalid HTTP method")
    if not url or len(url.encode("utf-8")) > MAX_URL_BYTES or re.search(r"[\x00-\x20\x7f]", url):
        raise ValueError("invalid or oversized URL")
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError("only absolute HTTP(S) URLs without user information are allowed")
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("invalid HTTP(S) URL") from exc
    if len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise ValueError("request body exceeds inspection limit")
    if len(headers) > MAX_HEADERS:
        raise ValueError("too many request headers")
    header_bytes = 0
    names = set()
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str) or not TOKEN.fullmatch(key):
            raise ValueError("invalid request header")
        lower = key.lower()
        if lower in names:
            raise ValueError("duplicate case-insensitive header name")
        names.add(lower)
        if re.search(r"[\x00-\x08\x0a-\x1f\x7f]", value):
            raise ValueError("invalid request header value")
        if lower == "content-encoding" and value.strip().lower() not in ("", "identity"):
            raise ValueError("encoded request bodies are unsupported")
        if for_transport and lower in ("host", "content-length", "transfer-encoding", "proxy-authorization", "proxy-connection"):
            raise ValueError("transport-managed request header is unsupported")
        header_bytes += len((key + ": " + value + "\r\n").encode("utf-8"))
    if header_bytes > MAX_HEADER_BYTES:
        raise ValueError("request headers exceed inspection limit")
    return parsed


class InspectionBudgetError(ValueError):
    """A fixed, privacy-safe error returned when inspection cannot be bounded."""


class _BudgetExpired(BaseException):
    """Private control flow that ordinary parser/network error handlers cannot swallow."""


class _BudgetAlarm:
    """Record expiry immediately; defer its exception only during resource handoff."""
    def __init__(self):
        self.expired = False
        self.deferrals = 0

    def __call__(self, _signum, _frame):
        self.expired = True
        if not self.deferrals:
            raise _BudgetExpired()

    @contextmanager
    def defer(self):
        self.deferrals += 1
        try:
            yield
        finally:
            self.deferrals -= 1
            if self.expired and not self.deferrals:
                raise _BudgetExpired()


@contextmanager
def _defer_deadline_expiry():
    # Python runs signal handlers on the main thread. A worker must not change
    # the main thread's cancellation state when using this helper independently.
    alarm = signal.getsignal(signal.SIGALRM) if threading.current_thread() is threading.main_thread() and hasattr(signal, "SIGALRM") else None
    if isinstance(alarm, _BudgetAlarm):
        with alarm.defer():
            yield
    else:
        yield


@contextmanager
def _deadline_timer(seconds, error_type, message):
    """Own the checked-idle timer; translate expiration only after restoring it."""
    previous = signal.getsignal(signal.SIGALRM)
    deadline = time.monotonic() + seconds
    alarm = _BudgetAlarm()
    signal.signal(signal.SIGALRM, alarm)
    try:
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _BudgetExpired()
            signal.setitimer(signal.ITIMER_REAL, remaining)
            yield
            # Also reject a delayed signal or a callback that catches even
            # BaseException. The latter cannot turn an expired result into success.
            if alarm.expired or time.monotonic() >= deadline:
                raise _BudgetExpired()
        finally:
            try:
                signal.setitimer(signal.ITIMER_REAL, 0)
            finally:
                signal.signal(signal.SIGALRM, previous)
    except _BudgetExpired:
        raise error_type(message) from None


@contextmanager
def inspection_budget():
    # Python's re is backtracking. Bound the entire normalization/matching pass,
    # including trusted custom expressions; unsupported runtimes fail closed.
    if not all(hasattr(signal, name) for name in ("setitimer", "getitimer", "ITIMER_REAL", "SIGALRM")) or threading.current_thread() is not threading.main_thread():
        raise InspectionBudgetError("Python inspection requires a POSIX main thread with interval timers; use the Go proxy")
    remaining, interval = signal.getitimer(signal.ITIMER_REAL)
    if remaining > 0 or interval > 0:
        raise InspectionBudgetError("Python inspection cannot replace an active caller timer; use the Go proxy")
    with _deadline_timer(MAX_INSPECTION_SECONDS, InspectionBudgetError,
                         "Request exceeded the two-second inspection time limit"):
        yield


class SnortEngine:
    def __init__(self):
        self.rules: List[SnortRule] = []

    def load_rules(self, text: str) -> int:
        pending = []
        sids = {rule.sid for rule in self.rules}
        for number, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rule = self.parse_rule(line)
                if rule.sid in sids:
                    raise ValueError("duplicate SID")
                sids.add(rule.sid)
                pending.append(rule)
            except ValueError as exc:
                raise ValueError(f"rule line {number}: {exc}") from exc
        self.rules.extend(pending)
        return len(pending)

    def parse_rule(self, raw: str) -> SnortRule:
        match = re.fullmatch(r"([A-Za-z]+)\s+([A-Za-z]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*\((.*)\)", raw.strip())
        if not match:
            raise ValueError("invalid rule header or options enclosure")
        action, protocol, source, source_port, direction, destination, destination_port, options = match.groups()
        action = action.lower()
        if action not in ("drop", "reject", "block", "alert"):
            raise ValueError("unsupported rule action")
        if protocol.lower() not in ("tcp", "http") or (source, source_port, direction, destination, destination_port) != ("any", "any", "->", "any", "any"):
            raise ValueError("only tcp/http any any -> any any headers are supported")
        rule = SnortRule(action, "", 0)
        last = None
        modifiers = set()
        scalars = set()
        for option in _options(options):
            key, separator, value = option.partition(":")
            key, value = key.strip().lower(), value.strip()
            if key in ("msg", "sid", "rev", "classtype"):
                if not separator or key in scalars:
                    raise ValueError("missing or duplicate scalar option")
                scalars.add(key)
                if key in ("sid", "rev"):
                    if not re.fullmatch(r"[0-9]+", value) or not 0 < int(value) <= 2147483647:
                        raise ValueError("sid and rev must be positive 32-bit integers")
                    setattr(rule, key, int(value))
                elif key == "msg":
                    rule.msg = _quoted(value)
                else:
                    rule.classtype = _quoted(value) if value.startswith('"') else value
                    if not re.fullmatch(r"[A-Za-z0-9_-]+", rule.classtype):
                        raise ValueError("invalid classtype")
            elif key in ("content", "pcre"):
                if not separator:
                    raise ValueError("matcher requires a value")
                negated = value.startswith("!")
                if negated:
                    value = value[1:].strip()
                value = _quoted(value)
                if key == "content":
                    last = ContentRule(_content(value), negated=negated)
                    rule.contents.append(last)
                else:
                    parsed = re.fullmatch(r"/(.+)/([A-Za-z]*)", value)
                    if not parsed:
                        raise ValueError("pcre requires /expression/flags")
                    expression, flags = parsed.groups()
                    if len(set(flags)) != len(flags) or any(flag not in "ism" for flag in flags):
                        raise ValueError("unsupported or duplicate regex flag")
                    bits = (re.I if "i" in flags else 0) | (re.S if "s" in flags else 0) | (re.M if "m" in flags else 0)
                    last = PCRERule(expression.replace(r"\/", "/"), bits, negated=negated)
                    rule.pcres.append(last)
                modifiers = set()
            elif key in TARGETS or key in ("nocase", "offset", "depth"):
                if last is None:
                    raise ValueError("modifier must follow a matcher")
                category = "target" if key in TARGETS else key
                if category in modifiers:
                    raise ValueError("duplicate matcher modifier")
                modifiers.add(category)
                if key in TARGETS:
                    if key == "http_header" and separator:
                        field = value.split()
                        if len(field) != 2 or field[0] != "field" or not TOKEN.fullmatch(field[1]):
                            raise ValueError("http_header accepts only field followed by an HTTP header name")
                        last.target = HEADER_FIELD_PREFIX + field[1].lower()
                    else:
                        if separator:
                            raise ValueError("target modifier takes no value")
                        last.target = key
                elif key == "nocase":
                    if separator or not isinstance(last, ContentRule):
                        raise ValueError("nocase only modifies content; use pcre /i")
                    last.nocase = True
                else:
                    if not isinstance(last, ContentRule) or not separator or not re.fullmatch(r"[0-9]+", value) or int(value) > 2147483647 or (key == "depth" and int(value) == 0):
                        raise ValueError("offset must be nonnegative and depth must be positive")
                    setattr(last, key, int(value))
            else:
                raise ValueError(f"unsupported option: {key}")
        if not rule.sid or not (rule.contents or rule.pcres):
            raise ValueError("a positive SID and at least one matcher are required")
        return rule

    def inspect(self, method: str, url: str, headers: Dict[str, str], body: str) -> Tuple[bool, Optional[SnortRule], str]:
        with inspection_budget():
            return self._inspect(method, url, headers, body)

    def _inspect(self, method: str, url: str, headers: Dict[str, str], body: str) -> Tuple[bool, Optional[SnortRule], str]:
        parsed = validate_request(method, url, headers, body)
        has_query = "?" in url.split("#", 1)[0]
        full_uri = (parsed.path or "/") + ("?" + parsed.query if has_query else "")
        host = next((value for key, value in headers.items() if key.lower() == "host"), parsed.netloc)
        raw_headers = "Host: " + host + "\n"
        raw_headers += "".join(f"{key}: {value}\n" for key, value in sorted(headers.items()) if key.lower() != "host")
        if len(raw_headers.encode("utf-8")) > MAX_HEADER_BYTES:
            raise ValueError("request headers exceed inspection limit")
        uri_views = _normalized_views(url, MAX_URL_BYTES)
        for view in _normalized_views(full_uri, MAX_URL_BYTES):
            if view not in uri_views:
                uri_views.append(view)
        buffers = {
            "http_uri": uri_views,
            "http_raw_uri": [full_uri],
            "http_header": _normalized_views(raw_headers, MAX_HEADER_BYTES),
            "http_client_body": _normalized_views(body, MAX_BODY_BYTES),
            "http_raw_body": [body],
            "http_method": [method],
        }
        # Named headers inspect values only; a missing field has no buffer and
        # therefore cannot satisfy even a negated matcher. Host is authoritative.
        header_values = {key.lower(): value for key, value in headers.items()}
        header_values["host"] = parsed.netloc
        field_targets = {matcher.target for entry in self.rules for matcher in (*entry.contents, *entry.pcres)
                         if matcher.target.startswith(HEADER_FIELD_PREFIX)}
        for target in field_targets:
            name = target[len(HEADER_FIELD_PREFIX):]
            buffers[target] = _normalized_views(header_values[name], MAX_HEADER_BYTES) if name in header_values else []
        # Cache every normalized buffer once, independent of catalog size.
        buffers["all"] = [f"{method} {url} {full_uri}\n{raw_headers}\n{body}"] + buffers["http_uri"] + buffers["http_header"] + buffers["http_client_body"]
        byte_buffers = {target: [view.encode("utf-8") for view in views] for target, views in buffers.items()}
        first_alert = None
        for rule in self.rules:
            matched = True
            for content in rule.contents:
                if not byte_buffers[content.target]:
                    matched = False
                    break
                pattern = content.pattern.lower() if content.nocase else content.pattern
                found = False
                for view in byte_buffers[content.target]:
                    view = view[content.offset:]
                    if content.depth:
                        view = view[:content.depth]
                    if content.nocase:
                        view = view.lower()
                    if pattern in view:
                        found = True
                        break
                if found == content.negated:
                    matched = False
                    break
            if not matched:
                continue
            for pcre in rule.pcres:
                if not buffers[pcre.target]:
                    matched = False
                    break
                found = any(pcre.regex.search(view) is not None for view in buffers[pcre.target])
                if found == pcre.negated:
                    matched = False
                    break
            if matched:
                result = (rule.action in ("drop", "block", "reject"), rule,
                          f"[SID {rule.sid}] {rule.classtype}: {rule.msg}")
                if result[0]:
                    return result
                if first_alert is None:
                    first_alert = result
        return first_alert or (False, None, "")


SAFE_INTEGER = (1 << 53) - 1
MAX_JSON_DEPTH = 64
MAX_JSON_TOKENS = 100000
MAX_FIELD_BYTES = 8192
MAX_RANGE_MEMBERS = 16
MAX_ENTITY_TAG_LIST_MEMBERS = 128
MAX_CHUNK_LINE_BYTES = 8192
MAX_DATA_CHUNKS = 4096
MAX_CHUNK_EXTENSION_BYTES = 64 * 1024
MAX_CHUNK_FRAMING_BYTES = 192 * 1024
MAX_INSPECTION_ATTEMPTS = 1000
MAX_SESSION_INSPECTION_BYTES = 64 * 1024 * 1024
MAX_SESSION_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_RPC_MESSAGES = 10000
MAX_RPC_BYTES = 64 * 1024 * 1024
METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
DENIED_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection", "upgrade", "trailer", "te",
    "expect", "keep-alive", "http2-settings", "forwarded", "x-original-url", "x-rewrite-url",
    "x-http-method-override", "x-method-override", "x-http-method", "x-host", "origin", "referer",
    "content-transfer-encoding", "x-original-host", "x-real-ip", "x-agent-id", "x-approval-token",
}
MAX_RESPONSE_METADATA_PARTS = 128
RESPONSE_SINGLETON_HEADERS = {
    "content-length", "transfer-encoding", "content-encoding", "content-type", "content-disposition",
    "content-location", "content-range", "date", "etag", "last-modified", "location",
    "retry-after", "server",
}
RESPONSE_CONNECTION_PROTECTED = (DENIED_HEADERS - {"keep-alive"}) | {
    "connection", "content-type", "content-encoding", "content-language", "content-location",
    "content-range", "content-disposition", "content-digest", "repr-digest", "want-content-digest", "want-repr-digest", "authorization", "proxy-authorization",
    "www-authenticate", "proxy-authenticate", "authentication-info", "proxy-authentication-info",
    "cookie", "set-cookie", "location", "date", "age", "expires", "retry-after", "server",
    "etag", "last-modified", "cache-control", "vary", "warning", "allow", "accept-ranges",
    "range", "if-match", "if-none-match", "if-modified-since", "if-unmodified-since", "if-range",
}
RESPONSE_CONNECTION_PREFIXES = ("proxy-", "sec-", "x-forwarded")
TOKEN_PREFIX = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
# Request subset of RFC 9110 sections 5.6.4 and 5.6.6: one optional UTF-8
# charset with quoted pairs. SP is allowed around ';', never around '='.
REQUEST_MEDIA_TOKEN = r"[!#$%&'*+.^_`|~0-9a-z-]+"
REQUEST_MEDIA_TYPE = re.compile(
    r"(" + REQUEST_MEDIA_TOKEN + r"/" + REQUEST_MEDIA_TOKEN + r")(?: *; *charset=("
    + REQUEST_MEDIA_TOKEN + r'|"(?:[\x20-\x21\x23-\x5b\x5d-\x7e]|\\[\x20-\x7e])*"))?',
    re.I | re.ASCII,
)
IPV4_DENY = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "168.63.129.16/32",
))
IPV6_PUBLIC = ipaddress.ip_network("2000::/3")
IPV6_DENY = tuple(ipaddress.ip_network(value) for value in (
    "2001::/23", "2001:db8::/32", "2002::/16", "2620:4f:8000::/48", "3fff::/20",
))
MAX_RESOLVED_ADDRESSES = 64  # Local work bound, including duplicate entries.
DNS_SLOTS = threading.BoundedSemaphore(4)


class ProtocolPolicyError(ValueError):
    """A privacy-safe policy error with no supplied URL, header or body text."""


def validate_response_media_type(value):
    """Validate bounded RFC 9110 media syntax and the broker's UTF-8 policy."""
    if len(value) > MAX_FIELD_BYTES or any(ord(char) < 32 or ord(char) > 126 for char in value):
        raise ProtocolPolicyError("Invalid response Content-Type")
    value = value.strip(" ")

    def token(position):
        match = TOKEN_PREFIX.match(value, position)
        if match is None:
            raise ProtocolPolicyError("Invalid response media type token")
        return match.group(), match.end()

    def spaces(position):
        while position < len(value) and value[position] == " ":
            position += 1
        return position

    main_type, position = token(0)
    if position >= len(value) or value[position] != "/":
        raise ProtocolPolicyError("Invalid response media type")
    subtype, position = token(position + 1)
    kind, parameters = (main_type + "/" + subtype).lower(), {}
    names = set()
    slots = 0
    while True:
        position = spaces(position)
        if position == len(value):
            return kind, parameters
        if value[position] != ";":
            raise ProtocolPolicyError("Ambiguous response Content-Type")
        slots += 1
        if slots > MAX_RESPONSE_METADATA_PARTS:
            raise ProtocolPolicyError("Response media parameter limit exceeded")
        position = spaces(position + 1)
        if position == len(value):
            return kind, parameters
        if value[position] == ";":
            continue  # RFC 9110 permits empty parameter slots.
        name, position = token(position)
        name = name.lower()
        if name in names or "*" in name:
            raise ProtocolPolicyError("Duplicate or extended response media parameter")
        names.add(name)
        # RFC 9110 parameters do not allow whitespace around '='.
        if position >= len(value) or value[position] != "=":
            raise ProtocolPolicyError("Invalid response media parameter")
        position += 1
        if position < len(value) and value[position] == '"':
            position += 1
            decoded = []
            while True:
                if position == len(value):
                    raise ProtocolPolicyError("Unterminated response media parameter")
                char = value[position]
                position += 1
                if char == '"':
                    break
                if char == "\\":
                    if position == len(value):
                        raise ProtocolPolicyError("Invalid response media quoted pair")
                    char = value[position]
                    position += 1
                decoded.append(char)
            parameter = "".join(decoded)
        else:
            parameter, position = token(position)
        if name == "charset" and parameter.lower() != "utf-8":
            raise ProtocolPolicyError("Only UTF-8 response charset is supported")
        parameters[name] = parameter


_DISPOSITION_GRANDFATHERED_LANGUAGES = frozenset("""en-gb-oed i-ami i-bnn i-default i-enochian i-hak
i-klingon i-lux i-mingo i-navajo i-pwn i-tao i-tay i-tsu sgn-be-fr sgn-be-nl sgn-ch-de
art-lojban cel-gaulish no-bok no-nyn zh-guoyu zh-hakka zh-min zh-min-nan zh-xiang""".split())


def _disposition_language(value):
    """RFC 5646 well-formedness, without registry or extension interpretation."""
    value = value.lower()
    if not value or value in _DISPOSITION_GRANDFATHERED_LANGUAGES:
        return True
    parts = value.split("-")
    if any(not re.fullmatch(r"[a-z0-9]{1,8}", part) for part in parts):
        return False
    if parts[0] == "x":
        return len(parts) > 1
    if len(parts[0]) < 2 or not parts[0].isalpha():
        return False
    i = 1
    if len(parts[0]) <= 3:
        for _ in range(3):
            if i < len(parts) and len(parts[i]) == 3 and parts[i].isalpha():
                i += 1
            else:
                break
    if i < len(parts) and len(parts[i]) == 4 and parts[i].isalpha():
        i += 1
    if i < len(parts) and (len(parts[i]) == 2 and parts[i].isalpha() or len(parts[i]) == 3 and parts[i].isdigit()):
        i += 1
    variants, extensions = set(), set()
    while i < len(parts) and (len(parts[i]) >= 5 or len(parts[i]) == 4 and parts[i][0].isdigit()):
        if parts[i] in variants:
            return False
        variants.add(parts[i])
        i += 1
    while i < len(parts) and parts[i] != "x":
        if len(parts[i]) != 1 or parts[i] in extensions:
            return False
        extensions.add(parts[i])
        i += 1
        first = i
        while i < len(parts) and len(parts[i]) >= 2:
            i += 1
        if i == first:
            return False
    return i == len(parts) or i + 1 < len(parts)


def _decode_disposition_extended(value):
    parts = value.split("'", 2)
    if len(parts) != 3 or not _disposition_language(parts[1]) or not re.fullmatch(r"(?:[a-zA-Z0-9!#$&+.^_`|~-]|%[a-fA-F0-9]{2})*", parts[2]):
        raise ProtocolPolicyError("Invalid HTTP Content-Disposition extended parameter")
    encoding = {"utf-8": "utf-8", "iso-8859-1": "latin-1"}.get(parts[0].lower())
    if encoding is None:
        raise ProtocolPolicyError("Unsupported HTTP Content-Disposition charset")
    try:
        # RFC 8187 permits legacy Latin-1 recipient support. '+' stays literal.
        return urllib.parse.unquote_to_bytes(parts[2]).decode(encoding, errors="strict")
    except UnicodeError as exc:
        raise ProtocolPolicyError("Invalid HTTP Content-Disposition encoded text") from exc


def _disposition_filename(value):
    # Advisory metadata, never authorization to write a file. Apply the same
    # conservative path/normalization exclusions regardless of the host OS.
    return bool(value) and value.strip() == value and not value.endswith(".") and not any(char in value for char in '\\/:<>|?*"') and not re.search(r"%[0-9a-fA-F]{2}", value) and not any(
        unicodedata.category(char) in ("Cc", "Cf") or 0xFDD0 <= ord(char) <= 0xFDEF or ord(char) & 0xFFFF >= 0xFFFE for char in value)


def validate_response_disposition(value):
    """Validate HTTP syntax before duplicate/continuation/encoding recovery."""
    def invalid():
        raise ProtocolPolicyError("Invalid or unsafe HTTP Content-Disposition")
    if len(value) > MAX_FIELD_BYTES or any(ord(char) < 32 or ord(char) > 126 for char in value):
        invalid()
    value = value.strip(" ")
    def spaces(position):
        while position < len(value) and value[position] == " ":
            position += 1
        return position
    def token(position):
        match = TOKEN_PREFIX.match(value, position)
        if match is None:
            invalid()
        return match.group(), match.end()
    _, position = token(0)
    seen = set()
    while True:
        position = spaces(position)
        if position == len(value):
            return
        if value[position] != ";":
            invalid()
        name, position = token(spaces(position + 1))
        name = name.lower()
        if name in seen or len(seen) >= MAX_RESPONSE_METADATA_PARTS or re.search(r"\*[0-9]+\*?$", name):
            invalid()
        seen.add(name)
        position = spaces(position)
        if position == len(value) or value[position] != "=":
            invalid()
        position = spaces(position + 1)
        quoted, escaped = position < len(value) and value[position] == '"', False
        if quoted:
            position += 1
            decoded = []
            while True:
                if position == len(value):
                    invalid()
                char = value[position]
                position += 1
                if char == '"':
                    break
                if char == "\\":
                    escaped = True
                    if position == len(value):
                        invalid()
                    char = value[position]
                    position += 1
                decoded.append(char)
            parameter = "".join(decoded)
        else:
            parameter, position = token(position)
        if name.endswith("*"):
            if quoted:
                invalid()
            parameter = _decode_disposition_extended(parameter)
        if name in ("filename", "filename*") and (escaped or not _disposition_filename(parameter)):
            invalid()


def _digest_invalid():
    raise ProtocolPolicyError("Message violates the HTTP digest integrity policy")


class _DigestParser:
    """RFC 8941 subset selected by RFC 9530, including opaque parameters."""
    def __init__(self, value):
        self.text, self.position = value.strip(" "), 0

    def take(self, char):
        if self.position < len(self.text) and self.text[self.position] == char:
            self.position += 1
            return True
        return False

    def space(self):
        while self.take(" "):
            pass

    def key(self):
        match = re.compile(r"[a-z*][a-z0-9_.*-]*").match(self.text, self.position)
        if match is None:
            _digest_invalid()
        self.position = match.end()
        return match.group()

    def parameters(self):
        count = 0
        while self.take(";"):
            count += 1
            if count > 256:
                _digest_invalid()
            self.space()
            self.key()
            if self.take("="):
                self.bare()

    def binary(self):
        if not self.take(":"):
            _digest_invalid()
        end = self.text.find(":", self.position)
        if end < 0:
            _digest_invalid()
        encoded = self.text[self.position:end]
        self.position = end + 1
        if re.fullmatch(r"[A-Za-z0-9+/=]*", encoded) is None:
            _digest_invalid()
        unpadded = encoded.rstrip("=")
        padding = (-len(unpadded)) % 4
        if len(unpadded) % 4 == 1 or "=" in unpadded or len(encoded)-len(unpadded) > padding:
            _digest_invalid()
        try:
            # RFC 8941 tolerates absent padding and nonzero unused pad bits.
            return base64.b64decode(unpadded + "="*padding, validate=True)
        except ValueError:
            _digest_invalid()

    def bare(self):
        if self.position == len(self.text):
            _digest_invalid()
        char = self.text[self.position]
        if char == ":":
            self.binary()
        elif self.take("?"):
            if not (self.take("0") or self.take("1")):
                _digest_invalid()
        elif self.take('"'):
            while True:
                if self.position == len(self.text):
                    _digest_invalid()
                char = self.text[self.position]
                self.position += 1
                if char == '"':
                    break
                if char == "\\" and not (self.take("\\") or self.take('"')):
                    _digest_invalid()
        elif char in "-0123456789":
            match = re.compile(r"-?[0-9]+(?:\.[0-9]+)?").match(self.text, self.position)
            if match is None:
                _digest_invalid()
            integer, dot, fraction = match.group().lstrip("-").partition(".")
            if len(integer) > (12 if dot else 15) or dot and len(fraction) > 3:
                _digest_invalid()
            self.position = match.end()
        else:
            match = re.compile(r"[A-Za-z*][!#$%&'*+.^_`|~0-9A-Za-z:/-]*").match(self.text, self.position)
            if match is None:
                _digest_invalid()
            self.position = match.end()


def parse_content_digest(values):
    if values is None:
        return {}
    if not values or len(values) > MAX_HEADERS or sum(map(len, values)) > MAX_HEADER_BYTES:
        _digest_invalid()
    members = {}
    for value in values:
        if len(value) > MAX_FIELD_BYTES or any(ord(c) < 32 or ord(c) > 126 for c in value):
            _digest_invalid()
        parser = _DigestParser(value)
        while True:
            key = parser.key()
            if key in members or len(members) >= 1024 or not parser.take("="):
                _digest_invalid()
            decoded = parser.binary()
            if key in ("sha-256", "sha-512") and len(decoded) != {"sha-256":32, "sha-512":64}[key]:
                _digest_invalid()
            members[key] = decoded
            parser.parameters()
            parser.space()
            if parser.position == len(parser.text):
                break
            if not parser.take(","):
                _digest_invalid()
            parser.space()
            # key() rejects empty members, including a trailing comma.
    if not ("sha-256" in members or "sha-512" in members):
        _digest_invalid()
    return members


def parse_digest_preferences(values):
    if values is None:
        return {}
    if not values or len(values) > MAX_HEADERS or sum(map(len, values)) > MAX_HEADER_BYTES:
        _digest_invalid()
    members = {}
    for value in values:
        if len(value) > MAX_FIELD_BYTES or any(ord(c) < 32 or ord(c) > 126 for c in value):
            _digest_invalid()
        parser = _DigestParser(value)
        if not parser.text:
            if len(values) != 1:
                _digest_invalid()  # Combined empty field lines produce empty members.
            return {}
        while True:
            key = parser.key()
            if key in members or len(members) >= 1024 or not parser.take("="):
                _digest_invalid()
            weight = re.compile(r"-?[0-9]+").match(parser.text, parser.position)
            if weight is None or len(weight.group().lstrip("-")) > 15:
                _digest_invalid()
            number = int(weight.group())
            if not 0 <= number <= 10:
                _digest_invalid()
            parser.position = weight.end()
            parser.parameters()
            members[key] = number
            parser.space()
            if parser.position == len(parser.text):
                break
            if not parser.take(","):
                _digest_invalid()
            parser.space()
            # key() rejects a trailing comma or another empty dictionary member.
    return members


def validate_content_digest(fields, body):
    members = parse_content_digest(fields.get("content-digest"))
    validate_digest_members(members, body)


def validate_digest_members(members, body):
    for algorithm, factory in (("sha-256", hashlib.sha256), ("sha-512", hashlib.sha512)):
        if algorithm in members and factory(body).digest() != members[algorithm]:
            _digest_invalid()


def _representation_unavailable():
    raise ProtocolPolicyError("Representation digest requires complete representation data")


def validate_response_representation_metadata(fields, status, method):
    members = parse_content_digest(fields.get("repr-digest"))
    if not members:
        return members
    if status < 200:
        validate_digest_members(members, b"")
    elif status in (204, 205):
        _representation_unavailable()
    elif method == "HEAD" or status == 304:
        if fields.get("content-length") != ["0"]:
            _representation_unavailable()
        validate_digest_members(members, b"")
    elif status == 206:
        kind = validate_response_media_type(fields["content-type"][0])[0] if "content-type" in fields else ""
        if kind != "multipart/byteranges":
            if len(fields.get("content-range", [])) != 1:
                _representation_unavailable()
            interval = parse_content_range(fields["content-range"][0])
            if interval.first != 0 or interval.complete is None or interval.size != interval.complete:
                _representation_unavailable()
    return members


def _uri_reference_invalid():
    raise ProtocolPolicyError("Invalid HTTP URI-reference metadata")


def _uri_component(value, extra="", percent=True):
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=" + extra
    position = 0
    while position < len(value):
        char = value[position]
        if char == "%" and percent:
            if position + 2 >= len(value) or any(c not in "0123456789abcdefABCDEF" for c in value[position+1:position+3]):
                return False
            position += 3
        elif char in allowed:
            position += 1
        else:
            return False
    return True


def _uri_authority(authority, http_context):
    if "@" in authority:
        userinfo, authority = authority.split("@", 1)
        if http_context or not _uri_component(userinfo, ":"):
            return False
    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0:
            return False
        host, suffix = authority[1:closing], authority[closing+1:]
        if suffix and not suffix.startswith(":"):
            return False
        port = suffix[1:]
        if host[:1] in ("v", "V"):
            version, dot, address = host[1:].partition(".")
            if not dot or not version or not address or any(c not in "0123456789abcdefABCDEF" for c in version) or not _uri_component(address, ":", percent=False):
                return False
        else:
            if "%" in host:
                return False
            try:
                ipaddress.IPv6Address(host)
            except ValueError:
                return False
    else:
        host, _, port = authority.partition(":")
        if not _uri_component(host):
            return False
    return (not http_context or bool(host)) and all(c in "0123456789" for c in port)


def validate_uri_reference(value, allow_fragment=False):
    """RFC 3986 syntax, with RFC 9110 HTTP authorities; never resolve or fetch.

    Percent octets remain opaque. Other schemes receive generic syntax checks;
    network-path references inherit the HTTP(S) target context. Content-Location
    excludes fragments. Actual destinations still require separate admission.
    """
    if len(value) > MAX_FIELD_BYTES or any(ord(c) <= 32 or ord(c) > 126 for c in value):
        _uri_reference_invalid()
    rest, marker, fragment = value.partition("#")
    if marker and (not allow_fragment or not _uri_component(fragment, ":@/?")):
        _uri_reference_invalid()
    path, marker, query = rest.partition("?")
    if marker and not _uri_component(query, ":@/?"):
        _uri_reference_invalid()
    scheme = ""
    colon, slash = path.find(":"), path.find("/")
    if colon >= 0 and (slash < 0 or colon < slash):
        scheme, path = path[:colon], path[colon+1:]
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*", scheme):
            _uri_reference_invalid()
        scheme = scheme.lower()
    http_scheme = scheme in ("http", "https")
    if path.startswith("//"):
        authority, separator, tail = path[2:].partition("/")
        if not _uri_authority(authority, http_scheme or not scheme):
            _uri_reference_invalid()
        path = "/" + tail if separator else ""
    elif http_scheme:
        _uri_reference_invalid()
    if not _uri_component(path, ":@/"):
        _uri_reference_invalid()


def validate_response_metadata(fields, multipart_part=False):
    """Check explicit metadata fields; unknown header semantics stay untrusted."""
    connection_parts = 0
    date_keys = {}
    for name, values in fields.items():
        if name in ("content-disposition", "content-digest", "repr-digest", "want-content-digest", "want-repr-digest") and multipart_part:
            continue  # HTTP message fields are separate from MIME payload metadata.
        if name in RESPONSE_SINGLETON_HEADERS and len(values) != 1:
            raise ProtocolPolicyError("Duplicate singleton response header")
        if name in ("want-content-digest", "want-repr-digest"):
            parse_digest_preferences(values)
        elif name in ("content-digest", "repr-digest"):
            parse_content_digest(values)
        elif name == "content-disposition":
            validate_response_disposition(values[0])
        elif name in ("location", "content-location") and not multipart_part:
            if len(name) + len(values[0]) + 4 > MAX_FIELD_BYTES:
                _uri_reference_invalid()
            validate_uri_reference(values[0].strip(" "), allow_fragment=name == "location")
        elif name == "content-type":
            validate_response_media_type(values[0])
        elif name == "content-range":
            parse_content_range(values[0].strip(" "))
        elif name == "etag":
            validate_entity_tag(values[0].strip(" "))
        elif name in ("date", "last-modified"):
            date_keys[name] = validate_http_date(values[0].strip(" "), allow_obsolete=True)
        elif name == "connection":
            for value in values:
                parts = value.split(",")
                connection_parts += len(parts)
                if connection_parts > MAX_RESPONSE_METADATA_PARTS:
                    raise ProtocolPolicyError("Response Connection option limit exceeded")
                for part in parts:
                    option = part.strip(" ").lower()
                    if not option:
                        continue  # Bounded empty-list tolerance, RFC 9110 5.6.1.2.
                    if not TOKEN.fullmatch(option):
                        raise ProtocolPolicyError("Invalid response Connection option")
                    if option in RESPONSE_CONNECTION_PROTECTED or option.startswith(RESPONSE_CONNECTION_PREFIXES):
                        raise ProtocolPolicyError("Response Connection nominates protected metadata")
    if "date" in date_keys and date_keys.get("last-modified", "") > date_keys["date"]:
        raise ProtocolPolicyError("Last-Modified is later than response Date")


def _valid_json_string(value):
    value.encode("utf-8", errors="strict")
    if any(0xFDD0 <= ord(char) <= 0xFDEF or ord(char) & 0xFFFF in (0xFFFE, 0xFFFF) for char in value):
        raise ProtocolPolicyError("JSON Unicode noncharacters are unsupported")


def strict_json_loads(text):
    """Preflight nesting/work before parsing, then enforce interoperable JSON."""
    text.encode("utf-8", errors="strict")
    quoted = escaped = False
    depth = tokens = 0
    in_atom = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == '"':
            tokens += 1
            quoted = True
            in_atom = False
        elif char in "[{":
            depth += 1
            tokens += 1
            in_atom = False
            if depth > MAX_JSON_DEPTH:
                raise ProtocolPolicyError("JSON exceeds the nesting limit")
        elif char in "]}":
            depth -= 1
            in_atom = False
        elif char in " \r\n\t,:":
            in_atom = False
        elif not in_atom:
            tokens += 1
            in_atom = True
        if tokens > MAX_JSON_TOKENS:
            raise ProtocolPolicyError("JSON exceeds the token limit")

    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            _valid_json_string(key)
            if key in result:
                raise ProtocolPolicyError("JSON contains duplicate object keys")
            result[key] = value
        return result

    def integer(value):
        number = int(value)
        if abs(number) > SAFE_INTEGER:
            raise ProtocolPolicyError("JSON integer exceeds the interoperable range")
        return number

    def floating(value):
        number = float(value)
        if not math.isfinite(number) or number.is_integer() and abs(number) > SAFE_INTEGER:
            raise ProtocolPolicyError("JSON number is not finite or interoperable")
        return number

    def constant(_):
        raise ProtocolPolicyError("JSON non-finite literals are unsupported")

    try:
        result = json.loads(text, object_pairs_hook=object_pairs, parse_int=integer,
                            parse_float=floating, parse_constant=constant)
    except (ValueError, RecursionError, OverflowError) as exc:
        raise ProtocolPolicyError("Invalid or non-interoperable JSON") from exc
    pending = [result]
    while pending:
        value = pending.pop()
        if isinstance(value, str):
            _valid_json_string(value)
        elif isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return result


_XML_DECLARATION = re.compile(r'''<\?xml[ \t\r\n]+version[ \t\r\n]*=[ \t\r\n]*("1\.0"|'1\.0')([ \t\r\n]+encoding[ \t\r\n]*=[ \t\r\n]*("(?i:utf-8)"|'(?i:utf-8)'))?([ \t\r\n]+standalone[ \t\r\n]*=[ \t\r\n]*("(yes|no)"|'(yes|no)'))?[ \t\r\n]*\?>''')
_XML_NAMESPACE = "http://www.w3.org/XML/1998/namespace"
_XMLNS_NAMESPACE = "http://www.w3.org/2000/xmlns/"
_XML_SPACE = " \t\r\n"


def _xml_character(c):
    return c in (9, 10, 13) or 0x20 <= c <= 0xD7FF or 0xE000 <= c <= 0xFFFD or 0x10000 <= c <= 0x10FFFF


def _xml_name_start(c):
    n = ord(c)
    return (c == "_" or "A" <= c <= "Z" or "a" <= c <= "z" or
            0xC0 <= n <= 0xD6 or 0xD8 <= n <= 0xF6 or 0xF8 <= n <= 0x2FF or
            0x370 <= n <= 0x37D or 0x37F <= n <= 0x1FFF or 0x200C <= n <= 0x200D or
            0x2070 <= n <= 0x218F or 0x2C00 <= n <= 0x2FEF or 0x3001 <= n <= 0xD7FF or
            0xF900 <= n <= 0xFDCF or 0xFDF0 <= n <= 0xFFFD or 0x10000 <= n <= 0xEFFFF)


def _xml_name_continue(c):
    n = ord(c)
    return _xml_name_start(c) or c in "-." or "0" <= c <= "9" or n == 0xB7 or 0x300 <= n <= 0x36F or 0x203F <= n <= 0x2040


def _xml_ncname(name):
    return bool(name) and _xml_name_start(name[0]) and all(_xml_name_continue(c) for c in name[1:])


def _xml_qname(name):
    parts = name.split(":")
    return len(parts) in (1, 2) and all(_xml_ncname(part) for part in parts)


class _XMLAdmission:
    """Bounded XML 1.0 Fifth Edition recognizer; no external resource loading."""
    def __init__(self, text):
        self.text = text
        self.position = self.beginning = 1 if text.startswith("\ufeff") else 0
        self.units = 0
        self.root = False
        self.stack = []
        self.namespaces = {"xml": _XML_NAMESPACE}

    def unit(self):
        self.units += 1
        return self.units <= 100000

    def space(self):
        while self.position < len(self.text) and self.text[self.position] in _XML_SPACE:
            self.position += 1

    def take(self, value):
        if not self.text.startswith(value, self.position):
            return False
        self.position += len(value)
        return True

    def name(self):
        start, size = self.position, 0
        while self.position < len(self.text):
            c = self.text[self.position]
            if c != ":" and not (_xml_name_start(c) if self.position == start else _xml_name_continue(c)):
                break
            self.position += 1
            size += len(c.encode("utf-8"))
            if size > 1024:
                return ""
        return self.text[start:self.position]

    def value(self, raw, attribute=False):
        out, i = [], 0
        while i < len(raw):
            c = raw[i]
            if attribute and c == "<":
                return None
            if c == "&":
                end = raw.find(";", i, i+32)
                if end < 0 or not self.unit():
                    return None
                ref = raw[i+1:end]
                decoded = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}.get(ref)
                if decoded is None:
                    if not ref.startswith("#"):
                        return None
                    digits, base = ref[1:], 10
                    if digits.startswith("x"):
                        digits, base = digits[1:], 16
                    alphabet = "0123456789abcdefABCDEF" if base == 16 else "0123456789"
                    if not digits or any(c not in alphabet for c in digits):
                        return None
                    code = int(digits, base)
                    if not _xml_character(code):
                        return None
                    decoded = chr(code)
                if attribute:
                    out.append(decoded)
                i = end+1
                continue
            if attribute:
                if c == "\r":
                    if i+1 < len(raw) and raw[i+1] == "\n":
                        i += 1
                    c = " "
                elif c in "\n\t":
                    c = " "
                out.append(c)
            i += 1
        return "".join(out)

    def document(self):
        while self.position < len(self.text):
            start = self.position
            if self.text[start] != "<":
                end = self.text.find("<", start)
                if end < 0:
                    end = len(self.text)
                raw = self.text[start:end]
                if not self.stack:
                    if any(c not in _XML_SPACE for c in raw):
                        return False
                elif "]]>" in raw or self.value(raw) is None:
                    return False
                self.position = end
                continue
            if not self.unit():
                return False
            if self.take("<!--"):
                end = self.text.find("-->", self.position)
                if end < 0 or len(self.text[start:end+3].encode()) > 65536:
                    return False
                raw = self.text[self.position:end]
                if "--" in raw or raw.endswith("-"):
                    return False
                self.position = end+3
            elif self.take("<![CDATA["):
                if not self.stack:
                    return False
                end = self.text.find("]]>", self.position)
                if end < 0:
                    return False
                self.position = end+3
            elif self.take("<?"):
                target = self.name()
                if not _xml_ncname(target):
                    return False
                end = self.text.find("?>", self.position)
                if end < 0 or len(self.text[start:end+2].encode()) > 65536 or end > self.position and self.text[self.position] not in _XML_SPACE:
                    return False
                self.position = end+2
                if target.lower() == "xml" and (target != "xml" or start != self.beginning or not _XML_DECLARATION.fullmatch(self.text[start:self.position])):
                    return False
            elif self.take("</"):
                name = self.name()
                self.space()
                if not _xml_qname(name) or not self.take(">") or not self.stack or self.stack[-1][0] != name or len(self.text[start:self.position].encode()) > 65536:
                    return False
                self.close()
            elif self.text.startswith("<!", self.position):
                return False  # Reject DTDs before any entity processing.
            elif not self.element():
                return False
        return self.root and not self.stack

    def element(self):
        start = self.position
        if not self.take("<"):
            return False
        name = self.name()
        if not _xml_qname(name) or len(self.stack) >= 64 or not self.stack and self.root:
            return False
        attrs, seen, empty = [], set(), False
        while True:
            before = self.position
            self.space()
            if self.take("/>"):
                empty = True
                break
            if self.take(">"):
                break
            if before == self.position or len(attrs) >= 128:
                return False
            key = self.name()
            if not _xml_qname(key) or key in seen:
                return False
            seen.add(key)
            self.space()
            if not self.take("="):
                return False
            self.space()
            if self.position >= len(self.text) or self.text[self.position] not in "'\"":
                return False
            quote = self.text[self.position]
            self.position += 1
            end = self.text.find(quote, self.position)
            if end < 0 or len(self.text[start:end+1].encode()) > 65536:
                return False
            value = self.value(self.text[self.position:end], True)
            if value is None:
                return False
            self.position = end+1
            attrs.append((key, value))
        if len(self.text[start:self.position].encode()) > 65536:
            return False
        bindings = []
        for key, value in attrs:
            if key != "xmlns" and not key.startswith("xmlns:"):
                continue
            prefix = key[6:] if key.startswith("xmlns:") else ""
            if (prefix == "xmlns" or prefix == "xml" and value != _XML_NAMESPACE or
                    prefix != "xml" and value == _XML_NAMESPACE or value == _XMLNS_NAMESPACE or prefix and not value or
                    any(ord(c) <= 32 or ord(c) == 127 for c in value)):
                return False
            bindings.append((prefix, self.namespaces.get(prefix)))
            self.namespaces[prefix] = value
        if ":" in name:
            prefix = name.split(":", 1)[0]
            if prefix == "xmlns" or not self.namespaces.get(prefix):
                return False
        expanded = set()
        for key, value in attrs:
            if key == "xmlns" or key.startswith("xmlns:"):
                continue
            uri, local = "", key
            if ":" in key:
                prefix, local = key.split(":")
                uri = self.namespaces.get(prefix)
                if not uri:
                    return False
            identity = (uri, local)
            if identity in expanded:
                return False
            expanded.add(identity)
        self.root = True
        self.stack.append((name, bindings))
        if empty:
            self.close()
        return True

    def close(self):
        _, bindings = self.stack.pop()
        for prefix, previous in bindings:
            if previous is None:
                self.namespaces.pop(prefix, None)
            else:
                self.namespaces[prefix] = previous


def validate_response_xml(body):
    if len(body) > MAX_RESPONSE_BYTES:
        raise ProtocolPolicyError("Response violates the XML interoperability policy")
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ProtocolPolicyError("Response violates the XML interoperability policy") from exc
    if any(not _xml_character(ord(c)) for c in text) or not _XMLAdmission(text).document():
        raise ProtocolPolicyError("Response violates the XML interoperability policy")


def _percent_syntax(value):
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise ProtocolPolicyError("Malformed percent encoding")


def strict_http_url(value, origin_only=False):
    if not isinstance(value, str) or not value or len(value) > MAX_URL_BYTES:
        raise ProtocolPolicyError("Invalid or oversized HTTP URL")
    if not value.isascii() or re.search(r'[\x00-\x20\x7f\\#"<> {}|^`]', value):
        raise ProtocolPolicyError("HTTP URL contains unsupported characters")
    if not re.match(r"^https?://", value):
        raise ProtocolPolicyError("Only absolute HTTP(S) URLs are supported")
    _percent_syntax(value)
    try:
        parsed = urllib.parse.urlsplit(value)
        host = parsed.hostname
        if not host or parsed.username is not None or parsed.password is not None or "%" in parsed.netloc:
            raise ValueError()
        authority = parsed.netloc
        if authority.startswith("["):
            closing = authority.find("]")
            if closing < 0 or authority[closing + 1:] and not authority[closing + 1:].startswith(":"):
                raise ValueError()
            address = ipaddress.IPv6Address(host)
            if address.ipv4_mapped is not None or str(address) != host or host != authority[1:closing]:
                raise ValueError()
            port_text = authority[closing + 2:] if authority[closing + 1:] else None
        else:
            if "[" in authority or "]" in authority or authority.count(":") > 1:
                raise ValueError()
            port_text = authority.split(":", 1)[1] if ":" in authority else None
            if re.fullmatch(r"[0-9.]+", host):
                if str(ipaddress.IPv4Address(host)) != host:
                    raise ValueError()
            else:
                if all(re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", label) for label in host.split(".")):
                    raise ValueError()
                last_label = host.rsplit(".", 1)[-1]
                if last_label.isdigit() or last_label.startswith("0x") or len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
                    raise ValueError()
        if port_text is not None and (not re.fullmatch(r"[1-9][0-9]{0,4}", port_text) or int(port_text) > 65535):
            raise ValueError()
        if any(char in parsed.path + parsed.query for char in "[]"):
            raise ValueError()
        for component in (parsed.path, parsed.query):
            decoded = urllib.parse.unquote_to_bytes(component)
            decoded.decode("utf-8", errors="strict")
            if any(byte < 32 or byte == 127 or byte == 92 for byte in decoded):
                raise ValueError()
        if origin_only and (parsed.path or "?" in value):
            raise ValueError()
        return parsed, (parsed.scheme, host, parsed.port or (443 if parsed.scheme == "https" else 80))
    except (ValueError, OverflowError) as exc:
        raise ProtocolPolicyError("Ambiguous or unsupported HTTP URL") from exc


def _entity_tag_prefix(value, position=0):
    # RFC 9110 entity tags have no quoted-pair/backslash escaping.
    weak = value.startswith("W/", position)
    if weak:
        position += 2
    if position >= len(value) or value[position] != '"':
        raise ProtocolPolicyError("Invalid entity tag")
    position += 1
    while position < len(value):
        if value[position] == '"':
            return position + 1, weak
        if not 33 <= ord(value[position]) <= 126:
            raise ProtocolPolicyError("Invalid entity tag bytes")
        position += 1
    raise ProtocolPolicyError("Unterminated entity tag")


def validate_entity_tag(value):
    if len(value) > MAX_FIELD_BYTES:
        raise ProtocolPolicyError("Entity tag exceeds field limit")
    end, weak = _entity_tag_prefix(value)
    if end != len(value):
        raise ProtocolPolicyError("Entity tag has trailing data")
    return weak


def validate_entity_tag_list(value):
    if len(value) > MAX_FIELD_BYTES:
        raise ProtocolPolicyError("Entity tag list exceeds field limit")
    if value == "*":
        return
    position = tags = slots = 0
    while True:
        slots += 1
        if slots > MAX_ENTITY_TAG_LIST_MEMBERS:
            raise ProtocolPolicyError("Entity tag list exceeds member limit")
        while position < len(value) and value[position] == " ":
            position += 1
        if position < len(value) and value[position] != ",":
            position, _ = _entity_tag_prefix(value, position)
            tags += 1
            while position < len(value) and value[position] == " ":
                position += 1
        if position == len(value):
            if not tags:
                raise ProtocolPolicyError("Conditional entity tag list must not be empty")
            return
        if value[position] != ",":
            raise ProtocolPolicyError("Invalid entity tag list separator")
        position += 1


def match_entity_tag_list(value, target, strong=False):
    validate_entity_tag_list(value)
    target_weak = validate_entity_tag(target)
    if value == "*":
        return True
    position = 0
    while position < len(value):
        if value[position] in " ,":
            position += 1
            continue
        end, weak = _entity_tag_prefix(value, position)
        tag = value[position:end]
        if (not strong or not weak and not target_weak) and tag.removeprefix("W/") == target.removeprefix("W/"):
            return True
        position = end
    return False


DATE_WEEKDAY = r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun)"
DATE_MONTH = r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
DATE_TIME = r"([0-9]{2}):([0-9]{2}):([0-9]{2})"
IMF_DATE = re.compile(DATE_WEEKDAY + r", ([0-9]{2}) " + DATE_MONTH + r" ([0-9]{4}) " + DATE_TIME + r" GMT")
OBSOLETE_DATE = re.compile(r"(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), ([0-9]{2})-" + DATE_MONTH + r"-([0-9]{2}) " + DATE_TIME + r" GMT")
ASCTIME_DATE = re.compile(DATE_WEEKDAY + " " + DATE_MONTH + r" ([0-9]{2}| [0-9]) " + DATE_TIME + r" ([0-9]{4})")
MONTH_NAMES = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
WEEKDAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def validate_http_date(value, allow_obsolete=False, now=None):
    """Return a calendar order key preserving leap seconds, not date strength."""
    if len(value) > 40:
        raise ProtocolPolicyError("Invalid HTTP date length")
    match = IMF_DATE.fullmatch(value)
    short_year = False
    fields = match.groups() if match else None
    if fields is None and allow_obsolete:
        match = OBSOLETE_DATE.fullmatch(value)
        if match:
            fields, short_year = match.groups(), True
        else:
            match = ASCTIME_DATE.fullmatch(value)
            if match:
                a = match.groups()
                fields = (a[0], a[2].strip(" "), a[1], a[6], a[3], a[4], a[5])
    if fields is None:
        raise ProtocolPolicyError("Invalid HTTP date grammar")
    weekday, day, month, year, hour, minute, second = fields
    day, month, year = int(day), MONTH_NAMES.index(month) + 1, int(year)
    hour, minute, second = int(hour), int(minute), int(second)
    if hour > 23 or minute > 59 or second > 60 or second == 60 and (hour != 23 or minute != 59):
        raise ProtocolPolicyError("Invalid HTTP time of day")
    # Preserve the leap second's calendar day; datetime has no leap-second value.
    calendar_second = min(second, 59)
    if short_year:
        now = (now or datetime.datetime.now(datetime.timezone.utc)).astimezone(datetime.timezone.utc)
        cutoff = now.replace(year=now.year + 50, day=1) + datetime.timedelta(days=now.day - 1)
        year += cutoff.year // 100 * 100
        # Compare fields without collapsing a leap second into the next day.
        if (year, month, day, hour, minute, second) > (cutoff.year, cutoff.month, cutoff.day, cutoff.hour, cutoff.minute, cutoff.second):
            year -= 100
    try:
        date = datetime.datetime(year, month, day, hour, minute, calendar_second, tzinfo=datetime.timezone.utc)
    except ValueError as exc:
        raise ProtocolPolicyError("Invalid HTTP calendar date") from exc
    if year < 1900 or WEEKDAY_NAMES[date.weekday()] != weekday[:3]:
        raise ProtocolPolicyError("Invalid HTTP year or weekday")
    return f"{year:04d}{month:02d}{day:02d}{hour:02d}{minute:02d}{second:02d}"


def validate_conditional_field(name, value):
    if name in ("if-match", "if-none-match"):
        validate_entity_tag_list(value)
    elif name == "if-range":
        if value.startswith(('"', "W/")):
            if validate_entity_tag(value):
                raise ProtocolPolicyError("If-Range requires a strong entity tag")
        else:
            validate_http_date(value)
    elif name in ("if-modified-since", "if-unmodified-since", "date"):
        validate_http_date(value)


def validate_response_conditions(fields, status, method=None, request_headers=None):
    """Reject observable contradictions, without inferring missing validators."""
    if request_headers is None:
        return  # The production caller supplies the admitted request headers.
    method = method or "GET"
    conditions = {}
    for name, value in request_headers.items():
        key = name.lower()
        if key in ("if-match", "if-none-match", "if-modified-since", "if-unmodified-since", "if-range"):
            if key in conditions:
                raise ProtocolPolicyError("Duplicate conditional request header")
            value = value.strip(" ")
            validate_conditional_field(key, value)
            conditions[key] = value
    read = method in ("GET", "HEAD")
    if status == 304 and (not read or not ("if-none-match" in conditions or "if-modified-since" in conditions)):
        raise ProtocolPolicyError("304 requires a conditional GET or HEAD request")
    # A write's validators describe the post-write representation. Redirects and
    # errors are determined before preconditions and do not assert their result.
    if not read or status not in (200, 206, 304):
        return
    etag = fields.get("etag", [""])[0].strip(" ")
    modified = fields.get("last-modified", [""])[0].strip(" ")
    last_modified = validate_http_date(modified, allow_obsolete=True) if modified else None
    if "if-match" in conditions:
        value = conditions["if-match"]
        if value != "*" and etag and not match_entity_tag_list(value, etag, strong=True):
            raise ProtocolPolicyError("Response contradicts If-Match")
    elif "if-unmodified-since" in conditions and last_modified is not None:
        if last_modified > validate_http_date(conditions["if-unmodified-since"]):
            raise ProtocolPolicyError("Response contradicts If-Unmodified-Since")
    if "if-none-match" in conditions:
        value = conditions["if-none-match"]
        match = None
        if value == "*":
            match = True
        elif etag:
            match = match_entity_tag_list(value, etag)
        if match is not None and match != (status == 304):
            raise ProtocolPolicyError("Response contradicts If-None-Match")
    elif "if-modified-since" in conditions and status == 304 and last_modified is not None:
        if last_modified > validate_http_date(conditions["if-modified-since"]):
            raise ProtocolPolicyError("304 contradicts If-Modified-Since")
        # Evaluating If-Modified-Since is a SHOULD; an older modification date
        # alone does not establish that a 200/206 response is nonconforming.
    if status == 206 and "if-range" in conditions:
        value = conditions["if-range"]
        if value.startswith('"'):
            if etag and etag != value:
                raise ProtocolPolicyError("Partial response contradicts If-Range entity tag")
        elif last_modified is not None and last_modified != validate_http_date(value):
            raise ProtocolPolicyError("Partial response contradicts If-Range date")


def _range_number(text):
    if not text or any(char < "0" or char > "9" for char in text):
        raise ProtocolPolicyError("Invalid byte range number")
    # Avoid unbounded integer conversion and Python's digit-limit behavior.
    digits = text.lstrip("0") or "0"
    if len(digits) > 19 or int(digits) > (1 << 63) - 1:
        raise ProtocolPolicyError("Byte range number exceeds local limit")
    return int(digits)


class ByteRange(NamedTuple):
    first: Optional[int]  # None denotes a suffix whose length is in last.
    last: Optional[int]  # None denotes an open interval.


def validate_byte_range(value):
    """RFC 9110 byte ranges with bounded local count, order and numeric policy."""
    if len(value) > MAX_FIELD_BYTES:
        raise ProtocolPolicyError("Range field exceeds limit")
    unit, equal, remaining = value.partition("=")
    if not equal or unit.lower() != "bytes":
        raise ProtocolPolicyError("Only byte range requests are supported")
    if remaining.count(",") >= MAX_RANGE_MEMBERS:
        raise ProtocolPolicyError("Range request exceeds member limit")

    ranges, previous_end = [], 0
    open_range, suffix = False, False
    for member in remaining.split(","):
        member = member.strip(" ")
        if not member:
            continue
        first, dash, last = member.partition("-")
        if not dash or open_range or suffix:
            raise ProtocolPolicyError("Invalid or overlapping byte range request")
        if not first:
            length = _range_number(last)
            if ranges:
                raise ProtocolPolicyError("Suffix byte range must stand alone")
            suffix = True
            interval = ByteRange(None, length)
        else:
            start = _range_number(first)
            if ranges and start <= previous_end:
                raise ProtocolPolicyError("Byte ranges must be ascending and disjoint")
            if not last:
                open_range = True
                interval = ByteRange(start, None)
            else:
                previous_end = _range_number(last)
                if previous_end < start:
                    raise ProtocolPolicyError("Invalid byte range endpoints")
                interval = ByteRange(start, previous_end)
        ranges.append(interval)
    if not ranges:
        raise ProtocolPolicyError("Range request must contain a range")
    return tuple(ranges)


class ByteContentRange(NamedTuple):
    first: Optional[int]
    last: Optional[int]
    complete: Optional[int]

    @property
    def size(self):
        return 0 if self.first is None else self.last - self.first + 1


def validate_returned_byte_range(requested, returned):
    """Apply local bounds policy, permitting subsets and coalesced intervals."""
    if requested is None:
        return  # Wire validation has no request-field context yet.

    def invalid():
        raise ProtocolPolicyError("Response range lies outside requested bounds")

    if returned is None or returned.first is None:
        invalid()
    starts = ends = False
    for interval in requested:
        first, last = interval
        if first is None:
            if last == 0:
                invalid()
            if returned.complete is None:
                # The absolute origin of a suffix cannot be inferred without
                # the representation length; only its size can be bounded.
                if returned.size <= last:
                    return
                invalid()
            first = max(0, returned.complete - last)
            last = returned.complete - 1
        else:
            if last is None:
                last = (1 << 63) - 1
            if returned.complete is not None:
                if first >= returned.complete:
                    continue  # This requested member is unsatisfiable.
                last = min(last, returned.complete - 1)
        starts = starts or first <= returned.first <= last
        ends = ends or first <= returned.last <= last
    if not starts or not ends:
        invalid()


def parse_content_range(value):
    """Bounded bytes-only Content-Range; lengths are octets, not characters."""
    unit, space, remaining = value.partition(" ")
    interval, slash, complete = remaining.partition("/")
    if len(value) > MAX_FIELD_BYTES or not space or unit.lower() != "bytes" or not slash:
        raise ProtocolPolicyError("Invalid or unsupported Content-Range")
    total = None if complete == "*" else _range_number(complete)
    if interval == "*":
        if total is None:
            raise ProtocolPolicyError("Unsatisfied Content-Range requires a known length")
        return ByteContentRange(None, None, total)
    first, dash, last = interval.partition("-")
    if not dash:
        raise ProtocolPolicyError("Invalid Content-Range interval")
    first, last = _range_number(first), _range_number(last)
    if last < first or total is not None and total <= last:
        raise ProtocolPolicyError("Inconsistent Content-Range endpoints or total")
    return ByteContentRange(first, last, total)


class PartialResponse(NamedTuple):
    size: Optional[int]
    boundary: Optional[bytes]
    requested: Optional[tuple] = None


def partial_response_metadata(fields, status, method=None, content_length=None, request_headers=None):
    content_range = parse_content_range(fields["content-range"][0].strip(" ")) if "content-range" in fields else None
    if status != 206:
        if content_range is not None and (status != 416 or content_range.first is not None):
            raise ProtocolPolicyError("Content-Range is inconsistent with response status")
        return None
    requested = None
    if request_headers is not None:
        range_values = [value for name, value in request_headers.items() if name.lower() == "range"]
        if len(range_values) > 1:
            raise ProtocolPolicyError("Duplicate request Range fields")
        requested = validate_byte_range(range_values[0]) if range_values else ()
    if method is not None and method != "GET" or requested == ():
        raise ProtocolPolicyError("Partial response requires a GET range request")
    kind, parameters = validate_response_media_type(fields["content-type"][0]) if "content-type" in fields else (None, {})
    if kind == "multipart/byteranges":
        boundary = parameters.get("boundary", "")
        if content_range is not None or requested is not None and len(requested) == 1 or not 1 <= len(boundary) <= 70 or boundary.endswith(" ") or not re.fullmatch(r"[0-9A-Za-z'()+_,./:=? -]+", boundary):
            raise ProtocolPolicyError("Invalid multipart range response metadata")
        return PartialResponse(None, boundary.encode("ascii"), requested)
    if content_range is None or content_range.first is None or content_range.size > MAX_RESPONSE_BYTES or content_length is not None and content_range.size != content_length:
        raise ProtocolPolicyError("Partial response Content-Range disagrees with body length")
    validate_returned_byte_range(requested, content_range)
    return PartialResponse(content_range.size, None, requested)


def validate_multipart_ranges(body, boundary, requested=None, representation=None):
    """Check original MIME bytes without header unfolding or transfer decoding."""
    def invalid():
        raise ProtocolPolicyError("Invalid or inconsistent multipart byte ranges")

    if len(body) > MAX_RESPONSE_BYTES:
        invalid()
    marker = b"--" + boundary
    position = 0 if body.startswith(marker) else body.find(b"\r\n" + marker)
    if position < 0:
        invalid()
    if not body.startswith(marker):
        position += 2  # Ignore the MIME preamble.
    parts = header_bytes = header_count = 0
    complete, greatest_last = None, 0
    json_representation = xml_representation = False
    returned = []
    content = memoryview(body)
    while True:
        if not body.startswith(marker, position):
            invalid()
        position += len(marker)
        closing = body.startswith(b"--", position)
        if closing:
            position += 2
        line_end = body.find(b"\r\n", position)
        if line_end < 0:
            if not closing:
                invalid()
            line_end = len(body)
        if line_end - position > MAX_FIELD_BYTES or body[position:line_end].strip(b" \t"):
            invalid()
        if closing:
            if not parts:
                invalid()
            for content_range, _ in returned:
                if complete is not None and content_range.complete is None:
                    content_range = content_range._replace(complete=complete)
                validate_returned_byte_range(requested, content_range)
            if representation or (json_representation or xml_representation) and complete is not None:
                validate_complete_multipart_content(returned, complete, json_representation, xml_representation, representation)
            return  # Optional final CRLF and epilogue are not part content.
        position = line_end + 2
        parts += 1
        if parts > MAX_RANGE_MEMBERS:
            invalid()
        fields = {}
        while True:
            line_end = body.find(b"\r\n", position)
            size = line_end - position + 2
            if line_end < 0 or size > MAX_FIELD_BYTES or header_bytes + size > MAX_HEADER_BYTES:
                invalid()
            line = body[position:line_end]
            position = line_end + 2
            header_bytes += size
            if not line:
                break
            header_count += 1
            if header_count > MAX_HEADERS or line.startswith(marker) or any(byte < 32 or byte > 126 for byte in line):
                invalid()
            name, colon, value = line.decode("ascii").partition(":")
            if not colon or not TOKEN.fullmatch(name):
                invalid()
            name, value = name.lower(), value.strip(" ")
            fields.setdefault(name, []).append(value)
            if name in ("content-length", "transfer-encoding", "trailer", "connection", "upgrade"):
                invalid()
            if name in ("content-encoding", "content-transfer-encoding"):
                expected = "identity" if name == "content-encoding" else "binary"
                if len(fields[name]) != 1 or value.lower() != expected:
                    invalid()
        validate_response_metadata(fields, multipart_part=True)
        if "content-type" in fields:
            kind, _ = validate_response_media_type(fields["content-type"][0])
            json_representation |= kind == "application/json" or kind.endswith("+json")
            xml_representation |= kind in ("application/xml", "text/xml") or kind.endswith("+xml")
        if "content-range" not in fields:
            invalid()
        content_range = parse_content_range(fields["content-range"][0])
        if content_range.first is None or content_range.size > len(body) - position:
            invalid()
        if content_range.complete is not None:
            if complete is not None and complete != content_range.complete:
                invalid()
            complete = content_range.complete
        greatest_last = max(greatest_last, content_range.last)
        if complete is not None and greatest_last >= complete:
            invalid()
        end = position + content_range.size
        if body.startswith(marker, position, end) or body.find(b"\r\n" + marker, position, end) >= 0 or not body.startswith(b"\r\n", end):
            invalid()
        # Views retain only the already bounded response. Resource offsets can
        # be very large, but relative slice offsets and pairwise work are bounded.
        part = content[position:end]
        for previous, previous_data in returned:
            first = max(content_range.first, previous.first)
            last = min(content_range.last, previous.last)
            if first > last:
                continue
            if part[first - content_range.first:last - content_range.first + 1] != previous_data[first - previous.first:last - previous.first + 1]:
                raise ProtocolPolicyError("Conflicting multipart byte ranges")
        returned.append((content_range, part))
        position = end + 2


def validate_complete_multipart_content(parts, complete, json_representation, xml_representation, representation=None):
    """Validate complete JSON/XML from one response; preserve the MIME body."""
    def incomplete():
        if representation:
            _representation_unavailable()
    if complete is None or complete > MAX_RESPONSE_BYTES:
        incomplete()
        return  # A bounded response cannot contain this complete representation.
    parts = sorted(parts, key=lambda part: part[0].first)
    covered = 0
    for interval, _ in parts:
        if interval.first > covered:
            incomplete()
            return
        covered = max(covered, interval.last + 1)
    if covered != complete:
        incomplete()
        return
    # Allocate only after proving full coverage under the response byte budget.
    document = bytearray(complete)
    for interval, data in parts:
        document[interval.first:interval.last + 1] = data
    if representation:
        validate_digest_members(representation, document)
    if json_representation:
        try:
            strict_json_loads(document.decode("utf-8", errors="strict"))
        except (ValueError, UnicodeError) as exc:
            raise ProtocolPolicyError("Response violates the JSON interoperability policy") from exc
    if xml_representation:
        validate_response_xml(document)


def _strict_request_args(args):
    if not isinstance(args, dict) or set(args) - {"url", "method", "headers", "body", "timeout_seconds"}:
        raise ProtocolPolicyError("Unknown or invalid HTTP request arguments")
    method, url = args.get("method", "GET"), args.get("url", "")
    if not isinstance(method, str) or method not in METHODS:
        raise ProtocolPolicyError("Unsupported or noncanonical HTTP method")
    _, origin = strict_http_url(url)
    body, supplied_headers = args.get("body", ""), args.get("headers", {})
    if not isinstance(body, str) or not isinstance(supplied_headers, dict):
        raise ProtocolPolicyError("Body must be UTF-8 text and headers must be an object")
    encoded = body.encode("utf-8", errors="strict")
    if len(encoded) > MAX_BODY_BYTES or method in ("GET", "HEAD") and body:
        raise ProtocolPolicyError("Request body is oversized or unsupported for the method")
    if len(supplied_headers) > MAX_HEADERS:
        raise ProtocolPolicyError("Too many HTTP headers")
    headers = {}
    total = 0
    for name, value in supplied_headers.items():
        if not isinstance(name, str) or not TOKEN.fullmatch(name) or not isinstance(value, str):
            raise ProtocolPolicyError("Invalid HTTP header")
        key = name.lower()
        if key in headers or key in DENIED_HEADERS or key.startswith(("proxy-", "x-forwarded", "sec-")):
            raise ProtocolPolicyError("Duplicate or transport-controlled HTTP header")
        if not value.isascii() or value != value.strip(" ") or any(ord(char) < 32 or ord(char) > 126 for char in value):
            raise ProtocolPolicyError("Unsupported HTTP header value")
        size = len(name) + len(value) + 4
        total += size
        if size > MAX_FIELD_BYTES or total > MAX_HEADER_BYTES:
            raise ProtocolPolicyError("HTTP header exceeds size limits")
        if key in ("content-encoding", "accept-encoding") and value.lower() != "identity":
            raise ProtocolPolicyError("Encoded HTTP bodies are unsupported")
        if key == "range":
            if method != "GET":
                raise ProtocolPolicyError("Range requests require GET")
            validate_byte_range(value)
        if key == "content-range":
            content_range = parse_content_range(value)
            if method != "PUT" or content_range.first is None or content_range.size != len(encoded):
                raise ProtocolPolicyError("Partial uploads require PUT and a Content-Range matching the body length")
        if key == "content-location":
            validate_uri_reference(value)
        validate_conditional_field(key, value)
        headers[key] = value
    if "if-range" in headers and (method != "GET" or "range" not in headers):
        raise ProtocolPolicyError("If-Range requires a GET Range request")
    for field in ("want-content-digest", "want-repr-digest"):
        if field in headers:
            parse_digest_preferences([headers[field]])
    if "content-digest" in headers:
        validate_content_digest({"content-digest": [headers["content-digest"]]}, encoded)
    if "repr-digest" in headers:
        representation = parse_content_digest([headers["repr-digest"]])
        if "content-range" in headers:
            interval = parse_content_range(headers["content-range"])
            if interval.first != 0 or interval.complete is None or interval.size != interval.complete:
                _representation_unavailable()
        validate_digest_members(representation, encoded)
    media = headers.get("content-type")
    if media is None and body:
        media = "application/json" if body.lstrip().startswith(("{", "[")) else "text/plain; charset=utf-8"
        headers["content-type"] = media
    if media is not None:
        parsed_media = REQUEST_MEDIA_TYPE.fullmatch(media)
        if parsed_media is None:
            raise ProtocolPolicyError("Invalid request content type or unsupported charset parameter")
        kind = parsed_media[1].lower()
        charset = parsed_media[2]
        if charset is not None:
            if charset.startswith('"'):
                charset = re.sub(r"\\([ -~])", r"\1", charset[1:-1])
            if charset.lower() != "utf-8":
                raise ProtocolPolicyError("Only UTF-8 request charset is supported")
        subtype = kind[len("application/"):] if kind.startswith("application/") else ""
        is_json = kind == "application/json" or bool(TOKEN.fullmatch(subtype) and subtype.endswith("+json"))
        if kind not in ("text/plain", "application/x-www-form-urlencoded") and not is_json:
            raise ProtocolPolicyError("Unsupported request content type")
        if is_json:
            strict_json_loads(body)
        elif kind == "application/x-www-form-urlencoded":
            _percent_syntax(body)
            try:
                fields = urllib.parse.parse_qsl(body, keep_blank_values=True, encoding="utf-8", errors="strict", max_num_fields=MAX_JSON_TOKENS)
            except (ValueError, UnicodeError) as exc:
                raise ProtocolPolicyError("Invalid UTF-8 form body") from exc
            if any(ord(char) < 32 or ord(char) == 127 or char == "\\" for pair in fields for item in pair for char in item):
                raise ProtocolPolicyError("Form body contains controls or backslash")
    headers["accept-encoding"] = "identity"
    if len(headers) > MAX_HEADERS or sum(len(key) + len(value) + 4 for key, value in headers.items()) > MAX_HEADER_BYTES:
        raise ProtocolPolicyError("Prepared HTTP headers exceed size limits")
    timeout = args.get("timeout_seconds", 30)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 1 <= timeout <= 120 or int(timeout) != timeout:
        raise ProtocolPolicyError("timeout_seconds must be an integer between 1 and 120")
    return method, url, headers, body, int(timeout), origin


def is_public_address(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return not any(address in network for network in IPV4_DENY)
    return address.scope_id is None and address.ipv4_mapped is None and address in IPV6_PUBLIC and not any(address in network for network in IPV6_DENY)


def _resolve_once(host, port, timeout):
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        address = (str(literal), port) if literal.version == 4 else (str(literal), port, 0, 0)
        family = socket.AF_INET if literal.version == 4 else socket.AF_INET6
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", address)]
    # Allocate before reserving capacity. Cancellation during construction then
    # owns no slot and cannot strand one before a worker exists to return it.
    completed = threading.Event()
    result = []
    slots = DNS_SLOTS
    def resolve():
        try:
            result.append(socket.getaddrinfo(host + ".", port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP))
        except OSError:
            result.append(None)
        finally:
            slots.release()
            completed.set()
    try:
        worker = threading.Thread(target=resolve, daemon=True)
    except RuntimeError as exc:
        raise ProtocolPolicyError("DNS resolver worker could not start") from exc
    # The owned deadline must not interrupt semaphore consumption or Thread.start:
    # before startup the caller owns the slot; afterwards only the worker does.
    # A pending expiry is raised on leaving this handoff, before waiting for DNS.
    with _defer_deadline_expiry():
        if not slots.acquire(blocking=False):
            raise ProtocolPolicyError("DNS resolution capacity exceeded")
        try:
            worker.start()
        except RuntimeError as exc:
            slots.release()
            raise ProtocolPolicyError("DNS resolver worker could not start") from exc
    # libc name resolution need not be interruptible. Bound its caller's wait and
    # retain the worker's slot until libc returns; it never opens a connection.
    if not completed.wait(min(timeout, 10)) or not result or result[0] is None:
        raise ProtocolPolicyError("DNS resolution failed or exceeded its deadline")
    return result[0]


def _public_connect(host, port, timeout):
    answers = _resolve_once(host, port, timeout)
    if not answers or len(answers) > MAX_RESOLVED_ADDRESSES:
        raise ProtocolPolicyError("Destination resolver result count is invalid")
    for family, _, _, _, address in answers:
        if family not in (socket.AF_INET, socket.AF_INET6) or not is_public_address(address[0]) or family == socket.AF_INET6 and address[3] != 0:
            raise ProtocolPolicyError("Destination resolves to a nonpublic or special-purpose address")
    for family, socktype, protocol, _, address in answers:
        connected = socket.socket(family, socktype, protocol)
        try:
            connected.settimeout(min(timeout, 10))
            connected.connect(address)
            connected.settimeout(timeout)
            return connected
        except BaseException as exc:
            connected.close()
            if not isinstance(exc, OSError):
                raise
    raise ProtocolPolicyError("Destination connection failed")


class _HeaderReader:
    def __init__(self, reader, method=None):
        self.reader = reader
        self.method = method
        self.total = self.fields = 0
        self.status_expected = True
        self.interim = False

    def readline(self, limit=-1):
        maximum = min(MAX_FIELD_BYTES + 1, MAX_HEADER_BYTES - self.total + 1)
        if limit >= 0:
            maximum = min(maximum, limit)
        line = self.reader.readline(maximum)
        self.total += len(line)
        if self.total > MAX_HEADER_BYTES or len(line) > MAX_FIELD_BYTES or not line.endswith(b"\r\n"):
            raise ProtocolPolicyError("Response headers are malformed or oversized")
        if self.status_expected:
            if not re.fullmatch(rb"HTTP/1\.1 [0-9]{3} [\x20-\x7e]*\r\n", line):
                raise ProtocolPolicyError("Only canonical HTTP/1.1 responses are supported")
            self.status_code = int(line[9:12])
            self.block_fields = set()
            self.block_metadata = {}
            self.interim = self.status_code in (100, 102, 103)
            self.status_expected = False
        elif line == b"\r\n":
            validate_response_metadata(self.block_metadata)
            validate_response_representation_metadata(self.block_metadata, self.status_code, self.method)
            if self.status_code < 200 or self.method == "HEAD" or self.status_code in (204, 205, 304):
                validate_content_digest(self.block_metadata, b"")
            partial_response_metadata(self.block_metadata, self.status_code, self.method)
            self.status_expected = self.interim
        else:
            self.fields += 1
            name, colon, value = line[:-2].partition(b":")
            if (self.interim or self.status_code == 204) and name.lower() in (b"content-length", b"transfer-encoding"):
                raise ProtocolPolicyError("Bodyless HTTP responses cannot declare body framing")
            if self.fields > MAX_HEADERS or not colon or not TOKEN.fullmatch(name.decode("ascii", "strict")) or value.startswith(b"\t") or any(byte < 32 or byte > 126 for byte in value):
                raise ProtocolPolicyError("Response header is malformed or unsupported")
            key, field_value = name.lower(), value.strip(b" ").lower()
            self.block_metadata.setdefault(key.decode("ascii"), []).append(value.strip(b" ").decode("ascii"))
            if key in (b"content-length", b"transfer-encoding", b"content-encoding") and key in self.block_fields:
                raise ProtocolPolicyError("Duplicate response framing or encoding header")
            self.block_fields.add(key)
            if key in (b"upgrade", b"trailer", b"http2-settings", b"content-transfer-encoding"):
                raise ProtocolPolicyError("Upgraded, trailer-bearing or encoded responses are unsupported")
            if key == b"content-encoding" and field_value != b"identity":
                raise ProtocolPolicyError("Encoded HTTP responses are unsupported")
            if key == b"connection" and b"upgrade" in (part.strip(b" ") for part in field_value.split(b",")):
                raise ProtocolPolicyError("HTTP response upgrades are unsupported")
        return line


def parse_chunk_line(line):
    """Parse RFC 9112 chunk-size/chunk-ext without evaluating extensions."""
    if len(line) > MAX_CHUNK_LINE_BYTES or not line.endswith(b"\r\n"):
        raise ProtocolPolicyError("Malformed or oversized chunk-size line")
    source = line[:-2]
    cursor = 0
    while cursor < len(source) and source[cursor] in b"0123456789abcdefABCDEF":
        cursor += 1
    if cursor == 0:
        raise ProtocolPolicyError("Missing hexadecimal chunk size")
    size = int(source[:cursor], 16)
    if size > MAX_RESPONSE_BYTES:
        raise ProtocolPolicyError("Declared response chunk exceeds the body limit")
    extension_bytes = len(source) - cursor
    token_bytes = b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    def bws(position):
        while position < len(source) and source[position] in (9, 32):
            position += 1
        return position

    def token(position):
        first = position
        while position < len(source) and source[position] in token_bytes:
            position += 1
        if first == position:
            raise ProtocolPolicyError("Missing chunk extension token")
        return position

    while cursor < len(source):
        cursor = bws(cursor)
        if cursor >= len(source) or source[cursor] != 59:
            raise ProtocolPolicyError("Invalid chunk extension separator")
        cursor = token(bws(cursor + 1))
        after_name = bws(cursor)
        if after_name < len(source) and source[after_name] == 61:
            cursor = bws(after_name + 1)
            if cursor < len(source) and source[cursor] == 34:
                cursor += 1
                while True:
                    if cursor >= len(source):
                        raise ProtocolPolicyError("Unterminated quoted chunk extension")
                    byte = source[cursor]
                    cursor += 1
                    if byte == 34:
                        break
                    if byte == 92:
                        if cursor >= len(source) or not (source[cursor] == 9 or 32 <= source[cursor] <= 126 or source[cursor] >= 128):
                            raise ProtocolPolicyError("Invalid chunk extension quoted pair")
                        cursor += 1
                    elif not (byte in (9, 32, 33) or 35 <= byte <= 91 or 93 <= byte <= 126 or byte >= 128):
                        raise ProtocolPolicyError("Invalid quoted chunk extension byte")
            else:
                cursor = token(cursor)
    return size, extension_bytes


class _BodyReader:
    """Account consumed body/framing bytes even if a later parser step rejects."""
    def __init__(self, reader, response):
        self.reader = reader
        self.response = response
        self.pending = bytearray()

    def _record(self, value):
        count = len(value)
        self.response.consumed_body_bytes += count
        if self.response.account_body_bytes is not None:
            self.response.account_body_bytes(count)
        return value

    def read(self, size=-1):
        chunks = []
        remaining = size
        if self.pending:
            count = len(self.pending) if remaining < 0 else min(remaining, len(self.pending))
            chunks.append(bytes(self.pending[:count]))
            del self.pending[:count]
            if remaining >= 0:
                remaining -= count
        while remaining:
            # BufferedReader.read(size) can consume data and then raise while
            # waiting for the rest, losing those bytes to the accounting hook.
            # read1 performs at most one raw read; charge each result promptly.
            chunk = self._record(self.reader.read1(65536 if remaining < 0 else min(65536, remaining)))
            if not chunk:
                break
            chunks.append(chunk)
            if remaining >= 0:
                remaining -= len(chunk)
        return b"".join(chunks)

    def readline(self, size=-1):
        while True:
            available = len(self.pending) if size < 0 else min(size, len(self.pending))
            newline = self.pending.find(b"\n", 0, available)
            if newline >= 0:
                available = newline + 1
            if newline >= 0 or size >= 0 and available == size:
                result = bytes(self.pending[:available])
                del self.pending[:available]
                return result
            chunk = self._record(self.reader.read1(4096 if size < 0 else min(4096, size - available)))
            if not chunk:
                result = bytes(self.pending)
                self.pending.clear()
                return result
            self.pending.extend(chunk)

    def __getattr__(self, name):
        return getattr(self.reader, name)


class StrictHTTPResponse(http.client.HTTPResponse):
    def _read_status(self):
        version, status, reason = super()._read_status()
        if 100 <= status < 200:
            self.interim_count += 1
            if status not in (100, 102, 103) or self.interim_count > 4:
                raise ProtocolPolicyError("Unsupported or excessive informational HTTP responses")
            return version, 100, reason
        return version, status, reason

    def begin(self):
        if self.headers is not None:
            return
        self.interim_count = 0
        original = self.fp
        self.fp = _HeaderReader(original, self._method)
        try:
            super().begin()
        finally:
            self.fp = original
        self.consumed_body_bytes = 0
        self.account_body_bytes = None
        self.data_chunks = self.chunk_extension_bytes = self.declared_body_bytes = self.chunk_framing_bytes = 0
        # CPython otherwise prioritizes chunked parsing over status 304's zero
        # content length. HEAD/204/304 metadata must never cause a body read.
        if self._method == "HEAD" or self.status in (204, 304):
            self.chunked = False
            self.length = 0
        self.fp = _BodyReader(original, self)

    def _account_chunk_framing(self, count):
        self.chunk_framing_bytes += count
        if self.chunk_framing_bytes > MAX_CHUNK_FRAMING_BYTES:
            raise ProtocolPolicyError("Response chunk framing budget exceeded")

    def _read_next_chunk_size(self):
        line = self.fp.readline(MAX_CHUNK_LINE_BYTES + 1)
        self._account_chunk_framing(len(line))
        size, extension_bytes = parse_chunk_line(line)
        self.chunk_extension_bytes += extension_bytes
        if size:
            self.data_chunks += 1
            self.declared_body_bytes += size
        if self.chunk_extension_bytes > MAX_CHUNK_EXTENSION_BYTES or self.data_chunks > MAX_DATA_CHUNKS or self.declared_body_bytes > MAX_RESPONSE_BYTES:
            raise ProtocolPolicyError("Response chunk resource budget exceeded")
        if self.status == 205 and size:
            raise ProtocolPolicyError("HTTP 205 responses cannot contain content")
        return size

    def _get_chunk_left(self):
        remaining = self.chunk_left
        if not remaining:
            if remaining is not None:
                try:
                    delimiter = self._safe_read(2)
                except http.client.IncompleteRead as exc:
                    self._account_chunk_framing(len(exc.partial))
                    raise
                self._account_chunk_framing(len(delimiter))
                if delimiter != b"\r\n":
                    raise ProtocolPolicyError("Invalid response chunk delimiter")
            remaining = self._read_next_chunk_size()
            if remaining == 0:
                self._read_and_discard_trailer()
                self._close_conn()
                remaining = None
            self.chunk_left = remaining
        return remaining

    def _read_and_discard_trailer(self):
        line = self.fp.readline(MAX_FIELD_BYTES + 1)
        self._account_chunk_framing(len(line))
        if line != b"\r\n":
            raise ProtocolPolicyError("HTTP response trailers are unsupported")


class PinnedHTTPConnection(http.client.HTTPConnection):
    response_class = StrictHTTPResponse
    def connect(self):
        if self._tunnel_host:
            raise ProtocolPolicyError("HTTP tunneling is unsupported")
        self.sock = _public_connect(self.host, self.port, self.timeout)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    response_class = StrictHTTPResponse
    def connect(self):
        if self._tunnel_host:
            raise ProtocolPolicyError("HTTP tunneling is unsupported")
        raw = _public_connect(self.host, self.port, self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class PinnedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, request):
        return self.do_open(PinnedHTTPConnection, request)


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, request):
        return self.do_open(PinnedHTTPSConnection, request, context=self._context)


@contextmanager
def transport_budget(seconds):
    if threading.current_thread() is not threading.main_thread() or not hasattr(signal, "setitimer"):
        raise ProtocolPolicyError("Secure transport requires POSIX main-thread deadlines")
    if any(signal.getitimer(signal.ITIMER_REAL)):
        raise ProtocolPolicyError("Secure transport cannot replace a caller timer")
    with _deadline_timer(seconds, ProtocolPolicyError,
                         "HTTP request exceeded its total deadline"):
        yield


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Return the redirect to the caller. A follow-up is a new inspected call.
        return None


class MCPServer:
    def __init__(self, engine: SnortEngine, allowed_origins=None, opener=None):
        self.engine = engine
        self.stats = {"total_inspected": 0, "total_passed": 0, "total_blocked": 0}
        self.inspected_bytes = 0
        self.response_bytes = 0
        self.rpc_messages = 0
        self.rpc_bytes = 0
        self.allowed_origins = set()
        for configured in allowed_origins or []:
            origin = strict_http_url(configured, origin_only=True)[1]
            self._validate_public_origin(origin)
            self.allowed_origins.add(origin)
        # An explicit embedding opener is trusted; patching the default opener
        # does not disable origin policy. CLI always uses the protected transport.
        self.enforce_origins = opener is None or allowed_origins is not None
        if opener is None:
            # RFC 9525 requires SAN identities. Older OpenSSL releases could
            # ignore the Common Name exclusion flag; require native support.
            if (not getattr(ssl, "HAS_NEVER_CHECK_COMMON_NAME", False)
                    or ssl.OPENSSL_VERSION_INFO < (1, 1, 1, 12)):
                raise ProtocolPolicyError("Secure transport requires SAN-only TLS certificate identity support (OpenSSL 1.1.1l or newer)")
            context = ssl.create_default_context()
            context.hostname_checks_common_name = False
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_alpn_protocols(["http/1.1"])
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirectHandler(),
                                                 PinnedHTTPHandler(), PinnedHTTPSHandler(context=context))
        self.opener = opener

    def run(self):
        logging.info("Starting ax-mcp-proxy on stdio (rules: %d)", len(self.engine.rules))
        while True:
            line = sys.stdin.readline(MAX_MESSAGE_BYTES + 1)
            if not line:
                break
            self.rpc_messages += 1
            try:
                line_bytes = len(line.encode("utf-8", errors="strict"))
            except UnicodeError:
                self._send_error(None, -32700, "Invalid UTF-8 MCP message")
                return
            self.rpc_bytes += line_bytes
            if self.rpc_messages > MAX_RPC_MESSAGES or self.rpc_bytes > MAX_RPC_BYTES:
                self._send_error(None, -32600, "MCP session message budget exhausted")
                return
            if line_bytes > MAX_MESSAGE_BYTES:
                # Do not drain an unbounded malicious line; end this session.
                self._send_error(None, -32600, "MCP message exceeds size limit")
                return
            if not line.strip():
                continue
            try:
                req = strict_json_loads(line)
            except (ValueError, RecursionError):
                self._send_error(None, -32700, "Parse error")
                continue
            if not isinstance(req, dict):
                self._send_error(None, -32600, "Request must be an object")
                continue
            self._handle_message(req)

    def _send_response(self, req_id: Any, result: Any):
        resp = {"jsonrpc": "2.0", "id": req_id, "result": result}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()

    def _send_error(self, req_id: Any, code: int, message: str, data: Any = None):
        err = {"code": code, "message": message}
        if data:
            err["data"] = data
        resp = {"jsonrpc": "2.0", "id": req_id, "error": err}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()

    def _handle_message(self, req: Dict[str, Any]):
        method = req.get("method")
        req_id = req.get("id")
        valid_id = isinstance(req_id, str) or isinstance(req_id, int) and not isinstance(req_id, bool) and abs(req_id) <= SAFE_INTEGER
        if req.get("jsonrpc") != "2.0" or not isinstance(method, str) or not method or not isinstance(req.get("params", {}), dict) or set(req) - {"jsonrpc", "id", "method", "params"}:
            self._send_error(None, -32600, "Invalid JSON-RPC request")
            return
        if "id" not in req:
            if method != "notifications/initialized":
                self._send_error(None, -32600, "Only initialized notifications are supported; tool calls require an ID")
            return
        if not valid_id or method == "notifications/initialized":
            self._send_error(None, -32600, "Invalid JSON-RPC request ID")
            return

        if method == "initialize":
            self._send_response(req_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            })
        elif method == "notifications/initialized":
            pass
        elif method == "ping":
            self._send_response(req_id, {})
        elif method == "tools/list":
            self._send_response(req_id, {"tools": self._tool_definitions()})
        elif method == "tools/call":
            params = req.get("params", {})
            if set(params) - {"name", "arguments", "_meta"} or not isinstance(params.get("name"), str) or not isinstance(params.get("_meta", {}), dict) or not isinstance(params.get("arguments", {}), dict):
                self._send_error(req_id, -32602, "Tool parameters and arguments must be objects")
                return
            self._handle_tool_call(req_id, params.get("name"), params.get("arguments", {}))
        else:
            if req_id is not None:
                self._send_error(req_id, -32601, f"Method {method} not found")

    def _handle_tool_call(self, req_id: Any, name: str, args: Dict[str, Any]):
        if name == "http_request":
            self._execute_http_request(req_id, args)
        elif name == "check_security_payload":
            self._execute_check_payload(req_id, args)
        elif name == "get_security_stats":
            if args:
                self._send_error(req_id, -32602, "Statistics tool accepts no arguments")
            else:
                self._execute_get_stats(req_id)
        else:
            self._send_error(req_id, -32601, f"Unknown tool {name}")

    def _request_args(self, args):
        self.stats["total_inspected"] += 1
        if self.stats["total_inspected"] > MAX_INSPECTION_ATTEMPTS:
            raise ProtocolPolicyError("Session inspection attempt budget exhausted")
        if self.response_bytes >= MAX_SESSION_RESPONSE_BYTES:
            raise ProtocolPolicyError("Session response byte budget exhausted")
        prepared = _strict_request_args(args)
        method, url, headers, body, _, _ = prepared
        size = len(url.encode("utf-8")) + len(body.encode("utf-8")) + sum(len(key) + len(value) + 4 for key, value in headers.items())
        if self.inspected_bytes + size > MAX_SESSION_INSPECTION_BYTES:
            raise ProtocolPolicyError("Session inspection byte budget exhausted")
        self.inspected_bytes += size
        return prepared

    @staticmethod
    def _validate_public_origin(origin):
        host = origin[1]
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if "." not in host or any(host == suffix or host.endswith("." + suffix) for suffix in ("localhost", "local", "internal", "home.arpa", "onion")):
                raise ProtocolPolicyError("Destination must be a public fully qualified DNS name")
            return
        if not is_public_address(str(address)):
            raise ProtocolPolicyError("Destination is a nonpublic or special-purpose address")

    def _check_origin(self, origin):
        if not self.enforce_origins:
            return
        self._validate_public_origin(origin)
        if origin not in self.allowed_origins:
            raise ProtocolPolicyError("Destination origin is not explicitly allowed")

    def _count_response_bytes(self, count):
        self.response_bytes += count
        if self.response_bytes > MAX_SESSION_RESPONSE_BYTES:
            raise ProtocolPolicyError("Session response byte budget exhausted")

    def _response_data(self, response, method=None, request_headers=None):
        code = response.code
        if code < 200 or code > 599 or getattr(response, "version", 11) != 11:
            raise ProtocolPolicyError("Unsupported HTTP response status or version")
        items = list(response.headers.items())
        if len(items) > MAX_HEADERS:
            raise ProtocolPolicyError("Too many response headers")
        fields = {}
        total = 0
        for name, value in items:
            if not TOKEN.fullmatch(name) or not value.isascii() or any(ord(char) < 32 or ord(char) > 126 for char in value):
                raise ProtocolPolicyError("Invalid response header")
            size = len(name) + len(value) + 4
            total += size
            if size > MAX_FIELD_BYTES or total > MAX_HEADER_BYTES:
                raise ProtocolPolicyError("Response headers exceed size limits")
            fields.setdefault(name.lower(), []).append(value)
        validate_response_metadata(fields)
        if code == 204 and ("content-length" in fields or "transfer-encoding" in fields):
            raise ProtocolPolicyError("HTTP 204 responses cannot declare body framing")
        if "upgrade" in fields or "trailer" in fields or "http2-settings" in fields or "content-transfer-encoding" in fields or any(token.strip().lower() == "upgrade" for value in fields.get("connection", []) for token in value.split(",")):
            raise ProtocolPolicyError("Upgraded, trailer-bearing or encoded responses are unsupported")
        if [value.lower() for value in fields.get("content-encoding", ["identity"])] != ["identity"]:
            raise ProtocolPolicyError("Encoded HTTP responses are unsupported")
        if len(fields.get("content-length", [])) > 1 or len(fields.get("transfer-encoding", [])) > 1 or "content-length" in fields and "transfer-encoding" in fields:
            raise ProtocolPolicyError("Ambiguous response framing")
        if "transfer-encoding" in fields and fields["transfer-encoding"][0].lower() != "chunked":
            raise ProtocolPolicyError("Unsupported response transfer encoding")
        bodyless = method == "HEAD" or getattr(response, "_method", None) == "HEAD" or code in (204, 304)
        if bodyless or code == 205:
            validate_content_digest(fields, b"")
        content_length = None
        if "content-length" in fields:
            value = fields["content-length"][0]
            digits = value
            if not re.fullmatch(r"0|[1-9][0-9]*", value) or len(digits) > 19 or int(digits) > (1 << 63) - 1:
                raise ProtocolPolicyError("Invalid response Content-Length")
            content_length = int(digits)
            if not bodyless and content_length > MAX_RESPONSE_BYTES:
                raise ProtocolPolicyError("Response content length exceeds the body limit")
            if code == 205 and content_length:
                raise ProtocolPolicyError("HTTP 205 responses cannot contain content")
        response_method = method or getattr(response, "_method", None)
        representation = validate_response_representation_metadata(fields, code, response_method)
        validate_response_conditions(fields, code, response_method, request_headers)
        partial = partial_response_metadata(fields, code, response_method, content_length, request_headers)
        available = min(0 if code == 205 else MAX_RESPONSE_BYTES, MAX_SESSION_RESPONSE_BYTES - self.response_bytes)
        if available < 0:
            raise ProtocolPolicyError("Session response byte budget exhausted")
        counted_response = response if isinstance(response, StrictHTTPResponse) else getattr(response, "fp", None)
        counts_wire = isinstance(counted_response, StrictHTTPResponse)
        if counts_wire:
            counted_response.account_body_bytes = self._count_response_bytes
        try:
            body = b"" if bodyless else response.read(available + 1)
        except http.client.IncompleteRead as exc:
            if not counts_wire:
                self._count_response_bytes(len(exc.partial))
            raise ProtocolPolicyError("Incomplete HTTP response body") from exc
        if not counts_wire:
            self._count_response_bytes(len(body))
        if content_length is not None and not bodyless and len(body) != content_length:
            raise ProtocolPolicyError("Incomplete HTTP response content length")
        if len(body) > available:
            raise ProtocolPolicyError("Response exceeds size limits")
        validate_content_digest(fields, body)
        if partial is not None:
            if partial.boundary is not None:
                validate_multipart_ranges(body, partial.boundary, partial.requested, representation)
            elif len(body) != partial.size:
                raise ProtocolPolicyError("Partial response body length differs from Content-Range")
        if partial is None or partial.boundary is None:
            validate_digest_members(representation, body)
        flattened = dict(items)
        for name in list(flattened):
            if name.lower() == "set-cookie":
                flattened[name] = fields["set-cookie"]
        for field in ("content-digest", "repr-digest", "want-content-digest", "want-repr-digest"):
            digest_names = [name for name in flattened if name.lower() == field]
            if digest_names:
                flattened[digest_names[0]] = ", ".join(fields[field])
                for name in digest_names[1:]:
                    del flattened[name]
        try:
            text = body.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ProtocolPolicyError("Response body is not valid UTF-8") from exc
        # Validate declared JSON/XML, including a 206 carrying a complete
        # representation. Multipart content was checked above; incomplete
        # ranges remain fragments.
        # No content sniffing or application-specific schema interpretation occurs.
        if not bodyless and code != 205 and "content-type" in fields:
            kind, _ = validate_response_media_type(fields["content-type"][0])
            is_xml = kind in ("application/xml", "text/xml") or kind.endswith("+xml")
            if kind == "application/json" or kind.endswith("+json") or is_xml:
                complete = True
                if code == 206:
                    interval = parse_content_range(fields["content-range"][0].strip(" "))
                    complete = interval.first == 0 and interval.complete == len(body)
                if complete:
                    if is_xml:
                        validate_response_xml(body)
                    else:
                        try:
                            strict_json_loads(text)
                        except (ValueError, UnicodeError) as exc:
                            raise ProtocolPolicyError("Response violates the JSON interoperability policy") from exc
        return {"status_code": code, "headers": flattened, "header_values": fields, "body": text}

    @staticmethod
    def _safe_error(exc):
        if isinstance(exc, (InspectionBudgetError, ProtocolPolicyError)):
            return str(exc)
        return "Request rejected by input validation or inspection limits"

    def _execute_http_request(self, req_id: Any, args: Dict[str, Any]):
        try:
            method, url, headers, body, timeout, origin = self._request_args(args)
            blocked, rule, reason = self.engine.inspect(method, url, headers, body)
            if not blocked:
                self._check_origin(origin)
        except (ValueError, TypeError, OverflowError) as exc:
            self.stats["total_blocked"] += 1
            self._send_tool_result(req_id, "SECURITY VIOLATION: " + self._safe_error(exc), is_error=True)
            return
        if blocked:
            self.stats["total_blocked"] += 1
            logging.warning("Blocked outbound request: SID %d (%s)", rule.sid, rule.classtype)
            self._send_tool_result(req_id, f"SECURITY VIOLATION: Outbound request blocked. Reason: {reason} (Action: {rule.action})", is_error=True)
            return
        if rule is not None:
            logging.info("Outbound request advisory: SID %d action %s", rule.sid, rule.action)
        self.stats["total_passed"] += 1
        try:
            with transport_budget(timeout):
                req = urllib.request.Request(url, data=body.encode("utf-8") if body else None, headers=headers, method=method)
                try:
                    response = self.opener.open(req, timeout=timeout)
                except urllib.error.HTTPError as error_response:
                    response = error_response
                with response:
                    out = self._response_data(response, method, headers)
            self._send_tool_result(req_id, json.dumps(out, indent=2), is_error=out["status_code"] >= 400)
        except Exception as exc:
            # Never expose urllib exception text, which can contain secrets.
            message = str(exc) if isinstance(exc, ProtocolPolicyError) else "Request failed or response exceeded size limits"
            self._send_tool_result(req_id, message, is_error=True)

    def _execute_check_payload(self, req_id: Any, args: Dict[str, Any]):
        try:
            method, url, headers, body, _, origin = self._request_args(args)
            blocked, rule, _ = self.engine.inspect(method, url, headers, body)
            if not blocked:
                self._check_origin(origin)
        except (ValueError, TypeError, OverflowError) as exc:
            self.stats["total_blocked"] += 1
            self._send_tool_result(req_id, json.dumps({"blocked": True, "matched": False, "rule_sid": None,
                                                     "error": self._safe_error(exc), "dns_checked": False}), is_error=True)
            return
        self.stats["total_blocked" if blocked else "total_passed"] += 1
        self._send_tool_result(req_id, json.dumps({
            "blocked": blocked, "matched": rule is not None, "rule_sid": rule.sid if rule else None,
            "rule_msg": rule.msg if rule else None, "classtype": rule.classtype if rule else None,
            "action": rule.action if rule else None, "dns_checked": False,
        }, indent=2))

    def _execute_get_stats(self, req_id: Any):
        res = {
            **self.stats,
            "rules_loaded": len(self.engine.rules),
            "inspected_bytes": self.inspected_bytes,
            "response_bytes": self.response_bytes,
            "rpc_messages": self.rpc_messages,
            "rpc_bytes": self.rpc_bytes,
        }
        self._send_tool_result(req_id, json.dumps(res, indent=2))

    def _send_tool_result(self, req_id: Any, text: str, is_error: bool = False):
        result = {
            "content": [{"type": "text", "text": text}],
            "isError": is_error,
        }
        self._send_response(req_id, result)

    def _tool_definitions(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "http_request",
                "description": "Sends inspected HTTP requests only to operator-allowed public origins. Strict HTTP/1.1 and UTF-8 text/JSON/form policy applies; bodies are limited to 1 MiB. Redirects require a separate inspected request.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Destination URL to request (e.g. https://api.github.com/repos)"},
                        "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"], "default": "GET"},
                        "headers": {"type": "object", "description": "HTTP headers", "additionalProperties": {"type": "string"}},
                        "body": {"type": "string", "description": "Request body payload"},
                        "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 120, "default": 30},
                    },
                    "required": ["url"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "check_security_payload",
                "description": "Checks request syntax, signatures and allowed-origin policy without network traffic. DNS and final destination-address checks occur only during dispatch.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "method": {"type": "string", "enum": sorted(METHODS), "default": "GET"},
                        "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                        "body": {"type": "string"},
                        "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 120, "default": 30},
                    },
                    "required": ["url"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "get_security_stats",
                "description": "Returns operational statistics on requests inspected, passed, and blocked by Snort rules.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
        ]


def main():
    parser = argparse.ArgumentParser(description="AX MCP Security Proxy Server")
    parser.add_argument("--rules", help="Path to custom Snort-style rules file")
    parser.add_argument("--allow-origin", action="append", default=[], help="Allow an exact HTTP(S) origin (repeatable; outbound denied by default)")
    parser.add_argument("--profile", choices=("default", "strict"), default="default", help="Bundled rule profile (strict adds sensitive policy signatures)")
    parser.add_argument("--only-custom-rules", action="store_true", help="Load only custom rules without default rules")
    args = parser.parse_args()

    if args.only_custom_rules and not args.rules:
        parser.error("--only-custom-rules requires --rules")
    engine = SnortEngine()
    try:
        if not args.only_custom_rules:
            load_profile(engine, args.profile)
        if args.rules:
            engine.load_rules(Path(args.rules).read_text(encoding="utf-8"))
        if not engine.rules:
            raise ValueError("at least one rule must be loaded")
    except (OSError, ValueError) as exc:
        parser.error(f"cannot load security rules: {exc}")
    try:
        server = MCPServer(engine, allowed_origins=args.allow_origin)
    except (ValueError, TypeError) as exc:
        parser.error(f"invalid egress configuration: {exc}")
    server.run()


if __name__ == "__main__":
    main()
