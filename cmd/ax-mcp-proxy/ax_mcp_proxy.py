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
from contextlib import contextmanager
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
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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


@contextmanager
def inspection_budget():
    # Python's re is backtracking. Bound the entire normalization/matching pass,
    # including trusted custom expressions; unsupported runtimes fail closed.
    if not all(hasattr(signal, name) for name in ("setitimer", "getitimer", "ITIMER_REAL", "SIGALRM")) or threading.current_thread() is not threading.main_thread():
        raise InspectionBudgetError("Python inspection requires a POSIX main thread with interval timers; use the Go proxy")
    remaining, interval = signal.getitimer(signal.ITIMER_REAL)
    if remaining > 0 or interval > 0:
        raise InspectionBudgetError("Python inspection cannot replace an active caller timer; use the Go proxy")
    previous_handler = signal.getsignal(signal.SIGALRM)

    def expired(_signum, _frame):
        raise InspectionBudgetError("Request exceeded the two-second inspection time limit")

    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, MAX_INSPECTION_SECONDS)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


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
    "content-length", "transfer-encoding", "content-encoding", "content-type",
    "content-location", "content-range", "date", "etag", "last-modified", "location",
    "retry-after", "server",
}
RESPONSE_CONNECTION_PROTECTED = (DENIED_HEADERS - {"keep-alive"}) | {
    "connection", "content-type", "content-encoding", "content-language", "content-location",
    "content-range", "content-disposition", "authorization", "proxy-authorization",
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

    _, position = token(0)
    if position >= len(value) or value[position] != "/":
        raise ProtocolPolicyError("Invalid response media type")
    _, position = token(position + 1)
    names = set()
    slots = 0
    while True:
        position = spaces(position)
        if position == len(value):
            return
        if value[position] != ";":
            raise ProtocolPolicyError("Ambiguous response Content-Type")
        slots += 1
        if slots > MAX_RESPONSE_METADATA_PARTS:
            raise ProtocolPolicyError("Response media parameter limit exceeded")
        position = spaces(position + 1)
        if position == len(value):
            return
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


def validate_response_metadata(fields):
    """Check explicit metadata fields; unknown header semantics stay untrusted."""
    connection_parts = 0
    for name, values in fields.items():
        if name in RESPONSE_SINGLETON_HEADERS and len(values) != 1:
            raise ProtocolPolicyError("Duplicate singleton response header")
        if name == "content-type":
            validate_response_media_type(values[0])
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
        headers[key] = value
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
    return address.ipv4_mapped is None and address in IPV6_PUBLIC and not any(address in network for network in IPV6_DENY)


def _resolve_once(host, port, timeout):
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        address = (str(literal), port) if literal.version == 4 else (str(literal), port, 0, 0)
        family = socket.AF_INET if literal.version == 4 else socket.AF_INET6
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", address)]
    # libc name resolution need not be interruptible. Bound its caller's wait and
    # cap abandoned resolver threads; workers never open destination connections.
    if not DNS_SLOTS.acquire(blocking=False):
        raise ProtocolPolicyError("DNS resolution capacity exceeded")
    completed = threading.Event()
    result = []
    def resolve():
        try:
            result.append(socket.getaddrinfo(host + ".", port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP))
        except OSError:
            result.append(None)
        finally:
            DNS_SLOTS.release()
            completed.set()
    try:
        threading.Thread(target=resolve, daemon=True).start()
    except RuntimeError as exc:
        DNS_SLOTS.release()
        raise ProtocolPolicyError("DNS resolver worker could not start") from exc
    if not completed.wait(min(timeout, 10)) or not result or result[0] is None:
        raise ProtocolPolicyError("DNS resolution failed or exceeded its deadline")
    return result[0]


def _public_connect(host, port, timeout):
    answers = _resolve_once(host, port, timeout)
    if not answers:
        raise ProtocolPolicyError("Destination has no usable addresses")
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
    def __init__(self, reader):
        self.reader = reader
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
        self.fp = _HeaderReader(original)
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
    previous = signal.getsignal(signal.SIGALRM)
    def expired(_signum, _frame):
        raise ProtocolPolicyError("HTTP request exceeded its total deadline")
    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


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
            context = ssl.create_default_context()
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

    def _response_data(self, response, method=None):
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
        flattened = dict(items)
        for name in list(flattened):
            if name.lower() == "set-cookie":
                flattened[name] = fields["set-cookie"]
        try:
            text = body.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ProtocolPolicyError("Response body is not valid UTF-8") from exc
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
                    out = self._response_data(response, method)
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
