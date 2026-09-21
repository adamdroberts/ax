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

"""AX Model Context Protocol (MCP) Security Proxy Server.

Intercepts and proxies all outbound HTTP/API requests from autonomous agents,
inspecting URLs, headers, and request bodies against Snort intrusion prevention
rules to prevent zero-day exploitation, unauthorized code execution, SSRF,
SQLi, path traversal, and illegal hacking activities.
"""

import argparse
import json
import logging
import re
import sys
import urllib.parse
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", stream=sys.stderr)

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "ax-mcp-proxy"
SERVER_VERSION = "1.0.0"

DEFAULT_RULES_SNORT = """
# Remote Code Execution (RCE) & Command Injection
drop tcp any any -> any any (msg:"EXPLOIT Log4Shell JNDI injection attempt"; content:"${jndi:"; nocase; classtype:"attempted-admin"; sid:1000001; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT Log4Shell obfuscated JNDI pattern"; pcre:"/\\$\\{[^}]*jndi[^}]*:/i"; classtype:"attempted-admin"; sid:1000002; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT Reverse Shell /dev/tcp payload"; content:"/dev/tcp/"; nocase; classtype:"attempted-admin"; sid:1000003; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT Netcat reverse shell execution"; pcre:"/nc(\\.traditional)?\\s+.*-e\\s+(\\/bin\\/(ba)?sh)/i"; classtype:"attempted-admin"; sid:1000004; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT Remote pipe to shell execution"; pcre:"/(curl|wget)\\s+.*\\|\\s*(ba)?sh/i"; classtype:"attempted-admin"; sid:1000005; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT Shell command injection attempt"; pcre:"/(;|\\||`|\\$\\().*\\b(cat\\s+\\/etc\\/passwd|whoami|id|uname\\s+-a|rm\\s+-rf)/i"; classtype:"attempted-admin"; sid:1000006; rev:1;)

# Zero-Day & Framework Exploits
drop tcp any any -> any any (msg:"EXPLOIT Spring4Shell classLoader manipulation"; content:"class.module.classLoader"; nocase; classtype:"attempted-admin"; sid:1000010; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT Apache Struts OGNL injection"; content:"#_memberAccess"; nocase; classtype:"attempted-admin"; sid:1000011; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT PHP CGI argument injection"; pcre:"/\\?-d\\+allow_url_include/i"; classtype:"attempted-admin"; sid:1000012; rev:1;)

# Path Traversal & Sensitive File Access
drop tcp any any -> any any (msg:"EXPLOIT Path Traversal directory climbing"; content:"../../"; http_uri; classtype:"web-application-attack"; sid:1000020; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT URL-encoded path traversal"; pcre:"/(\\.\\.%2f|\\.\\.%5c|%2e%2e%2f)/i"; http_uri; classtype:"web-application-attack"; sid:1000021; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT Sensitive system file access /etc/passwd"; content:"/etc/passwd"; nocase; classtype:"attempted-recon"; sid:1000022; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT Windows system file access"; pcre:"/(win\\.ini|boot\\.ini|system32\\/config\\/sam)/i"; nocase; classtype:"attempted-recon"; sid:1000023; rev:1;)

# Server-Side Request Forgery (SSRF) & Metadata Theft
drop tcp any any -> any any (msg:"ATTACK SSRF Cloud instance metadata probe"; content:"169.254.169.254"; http_uri; classtype:"bad-unknown"; sid:1000030; rev:1;)
drop tcp any any -> any any (msg:"ATTACK SSRF GCP metadata header probe"; content:"metadata.google.internal"; nocase; http_uri; classtype:"bad-unknown"; sid:1000031; rev:1;)
drop tcp any any -> any any (msg:"ATTACK SSRF Loopback service probe"; pcre:"/https?:\\/\\/(127\\.0\\.0\\.1|localhost|0\\.0\\.0\\.0|\\[::1\\])(:\\d+)?(\\/|$)/i"; http_uri; classtype:"bad-unknown"; sid:1000032; rev:1;)

# SQL Injection (SQLi)
drop tcp any any -> any any (msg:"EXPLOIT SQL Injection UNION SELECT"; pcre:"/union(\\s+all)?\\s+select/i"; classtype:"web-application-attack"; sid:1000040; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT SQL Injection classic OR tautology"; pcre:"/('\\s*or\\s+'?1'?\\s*=\\s*'?1|or\\s+1\\s*=\\s*1\\s*(--|#))/i"; classtype:"web-application-attack"; sid:1000041; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT SQL Injection stacked DROP/DELETE query"; pcre:"/(;\\s*drop\\s+(table|database)|;\\s*truncate\\s+table)/i"; classtype:"web-application-attack"; sid:1000042; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT SQL Injection time delay"; pcre:"/(waitfor\\s+delay\\s+'|sleep\\(\\s*\\d+\\s*\\)|benchmark\\(\\s*\\d+\\s*,)/i"; classtype:"web-application-attack"; sid:1000043; rev:1;)

# Cross-Site Scripting (XSS) & CRLF Injection
drop tcp any any -> any any (msg:"EXPLOIT Cross-Site Scripting script injection"; pcre:"/<script[^>]*>|javascript:\\s*/i"; classtype:"web-application-attack"; sid:1000050; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT CRLF header injection attempt"; pcre:"/(\\r\\n|\\n\\r|%0d%0a|%0a%0d)(Set-Cookie|Location):/i"; classtype:"web-application-attack"; sid:1000051; rev:1;)

# Automated Vulnerability Scanning & Exploit Toolkits
drop tcp any any -> any any (msg:"ATTACK Automated vulnerability scanner detected"; pcre:"/(sqlmap|nikto|havij|acunetix|dirbuster|nmap)/i"; http_header; classtype:"attempted-recon"; sid:1000060; rev:1;)
"""


class ContentRule:
    def __init__(self, pattern: str, nocase: bool = False, target: str = "all", negated: bool = False):
        self.pattern = pattern
        self.nocase = nocase
        self.target = target
        self.negated = negated


class PCRERule:
    def __init__(self, regex_pattern: str, flags: int = 0, target: str = "all", negated: bool = False):
        self.regex = re.compile(regex_pattern, flags)
        self.target = target
        self.negated = negated


class SnortRule:
    def __init__(self, action: str, msg: str, sid: int, classtype: str = ""):
        self.action = action.lower()
        self.msg = msg
        self.sid = sid
        self.classtype = classtype
        self.contents: List[ContentRule] = []
        self.pcres: List[PCRERule] = []


class SnortEngine:
    def __init__(self):
        self.rules: List[SnortRule] = []

    def load_rules(self, text: str) -> int:
        count = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rule = self.parse_rule(line)
            if rule:
                self.rules.append(rule)
                count += 1
        return count

    def parse_rule(self, raw: str) -> Optional[SnortRule]:
        m = re.match(r"^([a-zA-Z]+)\s+([a-zA-Z]+)\s+([^\s]+)\s+([^\s]+)\s+->\s+([^\s]+)\s+([^\s]+)\s*\((.*)\)$", raw)
        if not m:
            return None
        action = m.group(1).lower()
        options_str = m.group(7)

        msg = ""
        sid = 0
        classtype = ""
        contents = []
        pcres = []

        # Split options by ';' while ignoring quoted semicolons
        parts = [p.strip() for p in re.split(r';(?=(?:[^"]*"[^"]*")*[^"]*$)', options_str) if p.strip()]

        current_content: Optional[ContentRule] = None
        current_pcre: Optional[PCRERule] = None

        for opt in parts:
            if ":" in opt:
                key, val = opt.split(":", 1)
                key = key.strip().lower()
                val = val.strip().strip('"')

                if key == "msg":
                    msg = val
                elif key == "sid":
                    sid = int(val)
                elif key == "classtype":
                    classtype = val
                elif key == "content":
                    negated = val.startswith("!")
                    if negated:
                        val = val[1:].strip('"')
                    current_content = ContentRule(pattern=val, negated=negated)
                    contents.append(current_content)
                    current_pcre = None
                elif key == "pcre":
                    negated = val.startswith("!")
                    if negated:
                        val = val[1:].strip('"')
                    # format: /regex/flags
                    p_match = re.match(r"^/(.*)/([a-zA-Z]*)$", val)
                    if p_match:
                        p_body = p_match.group(1)
                        p_flags_str = p_match.group(2)
                        re_flags = 0
                        if "i" in p_flags_str:
                            re_flags |= re.IGNORECASE
                        if "s" in p_flags_str:
                            re_flags |= re.DOTALL
                        if "m" in p_flags_str:
                            re_flags |= re.MULTILINE
                        current_pcre = PCRERule(p_body, re_flags, negated=negated)
                        pcres.append(current_pcre)
                        current_content = None
            else:
                flag = opt.strip().lower()
                if flag == "nocase" and current_content:
                    current_content.nocase = True
                elif flag in ("http_uri", "http_header", "http_client_body", "http_method"):
                    if current_pcre:
                        current_pcre.target = flag
                    elif current_content:
                        current_content.target = flag

        rule = SnortRule(action, msg, sid, classtype)
        rule.contents = contents
        rule.pcres = pcres
        return rule

    def inspect(self, method: str, url: str, headers: Dict[str, str], body: str) -> Tuple[bool, Optional[SnortRule], str]:
        parsed = urllib.parse.urlparse(url)
        full_uri = parsed.path + ("?" + parsed.query if parsed.query else "")
        unquoted_uri = urllib.parse.unquote(full_uri)

        raw_headers = "\n".join(f"{k}: {v}" for k, v in headers.items())
        all_buf = f"{method} {full_uri} {unquoted_uri}\n{raw_headers}\n{body}"

        for rule in self.rules:
            matched = True
            for c in rule.contents:
                buf = self._get_target_buffer(c.target, method, url, full_uri, unquoted_uri, raw_headers, body, all_buf)
                pattern = c.pattern
                if c.nocase:
                    found = pattern.lower() in buf.lower()
                else:
                    found = pattern in buf
                if c.negated:
                    found = not found
                if not found:
                    matched = False
                    break

            if not matched:
                continue

            for p in rule.pcres:
                buf = self._get_target_buffer(p.target, method, url, full_uri, unquoted_uri, raw_headers, body, all_buf)
                found = bool(p.regex.search(buf))
                if p.negated:
                    found = not found
                if not found:
                    matched = False
                    break

            if matched:
                is_blocking = rule.action in ("drop", "block", "reject")
                reason = f"[SID {rule.sid}] {rule.classtype}: {rule.msg}"
                return is_blocking, rule, reason

        return False, None, ""

    def _get_target_buffer(self, target: str, method: str, url: str, full_uri: str, unquoted_uri: str, raw_headers: str, body: str, all_buf: str) -> str:
        if target == "http_uri":
            unquoted_url = urllib.parse.unquote(url)
            return f"{url} {unquoted_url} {full_uri} {unquoted_uri}"
        elif target == "http_header":
            return raw_headers
        elif target == "http_client_body":
            return body
        elif target == "http_method":
            return method
        return all_buf


class MCPServer:
    def __init__(self, engine: SnortEngine):
        self.engine = engine
        self.stats = {"total_inspected": 0, "total_passed": 0, "total_blocked": 0}

    def run(self):
        logging.info("Starting ax-mcp-proxy on stdio (rules: %d)", len(self.engine.rules))
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                self._send_error(None, -32700, "Parse error")
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
            self._execute_get_stats(req_id)
        else:
            self._send_error(req_id, -32601, f"Unknown tool {name}")

    def _execute_http_request(self, req_id: Any, args: Dict[str, Any]):
        self.stats["total_inspected"] += 1
        url = args.get("url", "")
        method = args.get("method", "GET").upper()
        headers = args.get("headers", {})
        body = args.get("body", "")
        timeout = float(args.get("timeout_seconds", 30))

        if not url:
            self._send_tool_result(req_id, "Missing required parameter 'url'", is_error=True)
            return

        # Inspect against Snort rules
        blocked, rule, reason = self.engine.inspect(method, url, headers, body)
        if blocked:
            self.stats["total_blocked"] += 1
            logging.warning("Blocked outbound request to %s: %s", url, reason)
            self._send_tool_result(
                req_id,
                f"SECURITY VIOLATION: Outbound request blocked by intrusion prevention rule. Reason: {reason} (Action: {rule.action if rule else 'block'})",
                is_error=True,
            )
            return

        self.stats["total_passed"] += 1

        # Execute safe request
        try:
            req_data = body.encode("utf-8") if body and method in ("POST", "PUT", "PATCH") else None
            req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status_code = resp.status
                resp_headers = dict(resp.headers)
                resp_body = resp.read(10 * 1024 * 1024).decode("utf-8", errors="replace")

            out = {
                "status_code": status_code,
                "headers": resp_headers,
                "body": resp_body,
            }
            self._send_tool_result(req_id, json.dumps(out, indent=2), is_error=False)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            out = {
                "status_code": e.code,
                "headers": dict(e.headers),
                "body": err_body,
            }
            self._send_tool_result(req_id, json.dumps(out, indent=2), is_error=True)
        except Exception as e:
            self._send_tool_result(req_id, f"Request failed: {e}", is_error=True)

    def _execute_check_payload(self, req_id: Any, args: Dict[str, Any]):
        url = args.get("url", "")
        method = args.get("method", "GET").upper()
        headers = args.get("headers", {})
        body = args.get("body", "")

        blocked, rule, reason = self.engine.inspect(method, url, headers, body)
        res = {
            "blocked": blocked,
            "matched": rule is not None,
            "rule_sid": rule.sid if rule else None,
            "rule_msg": rule.msg if rule else None,
            "classtype": rule.classtype if rule else None,
            "action": rule.action if rule else None,
        }
        self._send_tool_result(req_id, json.dumps(res, indent=2))

    def _execute_get_stats(self, req_id: Any):
        res = {
            **self.stats,
            "rules_loaded": len(self.engine.rules),
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
                "description": "Proxies outbound HTTP/API requests with Snort-based intrusion detection and exploit protection. Replaces raw curl, socket, or python HTTP calls to 3rd-party servers.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Destination URL to request (e.g. https://api.github.com/repos)"},
                        "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"], "default": "GET"},
                        "headers": {"type": "object", "description": "HTTP headers", "additionalProperties": {"type": "string"}},
                        "body": {"type": "string", "description": "Request body payload"},
                        "timeout_seconds": {"type": "integer", "default": 30},
                    },
                    "required": ["url"],
                },
            },
            {
                "name": "check_security_payload",
                "description": "Diagnostic tool to test whether a URL, headers, or body violate Snort security rules without sending network traffic.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "method": {"type": "string", "default": "GET"},
                        "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                        "body": {"type": "string"},
                    },
                    "required": ["url"],
                },
            },
            {
                "name": "get_security_stats",
                "description": "Returns operational statistics on requests inspected, passed, and blocked by Snort rules.",
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]


def main():
    parser = argparse.ArgumentParser(description="AX MCP Security Proxy Server")
    parser.add_argument("--rules", help="Path to custom Snort rules file")
    parser.add_argument("--only-custom-rules", action="store_true", help="Load only custom rules without default rules")
    args = parser.parse_args()

    engine = SnortEngine()
    if not args.only_custom_rules:
        engine.load_rules(DEFAULT_RULES_SNORT)
    if args.rules:
        with open(args.rules, "r", encoding="utf-8") as f:
            engine.load_rules(f.read())

    server = MCPServer(engine)
    server.run()


if __name__ == "__main__":
    main()
