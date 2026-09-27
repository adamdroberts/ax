#!/usr/bin/env python3
"""Regenerate AX's reviewed Agent Guard import without executing archive code.

This importer consumes the pinned data snapshot and reviewed coverage mappings.
--check verifies all generated outputs. It preserves hand-authored AX signatures
outside its marked section. Runtime behavior is tested separately in Go/Python.
"""
from __future__ import annotations

import argparse
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cmd/ax-mcp-proxy"))
import ax_mcp_proxy as ax

RULE_DIR = ROOT / "pkg/security/snort/rules"
IMPORT_DIR = ROOT / "pkg/security/snort/imports/agent-guard-snort3"
FIXTURES = ROOT / "pkg/security/snort/testdata/rule_cases.json"
MARKER = "# BEGIN GENERATED AGENT GUARD IMPORT\n"
ARCHIVE_SHA256 = "b1555e5100070173700dbdd06032a3e22c43de09d2ca3bb1492d37f385c882ba"
SOURCE_SHA256 = "fad4889422b121d0c57680ce90b0ca1a790918ca781f9a69d04031bcaf7707ba"
BASE_ALIASES = {1200101: 1100101, 1200102: 1100103, 1200103: 1100117,
                1200104: 1100107, 1200105: 1100104, 1200132: 1100718}
# The imported URI substring rule also covers the old strict /dns-query route
# predicate and is promoted to drop in strict mode. Keep one active signature.
STRICT_SUBSUMPTIONS = {1200133: 9104053}
BLOCKING = {"block", "drop", "reject"}
POLICY_ADAPTATIONS = {
    9114035: "Authorization credentials are expected on legitimate upstream API calls; retain telemetry in both profiles instead of treating authentication as exfiltration.",
}
POLICY_COVERAGE = {
    9102018: "Transport forbids agent-supplied Content-Length and Transfer-Encoding.",
    9102019: "Transport forbids agent-supplied Content-Length and duplicate header names.",
    9102020: "Transport forbids agent-supplied Host and duplicate header names.",
    9102021: "Transport forbids agent-supplied Transfer-Encoding and duplicate header names.",
    9102022: "Request header values containing CR/LF are rejected.",
    9102025: "Literal URL NUL/control bytes are rejected before dispatch.",
    9102030: "Transport forbids agent-supplied Proxy-Authorization.",
    9102046: "Non-identity request Content-Encoding is rejected.",
    9102047: "Non-identity request Content-Encoding is rejected.",
    9102048: "Non-identity request Content-Encoding is rejected.",
    9102049: "Non-identity request Content-Encoding is rejected.",
    9102051: "Transport manages Content-Length; actual body length is limited to 1 MiB.",
    9102052: "Transport manages Content-Length and rejects agent-supplied values.",
    9102053: "The HTTP transport generates Host from a required absolute destination URL.",
}


def json_text(data):
    return json.dumps(data, indent=2, ensure_ascii=True) + "\n"


def parse_lines(text):
    result = {}
    for line in text.splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            rule = ax.SnortEngine().parse_rule(line)
            if rule.sid in result:
                raise ValueError(f"duplicate SID {rule.sid}")
            result[rule.sid] = (rule, line)
    return result


def detection_key(rule):
    # Ignore identity/action/message and redundant capture groups or slash escaping.
    # Distinct buffers, case handling, negation, and byte windows remain distinct.
    contents = tuple(sorted((c.target, (c.pattern.lower() if c.nocase else c.pattern).hex(),
                             c.nocase, c.negated, c.offset, c.depth) for c in rule.contents))
    pcres = tuple(sorted((p.target, p.regex.pattern.replace(r"\/", "/").replace("(?:", "("),
                          int(p.regex.flags), p.negated) for p in rule.pcres))
    return contents, pcres


def action_line(line, action):
    return action + " " + line.split(" ", 1)[1]


def quote_content(text):
    # Source content is explicitly byte-oriented. All imported content is ASCII;
    # non-ASCII byte fixtures are native-only response/protocol signatures.
    parts = []
    for char in text:
        n = ord(char)
        if n > 255:
            raise ValueError("source content must be byte-oriented")
        if n < 32 or n > 126 or char in '\\";|':
            parts.append(f"|{n:02x}|")
        else:
            parts.append(char)
    return "".join(parts)


def translate(source):
    target = source["selector"]
    opts = [f'msg:"AGENT GUARD {source["title"].replace(chr(34), chr(39)).replace(chr(92), "/")}";']
    translations = ["Snort inspector flow/address constraints replaced by AX outbound-request context.",
                    "Snort fast_pattern selection omitted; it does not change match predicates."]
    for match in source["matches"]:
        if match["kind"] == "content":
            opts.append(f'content:"{quote_content(match["value"])}";')
            if match["nocase"]:
                opts.append("nocase;")
            if match["depth"] is not None:
                opts.append(f'depth:{match["depth"]};')
        elif match["kind"] == "pcre":
            pattern = match["value"]
            # These standalone predicates end in a lookahead. Consuming the same
            # final delimiter preserves boolean match existence (no relative rules).
            suffix = r'(?=[:/\s\x22]|$)'
            if pattern.endswith(suffix):
                pattern = pattern[:-len(suffix)] + r'(?:[:/\s\x22]|$)'
                translations.append("Terminal delimiter lookahead converted to an equivalent consuming group for RE2.")
            pattern = pattern.replace('"', r'\x22')
            opts.append('pcre:' + ('!' if match["negate"] else '') + '"/' + pattern + '/' + match["flags"] + '";')
        else:
            raise ValueError("unsupported predicate")
        opts.append(target + ";")
    opts.extend(['classtype:"policy-violation";', f'sid:{source["sid"]};', f'rev:{source["rev"]};'])
    line = source["action"] + ' tcp any any -> any any (' + " ".join(opts) + ')'
    ax.SnortEngine().parse_rule(line)
    return line, translations


def render_native(source):
    # Render only retained native records as data. No source generator is executed.
    title = source["title"].replace('"', "'").replace(';', ',').replace('\\', '/')
    options = [f'msg:"AGENT-GUARD {title}";']
    if source["sensor"] == "inspect":
        options.append("flow:established," + ("to_client" if source["direction"] == "response" else "to_server") + ";")
    if source["selector"]:
        options.append(source["selector"] + ";")
    for match in source["matches"]:
        if match["kind"] == "content":
            mods = []
            if match["nocase"]:
                mods.append("nocase")
            if match["fast"]:
                mods.append("fast_pattern")
            if match["depth"] is not None:
                mods.append("depth " + str(match["depth"]))
            options.append('content:"' + quote_content(match["value"]) + '"' + ("," + ",".join(mods) if mods else "") + ";")
        elif match["kind"] == "pcre":
            pattern = match["value"].replace("/", r"\/").replace('"', r"\x22")
            options.append('pcre:' + ('!' if match["negate"] else '') + '"/' + pattern + '/' + match["flags"] + '";')
        else:
            raise ValueError("unknown native predicate")
    options.extend(source["extra"])
    options.extend([f'priority:{1 if source["action"] == "block" else 2};',
                    f'metadata:created_at 2026_09_26, deployment agent_guard, category {source["category"]};',
                    f'sid:{source["sid"]};', f'rev:{source["rev"]};'])
    return source["action"] + " " + source["header"] + " (" + " ".join(options) + ")"

def native_reason(source):
    if source["sensor"] != "inspect":
        return "Requires packet addresses, ports, protocols or TCP flags at a separate network boundary."
    if source["direction"] != "request":
        return "Requires response/file inspection or response rate counters, outside AX request-only inspection."
    if source["selector"] == "http_raw_header":
        return "Requires original wire headers; MCP header maps cannot preserve that representation."
    if source["selector"] == "pkt_data":
        return "Requires raw packet payload before HTTP parsing; AX constructs HTTP requests."
    if source["extra"] or not source["matches"]:
        return "Requires native threshold/header-count/buffer-length predicates; source contract limits differ from AX."
    if source["conditions"]:
        raise ValueError("unexpected source conditions; manual review required")
    return None


def source_request(source, sample=None):
    value = source["sample"] if sample is None else sample
    result = {"method": "POST", "url": "https://example.test/inspect", "headers": {}, "body": ""}
    target = source["selector"]
    if target in ("http_client_body", "http_raw_body"):
        result["body"] = value
    elif target in ("http_uri", "http_raw_uri"):
        value = value if value.startswith("/") else "/search?q=" + value
        # URI source samples contain raw spaces and controls. Encode for a valid
        # transport while preserving already-encoded sequences used by raw rules.
        result["url"] = "https://example.test" + urllib.parse.quote(value, safe="/:?&=+%@[]!$'()*,-._~\\")
    elif target == "http_method":
        result["method"] = value
    elif target.startswith("http_header:field "):
        name = target.split(" ", 1)[1]
        if name == "host":
            result["url"] = "https://" + value + "/inspect"
        else:
            result["headers"][name.title()] = value
    else:
        raise ValueError(f"cannot produce request fixture for {target}")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify output without writing")
    args = parser.parse_args()
    raw = (IMPORT_DIR / "source-catalog.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        raise ValueError("source catalog digest changed; review and pin the new source first")
    source = json.loads(raw)["rules"]
    if len({r["sid"] for r in source}) != len(source) or len(source) != 825:
        raise ValueError("source inventory changed or has SID collisions")
    by_source = {r["sid"]: r for r in source}
    review = json.loads((IMPORT_DIR / "dedup-review.json").read_text())
    mappings = {r["source_sid"]: r for r in review["mappings"] + review["profile_only_mappings"]}
    for item in review.get("source_to_source_mappings", []):
        mappings[item["source_sid"]] = {**item, "existing_sid": item["retained_source_sid"]}

    default_text = (RULE_DIR / "default.rules").read_text().split(MARKER)[0].rstrip() + "\n"
    strict_text = (RULE_DIR / "strict.rules").read_text()
    default = parse_lines(default_text)
    strict = parse_lines(strict_text)
    for old, retained in STRICT_SUBSUMPTIONS.items():
        if old in strict:
            old_rule, old_line = strict.pop(old)
            if old_rule.contents or len(old_rule.pcres) != 1 or old_rule.pcres[0].regex.pattern != '/dns-query([?#]|$)':
                raise ValueError(f"review strict subsumption {old}->{retained} after predicate change")
            strict_text = strict_text.replace(old_line + "\n", "")
    overrides = {str(sid): "drop" for sid in BASE_ALIASES.values()}
    # Remove exact existing strict duplicates; retain policy by changing the action
    # of one retained signature when the strict profile is selected.
    for old, new in BASE_ALIASES.items():
        if old in strict:
            if detection_key(strict[old][0]) != detection_key(default[new][0]):
                raise ValueError(f"baseline alias {old}->{new} no longer equivalent")
            strict_text = strict_text.replace(strict.pop(old)[1] + "\n", "")
    # A source rule matching strict-only coverage becomes default telemetry on the
    # retained SID. CONNECT is an explicit balanced-profile block in the source.
    for item in review["profile_only_mappings"]:
        sid = item["existing_sid"]
        if sid in strict:
            old_rule, old_line = strict.pop(sid)
            strict_text = strict_text.replace(old_line + "\n", "")
            line = action_line(old_line, item["source_action"])
            default_text += line + "\n"
            default[sid] = (ax.SnortEngine().parse_rule(line), line)
        if default[sid][0].action == "alert" and item["source_strict_action"] in BLOCKING:
            overrides[str(sid)] = "drop"

    pending = {}
    decisions = {}
    for r in source:
        sid = r["sid"]
        info = {"source_sid": sid, "category": r["category"], "title": r["title"],
                "source_action": r["action"], "source_strict_action": r["strict_action"]}
        if sid in POLICY_COVERAGE:
            decisions[sid] = {**info, "status": "enforced_by_proxy", "reason": POLICY_COVERAGE[sid]}
            continue
        reason = native_reason(r)
        if reason:
            decisions[sid] = {**info, "status": "native_only", "reason": reason}
            continue
        line, notes = translate(r)
        pending[sid] = (ax.SnortEngine().parse_rule(line), line)
        decisions[sid] = {**info, "status": "imported", "ax_sid": sid, "adaptations": notes}

    # Reviewed semantic subsumptions; exact-byte equality alone is insufficient.
    for sid, m in mappings.items():
        if sid not in pending:
            continue
        target = m["existing_sid"]
        if target not in default and target not in pending:
            raise ValueError(f"coverage target {target} is unavailable")
        decisions[sid] = {**decisions[sid], "status": "deduplicated", "ax_sid": target, "reason": m["reason"]}
        pending.pop(sid)

    def resolve(sid):
        seen = set()
        while sid in decisions and decisions[sid]["status"] == "deduplicated":
            if sid in seen:
                raise ValueError("coverage cycle")
            seen.add(sid)
            sid = decisions[sid]["ax_sid"]
        return sid

    # Fingerprints ignore identity/action metadata while retaining match semantics.
    # This also rejects future accidental duplicates between the two AX packs.
    seen = {}
    for sid, (rule, line) in {**default, **strict, **pending}.items():
        key = detection_key(rule)
        if key in seen:
            if sid not in pending:
                raise ValueError(f"unexpected existing duplicate {sid} and {seen[key]}")
            target = seen[key]
            pending.pop(sid)
            decisions[sid] = {**decisions[sid], "status": "deduplicated", "ax_sid": target,
                              "reason": "Equal detection fingerprint ignoring identity/action metadata."}
        else:
            seen[key] = sid

    active = {**default, **strict, **pending}
    for r in source:
        decision = decisions[r["sid"]]
        if decision["status"] not in ("deduplicated", "imported"):
            continue
        sid = resolve(decision["ax_sid"])
        decision["ax_sid"] = sid
        retained, line = active[sid]
        if r["action"] in BLOCKING and retained.action == "alert":
            # Existing coverage is preserved, and the new source may strengthen it.
            line = action_line(line, r["action"])
            retained = ax.SnortEngine().parse_rule(line)
            if sid in default:
                default_text = default_text.replace(default[sid][1], line)
                default[sid] = (retained, line)
            else:
                pending[sid] = (retained, line)
            active[sid] = (retained, line)
        if retained.action == "alert" and r["strict_action"] in BLOCKING and r["sid"] not in POLICY_ADAPTATIONS:
            overrides[str(sid)] = "drop"
        elif retained.action in BLOCKING:
            overrides.pop(str(sid), None)
        if r["sid"] in POLICY_ADAPTATIONS:
            overrides.pop(str(sid), None)
            decision["policy_adaptation"] = POLICY_ADAPTATIONS[r["sid"]]
        decision["effective_action"] = retained.action
        decision["effective_strict_action"] = overrides.get(str(sid), retained.action)

    profiles = {sid: "default" for sid in default | pending}
    profiles.update({sid: "strict" for sid in strict})
    fixtures = json.loads(FIXTURES.read_text())
    cases = []
    for fixture in fixtures["cases"]:
        if fixture.get("source") == "agent-guard-snort3":
            continue
        c = copy.deepcopy(fixture)
        c["sid"] = (BASE_ALIASES | STRICT_SUBSUMPTIONS).get(c["sid"], c["sid"])
        c["profile"] = profiles[c["sid"]]
        cases.append(c)
    for r in source:
        d = decisions[r["sid"]]
        if d["status"] not in ("imported", "deduplicated"):
            continue
        positive = {"name": f'agent-guard-{r["sid"]}-positive', "sid": d["ax_sid"],
                    "source_sid": r["sid"], "source": "agent-guard-snort3", "profile": profiles[d["ax_sid"]],
                    "match": True, **source_request(r)}
        cases.append(positive)
        if d["status"] == "imported":
            # Negative fixture uses the same surface with benign text. Wrong-field
            # and delimiter/boundary near misses are tested separately below.
            neutral = "GET" if r["selector"] == "http_method" else "example.test" if r["selector"] == "http_header:field host" else "ordinary-report"
            cases.append({**positive, "name": f'agent-guard-{r["sid"]}-benign', "match": False,
                          **source_request(r, neutral)})
            wrong_field = {"method": "GET", "url": "https://example.test/inspect", "headers": {}, "body": r["sample"]}
            if r["selector"] in ("http_client_body", "http_raw_body"):
                wrong_field["body"] = ""
                wrong_field["url"] += "?q=" + urllib.parse.quote(r["sample"], safe="")
            cases.append({**positive, "name": f'agent-guard-{r["sid"]}-wrong-field', "match": False, **wrong_field})
    fixtures["cases"] = cases
    imported_lines = [v[1] for _, v in sorted(pending.items())]
    default_output = default_text + "\n" + MARKER + "# Source and per-SID coverage decisions: ../imports/agent-guard-snort3/import-report.json\n# Generated by tools/import_agent_guard.py. Profile actions are applied without duplicate signatures.\n" + "\n".join(imported_lines) + "\n# END GENERATED AGENT GUARD IMPORT\n"
    counts = Counter(d["status"] for d in decisions.values())
    report = {"schema_version": 1, "source_archive": "agent-guard-snort3.zip", "archive_sha256": ARCHIVE_SHA256,
              "source_catalog_sha256": SOURCE_SHA256, "source_rules": len(source), "source_engine_validated": False,
              "counts": dict(sorted(counts.items())), "active_unique_rules": len(active),
              "default_rules": len(default) + len(pending), "strict_additional_rules": len(strict),
              "strict_action_promotions": len(overrides), "regression_cases": len(cases),
              "baseline_aliases": {str(k): v for k, v in (BASE_ALIASES | STRICT_SUBSUMPTIONS).items()},
              "rules": [decisions[sid] for sid in sorted(decisions)]}
    outputs = {RULE_DIR / "default.rules": default_output, RULE_DIR / "strict.rules": strict_text,
               RULE_DIR / "strict-actions.json": json_text(dict(sorted(overrides.items(), key=lambda kv: int(kv[0])))),
               FIXTURES: json_text(fixtures), IMPORT_DIR / "import-report.json": json_text(report)}
    native_output = "# Native Snort 3 rules retained from the user-provided Agent Guard archive.\n# NOT loaded by the AX Go/Python HTTP proxy. Native validation is separate; see native-snort3/ at repository root.\n# Original balanced-profile actions and network variables are retained.\n# Requires a real Snort installation, matching sensors and independently configured variables.\n# See README.md and source-catalog.json for source strict actions and assumptions.\n\n"
    for entry in report["rules"]:
        if entry["status"] == "native_only":
            native_output += "# " + entry["reason"] + "\n" + render_native(by_source[entry["source_sid"]]) + "\n\n"
    outputs[IMPORT_DIR / "native-only.rules"] = native_output
    mismatches = []
    for path, text in outputs.items():
        if args.check:
            if not path.exists() or path.read_text() != text:
                mismatches.append(str(path.relative_to(ROOT)))
        else:
            path.write_text(text)
    if mismatches:
        raise SystemExit("Generated files are stale: " + ", ".join(mismatches))
    print(json.dumps({k: report[k] for k in ("counts", "active_unique_rules", "default_rules", "strict_additional_rules", "strict_action_promotions", "regression_cases")}, indent=2))


if __name__ == "__main__":
    main()
