#!/usr/bin/env python3
"""Audit an offset-zero wire-prefix oracle under Snort's current flow grouping.

This is not an endpoint-validity oracle. RFC 8200 processes preceding headers
before queueing; RFC 6275 Home Address processing can change logical source
identity. Differing Home Address semantics can therefore require different
reassembly contexts or rejection at a Mobile IPv6 endpoint.
"""
import argparse
import json
from pathlib import Path
import struct

from home_address_replay import CARE, HOME, DEST, fixture, frame, home, transport, validate


def cases():
    different = "2001:db8::a"
    variants = (("different-home", [home()], [home(different)], HOME, different),
                ("missing-home", [home()], [], HOME, CARE),
                ("added-home", [], [home(different)], CARE, different),
                ("different-padding", [home()], [home(position=14)], HOME, CARE))
    for protocol in (6, 17, 58):
        for label, first, continuation, correct, incorrect in variants:
            for valid in (True, False):
                data = transport(protocol, correct if valid else incorrect, DEST)
                wires = []
                for start, end, prefix in ((0, 24, first), (24, 72, continuation)):
                    frag = (44, bytes([0, 0]) + struct.pack("!HI", start | int(end < 72), 7654))
                    wires.append(frame(prefix + [frag], protocol, data[start:end]))
                for order in ((0, 1), (1, 0)):
                    ordered = [wires[index] for index in order]
                    yield fixture(f"p{protocol}-{label}-" + "".join(map(str, order)) + ("-matches-oracle" if valid else "-differs-from-oracle"),
                                  ordered, ordered if valid else ordered[:-1], protocol, checksum_valid=valid,
                                  source=correct, fragments=True, reassembled=1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snort", type=Path, required=True)
    parser.add_argument("--plugin-path", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = validate(args.snort, args.plugin_path, cases, [Path(__file__).resolve()])
    result["status"] = "wire_prefix_oracle_disagreement" if result["summary"]["failures"] else "verified_wire_prefix_oracle"
    result["scope"] = "File-only inline audit under Snort's current wire-identity flow grouping; not Mobile IPv6 endpoint-validity, binding-state or deployment proof."
    result["oracle"] = {
        "representation": "Select the checksum source from the offset-zero fragment's original wire prefix.",
        "limitation": "Differing Home Address semantics may change source identity before endpoint reassembly; these fixtures do not establish that all fragments belong to one authorized endpoint context.",
        "required_follow_up": "Independently verify offset-zero prefix retention and endpoint processing before queueing, including logical source grouping and binding validation.",
    }
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"], indent=2))
    raise SystemExit(bool(result["summary"]["failures"]))


if __name__ == "__main__":
    main()
