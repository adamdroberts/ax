#!/usr/bin/env python3
"""Validate DNS-aware native profiles and reject conflicting configurations.

No interfaces, live network traffic or deployment changes.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

import generate_dns_perimeter as generator

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
HTTP_ENV = {"AX_NATIVE_OVERLAY": "http", "AX_INSPECT_CLIENTS": "10.40.0.0/24,fd00:40::/64",
            "AX_INSPECT_SERVERS": "10.50.0.10,fd00:50::10", "AX_INSPECT_PORTS": "8080,8081"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def environment(http=False):
    clean = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}
    return clean | (HTTP_ENV if http else {})


def expected_actions(http=False):
    inventory = json.loads((HERE / "builtin-inventory.json").read_text())
    result = {(r["gid"], r["sid"]): r["action"] for r in inventory["rules"]}
    lines = (HERE / "protocol-validation.rules").read_text().splitlines()
    lines += generator.rules()[1]
    if http:
        lines += [line for line in generator.IMPORTED.read_text().splitlines() if "$INSPECT_CLIENTS" in line and not line.startswith("#")]
    for line in lines:
        if not line or line.startswith("#"):
            continue
        key = (1, int(re.search(r"; sid:(\d+);", line)[1]))
        assert key not in result, "duplicate native rule ID"
        result[key] = line.split()[0]
    assert all((1, sid) not in result for sid in range(9101001, 9101007)), "original perimeter leaked into DNS profile"
    return result


def validate(snort, plugin):
    snort, plugin = snort.resolve(strict=True), plugin.resolve(strict=True)
    assert subprocess.check_output([str(snort), "--dump-version"], text=True).strip() == "3.12.2.0"
    plugin_files = sorted(plugin.glob("*.so"))
    assert {path.name for path in plugin_files} == {"ax_nd_options.so", "ax_ip6_route_present.so"}
    sources = [Path(__file__), HERE / "generate_dns_perimeter.py", HERE / "dns-perimeter.rules",
               HERE / "dns-perimeter.example.json", generator.IMPORTED,
               HERE / "perimeter/ax_ip6_route_present.cc", HERE / "perimeter/build.py",
               HERE / "plugins/home_address.h",
               *[HERE / name for name in ("builtin-inventory.json", "protocol-ips.lua", "protocol.states",
                                          "protocol-builtins.rules", "protocol-validation.rules", "agent-guard-overlay.lua")]]
    hashes = {str(path.relative_to(ROOT)): digest(path) for path in sources}
    binary_hash, plugin_hashes = digest(snort), {path.name: digest(path) for path in plugin_files}
    results, negatives = [], []
    with tempfile.TemporaryDirectory(prefix="ax-dns-perimeter-config-") as temporary:
        paths = {}
        for http in (False, True):
            config = Path(temporary) / ("dns-http.lua" if http else "dns.lua")
            config.write_text(generator.render(generator.load(HERE / "dns-perimeter.example.json"), http))
            paths[http] = config
            command = [str(snort), "--plugin-path", str(plugin), "-c", str(config), "-T", "--dump-rule-state"]
            run = subprocess.run(command, env=environment(http), text=True, capture_output=True, timeout=60)
            assert run.returncode == 0, run.stdout + run.stderr
            observed = {}
            for line in run.stdout.splitlines():
                state = json.loads(line)
                key = state["gid"], state["sid"]
                assert key not in observed, "duplicate loaded ID"
                assert len(state["states"]) == 1 and state["states"][0]["enable"] == "yes"
                observed[key] = state["states"][0]["action"]
            assert observed == expected_actions(http), "effective action or scope mismatch"
            assert len(observed) < 512
            assert max(Counter(action for (gid, _), action in observed.items() if gid == 1).values()) < 100
            results.append({"profile": "dns-and-http" if http else "dns", "enabled": len(observed),
                            "actions": dict(Counter(observed.values())), "config_sha256": digest(config)})
        for name, http, overlay, with_plugin in (("extra-perimeter", False, "perimeter", True),
                ("both-overlays", False, "both", True), ("missing-http-selection", True, None, True),
                ("http-with-both", True, "both", True), ("missing-plugins", False, None, False)):
            env = environment(http)
            env.pop("AX_NATIVE_OVERLAY", None)
            if overlay is not None:
                env["AX_NATIVE_OVERLAY"] = overlay
            command = [str(snort)] + (["--plugin-path", str(plugin)] if with_plugin else [])
            command += ["-c", str(paths[http]), "-T", "-q"]
            run = subprocess.run(command, env=env, text=True, capture_output=True, timeout=60)
            assert run.returncode != 0, "invalid configuration accepted: " + name
            negatives.append({"name": name, "rejected": True})
    assert hashes == {str(path.relative_to(ROOT)): digest(path) for path in sources}
    assert digest(snort) == binary_hash and plugin_hashes == {path.name: digest(path) for path in plugin_files}
    return {"scope": "Configuration and effective rule states only; not packet forwarding or deployment.",
            "snort_version": "3.12.2.0", "snort_binary_sha256": binary_hash,
            "plugin_sha256": plugin_hashes, "source_sha256": hashes, "profiles": results, "negative_cases": negatives}


def main():
    if not __debug__:
        raise RuntimeError("validation requires assertions")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snort", type=Path, required=True)
    parser.add_argument("--plugin-path", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = validate(args.snort, args.plugin_path)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"profiles": report["profiles"], "rejected": len(report["negative_cases"])}))


if __name__ == "__main__":
    main()
