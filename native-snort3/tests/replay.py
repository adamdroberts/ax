#!/usr/bin/env python3
"""Replay synthetic fixtures locally; never transmit traffic or change a firewall."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

from generate_pcaps import generate

HERE = Path(__file__).resolve().parent
NATIVE = HERE.parent
ROOT = NATIVE.parent
BLOCKING = {"would_drop", "would_block", "drop", "block"}


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_profiles", NATIVE / "validate_profiles.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_capture(snort, path, plugin_path):
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}
    result = subprocess.run(
        [str(snort), "--plugin-path", str(plugin_path), "-c", str(NATIVE / "protocol-ips.lua"), "-r", str(path),
         "-s", "65535", "-A", "alert_json", "-q"],
        env=environment, capture_output=True, text=True, timeout=30,
    )
    if result.returncode:
        raise RuntimeError(result.stderr + result.stdout)
    alerts = []
    for line in result.stdout.splitlines():
        entry = json.loads(line)
        alerts.append({key: entry[key] for key in ("rule", "action", "msg")})
    if result.stderr.strip():
        raise RuntimeError("Unexpected Snort diagnostic: " + result.stderr)
    return alerts


def replay(snort, directory, plugin_path):
    snort, plugin_path = snort.resolve(strict=True), plugin_path.resolve(strict=True)
    binary_hash = hashlib.sha256(snort.read_bytes()).hexdigest()
    files = [HERE / "generate_pcaps.py", HERE / "replay.py"]
    source_hashes = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                     for path in files}
    profiles = load_validator().validate(snort, plugin_path)
    manifest = generate(directory)
    results = []
    for case in manifest:
        path = directory / case["file"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != case["sha256"]:
            raise RuntimeError("Fixture hash mismatch: " + case["name"])
        alerts = run_capture(snort, path, plugin_path)
        blocking = [event for event in alerts if event["action"] in BLOCKING]
        expected = case["expected_drop_rule"]
        if expected is None:
            passed = not blocking
        else:
            passed = any([int(part) for part in event["rule"].split(":")[:2]] == expected
                         for event in blocking)
        results.append({**case, "passed": passed, "observed": alerts})
    if binary_hash != hashlib.sha256(snort.read_bytes()).hexdigest():
        raise RuntimeError("Snort binary changed during replay")
    for relative, expected in source_hashes.items() | profiles["sha256"].items():
        if hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() != expected:
            raise RuntimeError("Source/configuration changed during replay: " + relative)
    plugin_files = [plugin_path] if plugin_path.is_file() else sorted(
        set(plugin_path.rglob("*.so")) | set(plugin_path.rglob("*.dylib")))
    if profiles["plugin_sha256"] != {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                    for path in plugin_files}:
        raise RuntimeError("Plugin changed during replay")
    failures = [case["name"] for case in results if not case["passed"]]
    return {
        "snort_version": profiles["snort_version"], "source_commit": profiles["source_commit"],
        "snort_binary_sha256": binary_hash,
        "scope": "Offline readback with inline simulation. would_drop/would_block are simulated verdicts; live packet blocking and deployment topology are not tested.",
        "configuration": profiles,
        "fixture_source_sha256": source_hashes,
        "summary": {"cases": len(results), "passed": len(results) - len(failures),
                    "valid_cases": sum(case["category"] == "valid" for case in results),
                    "malformed_cases": sum(case["category"] == "malformed" for case in results),
                    "policy_rejections": sum(case["category"] == "policy_rejection" for case in results),
                    "failures": failures},
        "cases": results,
        "policy_restrictions": ["All atomic IPv6 fragments are dropped by 116:458, including otherwise valid non-ND traffic. This is a stricter local policy, not universal RFC invalidity.",
                                "More than eight IPv6 extension headers are dropped by 116:456 as a local inspection budget, not a universal RFC limit.",
                                "The base Next Header admission set retains the pinned decoder's prior set plus AH; other values remain local policy rejections, not universal RFC invalidity.",
                                "First-fragment upper-layer header shapes unknown to the bounded validator are rejected by local policy; nested Fragment and more than eight post-fragment extensions also fail closed."],
        "limitations": ["Only selected behaviors are replayed; passing fixtures are not exhaustive standards conformance.",
                        "Read-file inline simulation skips checksum-drop enforcement. Run checksum_replay.py for file-only inline DAQ verdict and forwarded-output evidence.",
                        "No live inline DAQ, deployment route, resource-exhaustion load or encrypted application traffic is tested."],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snort", type=Path, required=True)
    parser.add_argument("--plugin-path", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--pcaps", type=Path, help="Keep generated fixtures in this directory")
    args = parser.parse_args()
    if args.pcaps:
        report = replay(args.snort.resolve(), args.pcaps, args.plugin_path.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix="ax-snort-replay-") as directory:
            report = replay(args.snort.resolve(), Path(directory), args.plugin_path.resolve())
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"summary": report["summary"], "limitations": report["limitations"]}, indent=2))
    if report["summary"]["failures"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
