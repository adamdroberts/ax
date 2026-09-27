#!/usr/bin/env python3
"""Build the ND plugin required by this native profile without installing it."""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
PINNED_VERSION = "3.12.2.0"
# These headers contain the inline policy used by ax_ip6_base_next_header.
# Hashes match the official release-pinned source, not a generated SDK file.
POLICY_HEADER_SHA256 = {
    "protocols/ipv6.h": "4bff3d59ab543445d703a2ca2534b9e952867b39ae624ead8a81896de7018e9a",
    "protocols/protocol_ids.h": "937ebd964888ed51f687854c5eee3101f9e5eadb12fa7de9ca4c6440699cf7cc",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snort-prefix", type=Path, required=True)
    parser.add_argument("--daq-include", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cxx", default="c++")
    parser.add_argument("--sanitize-tests", action="store_true")
    args = parser.parse_args()
    if sys.platform not in ("darwin", "linux"):
        parser.error("this build helper supports macOS and Linux")
    prefix = args.snort_prefix.resolve()
    headers = prefix / "include/snort"
    daq = args.daq_include.resolve()
    for header in (headers / "framework/ips_option.h", daq / "daq_common.h"):
        if not header.is_file():
            parser.error(f"required development header is missing: {header}")
    sdk_hashes = {}
    for name, expected in POLICY_HEADER_SHA256.items():
        path = headers / name
        if not path.is_file():
            parser.error(f"required policy header is missing: {path}")
        sdk_hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        if sdk_hashes[name] != expected:
            parser.error(f"policy header differs from reviewed Snort source: {path}")
    version = subprocess.run([str(prefix / "bin/snort"), "-V"], text=True,
                             capture_output=True, check=True)
    if not re.search(r"\bVersion " + re.escape(PINNED_VERSION) + r"(?:\s|$)", version.stdout + version.stderr):
        parser.error(f"use the validated Snort version {PINNED_VERSION}; re-audit other releases")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    library = output / "ax_nd_options.so"
    compile_plugin = [args.cxx, "-std=c++17", "-O2", "-fPIC", "-fvisibility=hidden",
                      "-DHAVE_VISIBILITY=1", "-Wall", "-Wextra", "-shared"]
    if sys.platform == "darwin":
        compile_plugin.append("-Wl,-undefined,dynamic_lookup")
    compile_plugin += ["-isystem", str(headers), "-isystem", str(daq),
                       str(HERE / "ax_nd_options.cc"), "-o", str(library)]
    subprocess.run(compile_plugin, check=True)
    commands = [compile_plugin]
    checked = []
    for name in ("nd_validation_test", "ip_validation_test", "ip4_options_test",
                 "ip6_options_test", "esp_validation_test", "routing_validation_test", "home_address_test"):
        test = output / name
        compile_test = [args.cxx, "-std=c++17", "-O1", "-g", "-Wall", "-Wextra"]
        if args.sanitize_tests:
            compile_test += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        compile_test += [str(HERE / (name + ".cc")), "-o", str(test)]
        subprocess.run(compile_test, check=True)
        result = subprocess.run([str(test)], text=True, capture_output=True, check=True)
        commands += [compile_test, [str(test)]]
        checked.append(name + ": " + result.stdout.strip())
    report = {
        "snort_version": PINNED_VERSION,
        "plugin": str(library),
        "plugin_sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
        "sdk_sha256": sdk_hashes,
        "source_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in (HERE / "ax_nd_options.cc", HERE / "nd_validation.h",
                                       HERE / "nd_validation_test.cc", HERE / "ip_validation.h",
                                       HERE / "ip_validation_test.cc", HERE / "ip4_options.h",
                                       HERE / "ip4_options_test.cc", HERE / "ip6_options.h",
                                       HERE / "ip6_options_test.cc", HERE / "esp_validation.h",
                                       HERE / "esp_validation_test.cc", HERE / "routing_validation.h",
                                       HERE / "routing_validation_test.cc", HERE / "home_address.h",
                                       HERE / "home_address_test.cc", HERE / "build.py")},
        "commands": commands,
        "sanitizers": args.sanitize_tests,
        "unit_tests": "\n".join(checked),
        "scope": "Build and pure-parser checks only. Load and PCAP replay must be validated separately.",
    }
    (output / "build-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
