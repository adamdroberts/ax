#!/usr/bin/env python3
"""Build DNS perimeter options alongside an existing protocol plugin.

Uses the operator's compiler and Snort 3.12.2.0 SDK. No downloads or installation.
The output directory must be new, so an existing deployment is never replaced.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snort-include", type=Path, required=True)
    parser.add_argument("--daq-include", type=Path, required=True)
    parser.add_argument("--protocol-plugin", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cxx", default="c++")
    parser.add_argument("--sanitize", action="store_true", help="instrument new options with address/undefined sanitizers; use a matching instrumented Snort")
    args = parser.parse_args()
    sdk = args.snort_include.resolve(strict=True)
    daq = args.daq_include.resolve(strict=True)
    protocol = args.protocol_plugin.resolve(strict=True)
    source = HERE / "ax_ip6_route_present.cc"
    headers = [sdk / name for name in ("framework/ips_option.h", "framework/module.h",
               "protocols/layer.h", "protocols/packet.h", "protocols/protocol_ids.h")]
    inputs = (source, Path(__file__), HERE.parent / "plugins/home_address.h", protocol)
    source_hashes = {path.name: digest(path) for path in inputs}
    sdk_hashes = {str(path.relative_to(sdk)): digest(path) for path in headers}
    if protocol.name != "ax_nd_options.so":
        parser.error("--protocol-plugin must be the reviewed ax_nd_options.so library")
    output = args.output_dir.resolve()
    output.mkdir()  # Fail if an output/deployment directory already exists.
    library = output / "ax_ip6_route_present.so"
    command = [args.cxx, "-std=c++17", "-O2", "-fPIC", "-fvisibility=hidden",
               "-DHAVE_VISIBILITY=1", "-Wall", "-Wextra", "-Werror", "-shared"]
    if platform.system() == "Darwin":
        command += ["-Wl,-undefined,dynamic_lookup"]
    if args.sanitize:
        command += ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    command += ["-isystem", str(sdk), "-isystem", str(daq), str(source), "-o", str(library)]
    subprocess.run(command, check=True)
    shutil.copyfile(protocol, output / protocol.name)
    if source_hashes != {path.name: digest(path) for path in inputs}:
        raise RuntimeError("source or protocol plugin changed during build")
    report = {"scope": "Build only; validate the generated profiles and replay captures separately.",
              "command": command, "compiler": subprocess.check_output([args.cxx, "--version"], text=True),
              "source_sha256": source_hashes, "sdk_sha256": sdk_hashes,
              "new_option_sanitizers": ["address", "undefined"] if args.sanitize else [],
              "plugin_sha256": {path.name: digest(path) for path in sorted(output.glob("*.so"))}}
    (output / "build-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(output), "plugin_sha256": report["plugin_sha256"]}))


if __name__ == "__main__":
    main()
