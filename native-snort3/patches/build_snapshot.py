#!/usr/bin/env python3
"""Build an already configured isolated Snort tree and preserve local evidence.

No dependency installation, system installation, interfaces, or traffic.
The configuration manifest must describe the completed local CMake configure.
Optional macOS relocation maps are exact old-library-name/new-path pairs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

if not __debug__:
    raise RuntimeError("build evidence requires assertions")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes(source):
    return {path.relative_to(source).as_posix(): digest(path) for path in sorted(source.rglob("*"))
            if path.is_file() and ".git" not in path.relative_to(source).parts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--configure-manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--relocations", type=Path)
    args = parser.parse_args()
    source, build = args.source.resolve(strict=True), args.build.resolve(strict=True)
    output = args.output_dir.resolve()
    if output == source or source in output.parents or output == build or build in output.parents:
        parser.error("output must be separate from source and build trees")
    output.mkdir(parents=True, exist_ok=False)
    configure = json.loads(args.configure_manifest.read_text())
    assert configure["returncode"] == 0
    cache = (build / "CMakeCache.txt").read_text()
    assert "CMAKE_HOME_DIRECTORY:INTERNAL=" + str(source) + "\n" in cache
    before = source_hashes(source)
    (output / "source-hashes.json").write_text(json.dumps(before, indent=2) + "\n")
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("AX_", "CMAKE_", "DYLD_", "PKG_CONFIG_", "CPPFLAGS",
                                          "CXXFLAGS", "CFLAGS", "LDFLAGS", "CPATH", "LIBRARY_PATH"))}
    environment.update(configure["environment"])
    command = [configure["command"][0], "--build", str(build), "--target", "snort", "--parallel", "6"]
    started = time.monotonic()
    with (output / "build.log").open("w") as log:
        result = subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT)
    assert before == source_hashes(source), "source changed while building"
    report = {"command": command, "returncode": result.returncode,
              "elapsed_seconds": round(time.monotonic() - started, 3),
              "scope": "Local build evidence, not a hermetic reproducible-build or deployment attestation.",
              "builder_sha256": digest(Path(__file__)), "source_unchanged_during_build": True}
    for name in ("CMakeCache.txt", "compile_commands.json", "build.ninja", "config.h"):
        shutil.copy2(build / name, output / name)
    shutil.copy2(args.configure_manifest, output / "configure-manifest.json")
    if result.returncode == 0:
        binary = output / "snort"
        shutil.copy2(build / "src/snort", binary)
        report["raw_binary_sha256"] = digest(binary)
        relocations = json.loads(args.relocations.read_text()) if args.relocations else {}
        report["relocations"] = relocations
        if sys.platform == "darwin":
            links = subprocess.check_output(["otool", "-L", str(binary)], text=True).splitlines()[1:]
            changes = []
            for line in links:
                name = line.strip().split(" (")[0]
                if name in relocations:
                    target = Path(relocations[name]).resolve(strict=True)
                    changes.extend(["-change", name, str(target)])
                elif "@@" in name:
                    raise RuntimeError("unresolved library path: " + name)
            if changes:
                subprocess.run(["install_name_tool", *changes, str(binary)], check=True, capture_output=True)
                subprocess.run(["codesign", "--force", "--sign", "-", str(binary)], check=True, capture_output=True)
        version = subprocess.run([str(binary), "-V"], capture_output=True, text=True)
        report.update(binary_sha256=digest(binary), version_returncode=version.returncode,
                      version_output=version.stdout + version.stderr)
        if version.returncode:
            raise RuntimeError(report["version_output"])
    report["files"] = {path.name: digest(path) for path in sorted(output.iterdir()) if path.is_file()}
    (output / "build-manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("returncode", "elapsed_seconds")}, indent=2))
    if result.returncode:
        print((output / "build.log").read_text()[-5000:])
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
