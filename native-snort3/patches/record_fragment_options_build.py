#!/usr/bin/env python3
"""Verify matched local snapshots and record fragment-option repair evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import apply_fragment_options_repair as repair

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
if not __debug__:
    raise RuntimeError("build evidence requires assertions")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(build_root, previous_root, upstream):
    snapshots = {name: build_root / name for name in ("baseline", "repaired")}
    manifests, sources = {}, {}
    for name, directory in snapshots.items():
        manifests[name] = json.loads((directory / "build-manifest.json").read_text())
        assert manifests[name]["returncode"] == 0 and manifests[name]["version_returncode"] == 0
        assert manifests[name]["source_unchanged_during_build"]
        assert manifests[name]["builder_sha256"] == digest(HERE / "build_snapshot.py")
        for filename, expected in manifests[name]["files"].items():
            assert digest(directory / filename) == expected, (name, filename)
        sources[name] = json.loads((directory / "source-hashes.json").read_text())
    for filename in ("CMakeCache.txt", "compile_commands.json", "config.h", "build.ninja", "configure-manifest.json"):
        assert (snapshots["baseline"] / filename).read_bytes() == (snapshots["repaired"] / filename).read_bytes()
    previous = json.loads((previous_root / "repaired/source-hashes.json").read_text())
    assert previous == sources["baseline"]
    assert digest(previous_root / "repaired/snort") == manifests["baseline"]["binary_sha256"]
    current = build_root / "source"
    actual = {path.relative_to(current).as_posix(): digest(path) for path in sorted(current.rglob("*"))
              if path.is_file() and ".git" not in path.relative_to(current).parts}
    assert actual == sources["repaired"]
    changed = {name: {"before": sources["baseline"].get(name), "after": sources["repaired"].get(name)}
               for name in sources["baseline"].keys() | sources["repaired"].keys()
               if sources["baseline"].get(name) != sources["repaired"].get(name)}
    assert changed.keys() == {*repair.FILES, repair.HEADER, "ax-fragment-options.patch",
                              "ax-fragment-options-source-validation.json"}
    commit = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    assert commit == repair.type2.COMMIT
    for relative in repair.FILES:
        original = subprocess.check_output(["git", "-C", str(upstream), "show", "HEAD:" + relative])
        assert hashlib.sha256(original).hexdigest() == sources["baseline"][relative]
        assert repair.patched(relative, original) == (current / relative).read_bytes()
    source_report = json.loads((current / "ax-fragment-options-source-validation.json").read_text())
    for name, expected in source_report["local_source_sha256"].items():
        assert digest(HERE / name) == expected
    for relative, expected in source_report["after_sha256"].items():
        assert actual[relative] == expected
    patch = current / "ax-fragment-options.patch"
    assert digest(patch) == source_report["patch_sha256"]
    (HERE / "snort-fragment-options.patch").write_bytes(patch.read_bytes())
    assert manifests["baseline"]["binary_sha256"] != manifests["repaired"]["binary_sha256"]
    return {"scope": "Matched local source builds only; no install, interface or deployment.",
            "upstream_commit": commit,
            "binary_sha256": {name: item["binary_sha256"] for name, item in manifests.items()},
            "comparison": {"same_configuration": True, "baseline_matches_previous_ipv4_route_source": True,
                           "only_fragment_options_repair_changes": True, "source_changes": dict(sorted(changed.items()))},
            "configuration": json.loads((build_root / "configure-manifest.json").read_text()),
            "builds": manifests, "source_repair": source_report,
            "recorder_sha256": digest(Path(__file__)),
            "previous_build_report_sha256": digest(HERE.parent / "ipv4-route-build-validation.json")}


def parser_record(build_root):
    binary = build_root / "fragment-options-parser-test"
    command = ["/usr/bin/clang++", "-std=c++17", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
               "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
               str(HERE / "ipv4_fragment_options_test.cc"), "-o", str(binary)]
    subprocess.run(command, check=True, capture_output=True, text=True)
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
    assert not result.stderr
    return {"scope": "Pure copied-option parser and rejection state; not native reassembly or deployment.",
            "compiler": subprocess.check_output([command[0], "--version"], text=True), "command": command,
            "sanitizers": ["address", "undefined"], "binary_sha256": digest(binary),
            "sha256": {path.relative_to(ROOT).as_posix(): digest(path) for path in
                       (HERE / "ipv4_fragment_options.h", HERE / "ipv4_fragment_options_test.cc", Path(__file__))},
            "summary": json.loads(result.stdout)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--previous-build-root", type=Path, required=True)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--parser-report", type=Path, required=True)
    args = parser.parse_args()
    result = record(args.build_root.resolve(), args.previous_build_root.resolve(), args.upstream.resolve())
    pure = parser_record(args.build_root.resolve())
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    args.parser_report.write_text(json.dumps(pure, indent=2) + "\n")
    print(json.dumps({"binary_sha256": result["binary_sha256"], "parser": pure["summary"]}, indent=2))


if __name__ == "__main__":
    main()
