#!/usr/bin/env python3
"""Bind the preceding and repaired structural plugins to their saved sources."""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / "plugins"
if not __debug__:
    raise RuntimeError("plugin evidence requires assertions")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(baseline_source, baseline_report, repaired_report):
    old, new = (json.loads(path.read_text()) for path in (baseline_report, repaired_report))
    for label, report, directory in (("baseline", old, baseline_source), ("repaired", new, SOURCE)):
        for name, expected in report["source_sha256"].items():
            assert digest(directory / name) == expected, (label, name)
        assert digest(Path(report["plugin"])) == report["plugin_sha256"]
        assert report["sanitizers"]
    assert old["sdk_sha256"] == new["sdk_sha256"] and old["snort_version"] == new["snort_version"]
    before = {path.name: digest(path) for path in baseline_source.iterdir()
              if path.is_file() and path.name != "preceding-build-report.json"}
    after = {path.name: digest(path) for path in SOURCE.iterdir() if path.is_file()}
    changes = {name: {"before": before.get(name), "after": after.get(name)}
               for name in before.keys() | after.keys() if before.get(name) != after.get(name)}
    assert set(changes) == {"build.py", "home_address.h", "home_address_test.cc", "ip6_options.h", "README.md"}
    return {"scope": "Local build and pure-parser records. Baseline sources were preserved before editing. Native replay is separate.",
            "baseline": old, "repaired": new, "same_sdk": True,
            "source_changes": changes, "baseline_source_sha256": before, "repaired_source_sha256": after,
            "input_report_sha256": {str(path): digest(path) for path in (baseline_report, repaired_report)},
            "recorder_sha256": digest(Path(__file__))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-source", type=Path, required=True)
    parser.add_argument("--baseline-build-report", type=Path, required=True)
    parser.add_argument("--repaired-build-report", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = record(args.baseline_source.resolve(), args.baseline_build_report.resolve(), args.repaired_build_report.resolve())
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({name: result[name]["plugin_sha256"] for name in ("baseline", "repaired")}, indent=2))


if __name__ == "__main__":
    main()
