#!/usr/bin/env python3
"""Check native configuration, effective actions, scope isolation and failure modes.

No packets are transmitted and no interfaces/firewall settings are changed.
Run replay.py separately for packet evidence and an isolated inline lab for
enforcement evidence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

if not __debug__:
    raise RuntimeError("validation requires Python assertions; do not use -O or PYTHONOPTIMIZE")

HERE = Path(__file__).resolve().parent
NATIVE = HERE.parent / "pkg/security/snort/imports/agent-guard-snort3/native-only.rules"
FIXTURE_ENV = {
    "AX_AGENT_NET": "10.20.0.0/24", "AX_BROKER_NET": "10.30.0.10",
    "AX_BROKER_PORTS": "443", "AX_INSPECT_CLIENTS": "10.40.0.0/24",
    "AX_INSPECT_SERVERS": "10.50.0.10", "AX_INSPECT_PORTS": "8080,8081",
}


def validate(snort, plugin_path=None):
    version = subprocess.check_output([str(snort), "--dump-version"], text=True).strip()
    inventory = json.loads((HERE / "builtin-inventory.json").read_text())
    assert version == inventory["snort_version"], f"unsupported Snort {version}"
    expected_base = {(rule["gid"], rule["sid"]): rule["action"] for rule in inventory["rules"]}
    assert len(expected_base) == len(inventory["rules"]), "duplicate builtin ID"
    protocol_rules = (HERE / "protocol-validation.rules").read_text()
    needs_plugin = any("ax_nd_" in line for line in protocol_rules.splitlines()
                       if line.strip() and not line.lstrip().startswith("#"))
    if needs_plugin and plugin_path is None:
        raise ValueError("this profile requires --plugin-path pointing to the reviewed native ND plugin")
    if plugin_path is not None:
        plugin_path = Path(plugin_path).resolve(strict=True)
    for line in protocol_rules.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key = (1, int(re.search(r"; sid:(\d+);", line)[1]))
        assert key not in expected_base, "duplicate protocol validation ID"
        expected_base[key] = line.split()[0]
    native = {}
    for line in NATIVE.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        sid = int(re.search(r"; sid:(\d+);", line)[1])
        assert sid not in native, f"duplicate imported SID {sid}"
        assert (1, sid) not in expected_base, f"imported/protocol SID collision {sid}"
        native[sid] = (line.split()[0], "perimeter" if "$AGENT_NET" in line else "http")
    assert len(native) == 70, "native inventory changed"
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AX_")}

    def run(profile, extra, load_plugin=True):
        command = [str(snort)]
        if load_plugin and plugin_path is not None:
            command.extend(["--plugin-path", str(plugin_path)])
        command.extend(["-c", str(HERE / profile), "-T", "--dump-rule-state"])
        return subprocess.run(command,
                              env=environment | extra, capture_output=True, text=True, timeout=60)

    results = []
    for mode in ("protocol", "perimeter", "http", "both"):
        profile = "protocol-ips.lua" if mode == "protocol" else "agent-guard-overlay.lua"
        env = {} if mode == "protocol" else FIXTURE_ENV | {"AX_NATIVE_OVERLAY": mode}
        result = run(profile, env)
        assert result.returncode == 0, result.stderr + result.stdout
        expected = dict(expected_base)
        if mode != "protocol":
            expected.update({(1, sid): action for sid, (action, scope) in native.items()
                             if mode == "both" or scope == mode})
        observed, seen = {}, set()
        for line in result.stdout.splitlines():
            state = json.loads(line)
            key = state["gid"], state["sid"]
            assert key not in seen, f"duplicate runtime ID {key}"
            seen.add(key)
            assert len(state["states"]) == 1, "unexpected policy count"
            effective = state["states"][0]
            if effective["enable"] == "yes":
                observed[key] = effective["action"]
            else:
                assert effective["enable"] == "no", "unresolved inherited rule state"
        assert observed == expected, f"active action/scope mismatch in {mode}"
        assert seen == expected.keys(), f"unexpected loaded rules (including disabled builtins) in {mode}"
        assert len(observed) < 512, f"enabled catalog exceeds reviewed event queue budget in {mode}"
        text_actions = [action for (gid, _), action in observed.items() if gid == 1]
        assert all(text_actions.count(action) < 100 for action in set(text_actions)), \
            f"text rule action group exceeds native match queue budget in {mode}"
        results.append({"profile": mode, "loaded": len(seen), "enabled": len(observed),
                        "actions": {action: list(observed.values()).count(action)
                                    for action in ("drop", "block", "alert")}})

    negatives = [("missing mode", {}), ("invalid mode", {"AX_NATIVE_OVERLAY": "all"}),
                 ("missing scopes", {"AX_NATIVE_OVERLAY": "both"})]
    for name in FIXTURE_ENV:
        env = FIXTURE_ENV | {"AX_NATIVE_OVERLAY": "both"}
        del env[name]
        negatives.append(("missing " + name, env))
    for port in ("any", "0", "65536", "0443", "443,", "443,,8080", "443,443", "80:90"):
        negatives.append(("invalid port " + port, FIXTURE_ENV | {
            "AX_NATIVE_OVERLAY": "both", "AX_INSPECT_PORTS": port}))
    for name, env in negatives:
        result = run("agent-guard-overlay.lua", env)
        assert result.returncode != 0, f"unsafe configuration accepted: {name}"
    if needs_plugin:
        result = run("protocol-ips.lua", {}, load_plugin=False)
        assert result.returncode != 0, "required ND plugin was silently omitted"
        negatives.append(("missing required native ND plugin", {}))
    files = [HERE / path for path in ("protocol-ips.lua", "agent-guard-overlay.lua", "protocol.states",
                                     "protocol-builtins.rules",
                                     "builtin-inventory.json", "protocol-validation.rules",
                                     "generate_inventory.py", "validate_profiles.py",
                                     "plugins/README.md", "plugins/build.py", "plugins/ax_nd_options.cc",
                                     "plugins/nd_validation.h", "plugins/nd_validation_test.cc",
                                     "plugins/ip_validation.h", "plugins/ip_validation_test.cc",
                                     "plugins/ip4_options.h", "plugins/ip4_options_test.cc",
                                     "plugins/ip6_options.h", "plugins/ip6_options_test.cc",
                                     "plugins/esp_validation.h", "plugins/esp_validation_test.cc",
                                     "plugins/routing_validation.h", "plugins/routing_validation_test.cc",
                                     "plugins/home_address.h", "plugins/home_address_test.cc",
                                     "plugins/tcp_options.h", "plugins/tcp_options_test.cc",
                                     "plugins/tcp_sack_state.h", "plugins/tcp_sack_state_test.cc",
                                     "plugins/tcp_sack_option.h", "plugins/tcp_sack_option.cc")] + [NATIVE]
    plugin_files = []
    if plugin_path is not None:
        plugin_files = [plugin_path] if plugin_path.is_file() else sorted(
            set(plugin_path.rglob("*.so")) | set(plugin_path.rglob("*.dylib")))
        assert plugin_files, "no native plugin library found at the supplied path"
    return {"snort_version": version, "source_commit": inventory["source_commit"],
            "scope": "Native configuration loading and effective rule states only; no traffic or live inline enforcement.",
            "profiles": results, "rejected_invalid_configurations": len(negatives),
            "plugin_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in plugin_files},
            "sha256": {path.relative_to(HERE.parent).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in files}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snort", type=Path, required=True)
    parser.add_argument("--plugin-path", type=Path, help="Explicit reviewed plugin library or directory; passed to native Snort")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    report = validate(args.snort.resolve(), args.plugin_path)
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "sha256"}, indent=2))


if __name__ == "__main__":
    main()
