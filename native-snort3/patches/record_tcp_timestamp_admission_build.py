#!/usr/bin/env python3
"""Verify cumulative timestamp admission builds and their exact source delta."""
import argparse
import hashlib
import json
from pathlib import Path

import apply_tcp_timestamp_admission_repair as repair

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(regular_root, asan_root, previous_root, previous_asan_root):
    assert __debug__
    source = regular_root / 'source'
    before = json.loads((previous_root / 'repaired/source-hashes.json').read_text())
    prior = json.loads((HERE.parent / 'tcp-timestamp-build-validation.json').read_text())
    assert digest(previous_root / 'repaired/source-hashes.json') == prior['source_manifest_sha256']
    assert digest(previous_root / 'repaired/snort') == prior['binary_sha256']['regular']
    current = {p.relative_to(source).as_posix(): digest(p) for p in sorted(source.rglob('*'))
               if p.is_file() and '.git' not in p.relative_to(source).parts}
    changes = {p: {'before': before.get(p), 'after': current.get(p)} for p in before.keys() | current.keys()
               if before.get(p) != current.get(p)}
    assert changes.keys() == {*(repair.PREFIX + p for p in repair.MODIFIED + repair.ADDED),
                              'ax-tcp-timestamp-admission.patch', 'ax-tcp-timestamp-admission-source-validation.json'}
    for name in repair.MODIFIED:
        assert repair.patched(name, (previous_root / 'source' / repair.PREFIX / name).read_bytes()) == (source / repair.PREFIX / name).read_bytes()
    for name in repair.ADDED:
        assert (HERE / name).read_bytes() == (source / repair.PREFIX / name).read_bytes()
    patch = json.loads((source / 'ax-tcp-timestamp-admission-source-validation.json').read_text())
    assert patch['patch_sha256'] == digest(source / 'ax-tcp-timestamp-admission.patch')
    for name, expected in patch['local_source_sha256'].items():
        assert digest(ROOT / name) == expected
    builds, configurations = {}, {}
    for label, root, old_root in [('regular', regular_root, previous_root), ('asan', asan_root, previous_asan_root)]:
        snapshot = root / 'repaired'
        build = json.loads((snapshot / 'build-manifest.json').read_text())
        assert build['returncode'] == build['version_returncode'] == 0
        assert build['source_unchanged_during_build']
        assert build['builder_sha256'] == digest(HERE / 'build_snapshot.py')
        for name, expected in build['files'].items():
            assert digest(snapshot / name) == expected
        assert json.loads((snapshot / 'source-hashes.json').read_text()) == current
        config = json.loads((root / 'configure-manifest.json').read_text())
        old = json.loads((old_root / 'configure-manifest.json').read_text())
        expected = [arg.replace(str(old_root), str(root)) for arg in old['command']]
        expected[expected.index('-S') + 1] = str(source)
        expected[expected.index('-B') + 1] = str(root / 'build')
        assert config['command'] == expected
        assert config['environment'] == old['environment'] and config['pkgconfig'] == old['pkgconfig']
        assert config['returncode'] == 0
        builds[label], configurations[label] = build, config
    (HERE / 'snort-tcp-timestamp-admission.patch').write_bytes((source / 'ax-tcp-timestamp-admission.patch').read_bytes())
    return {'scope': 'Local cumulative source builds; no installation, interface or deployment.',
            'upstream_commit': repair.COMMIT,
            'binary_sha256': {'baseline': digest(previous_root / 'repaired/snort'),
                              'regular': builds['regular']['binary_sha256'], 'asan': builds['asan']['binary_sha256']},
            'comparison': {'only_timestamp_admission_source_changes': True,
                           'configuration_matches_previous_except_paths': True,
                           'regular_and_asan_source_identical': True, 'source_changes': dict(sorted(changes.items()))},
            'source_repair': patch, 'builds': builds, 'configurations': configurations,
            'source_manifest_sha256': digest(regular_root / 'repaired/source-hashes.json'),
            'recorder_sha256': digest(Path(__file__))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-root', type=Path, required=True)
    parser.add_argument('--asan-build-root', type=Path, required=True)
    parser.add_argument('--previous-build-root', type=Path, required=True)
    parser.add_argument('--previous-asan-build-root', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    result = record(args.build_root.resolve(), args.asan_build_root.resolve(),
                    args.previous_build_root.resolve(), args.previous_asan_build_root.resolve())
    args.report.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['binary_sha256']))


if __name__ == '__main__':
    main()
