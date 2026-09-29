#!/usr/bin/env python3
"""Bind native TCP timestamp mutations to final packet admission."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
COMMIT = '14aeb09f5a0856812dbe08ead3c21f99e8860aa0'
PREFIX = 'src/stream/tcp/'
MODIFIED = ('CMakeLists.txt', 'stream_tcp.cc', 'tcp_session.cc',
            'tcp_stream_tracker.h', 'tcp_stream_tracker.cc')
ADDED = ('tcp_timestamp_admission.h', 'tcp_timestamp_admission.cc')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def once(source, before, after):
    if source.count(before) != 1:
        raise ValueError('unexpected source around: ' + before[:100])
    return source.replace(before, after, 1)


def patched(name, original):
    source = original.decode()
    if name == 'CMakeLists.txt':
        source = once(source, '    tcp_session.cc\n',
                      '    tcp_session.cc\n    tcp_timestamp_admission.cc\n    tcp_timestamp_admission.h\n')
    elif name == 'stream_tcp.cc':
        source = once(source, '#include "tcp_session.h"', '#include "tcp_session.h"\n#include "tcp_timestamp_admission.h"')
        source = once(source, '    sc->max_pdu = config->paf_max;',
                      '    tcp_timestamp_admission_configure(sc);\n    sc->max_pdu = config->paf_max;')
        source = once(source, '    TcpStateMachine::initialize();',
                      '    tcp_timestamp_admission_init();\n    TcpStateMachine::initialize();')
    elif name == 'tcp_session.cc':
        source = once(source, '#include "tcp_session.h"', '#include "tcp_session.h"\n#include "tcp_timestamp_admission.h"')
        source = once(source, '    TcpSegmentDescriptor tsd(flow, p, tel);\n    init_tcp_packet_analysis(tsd);',
                      '    TcpTimestampAdmission timestamp_admission(client, server, p);\n'
                      '    TcpSegmentDescriptor tsd(flow, p, tel);\n    init_tcp_packet_analysis(tsd);')
    elif name == 'tcp_stream_tracker.h':
        source = once(source, '#include "tcp_defs.h"', '#include "tcp_defs.h"\n#include "tcp_timestamp_admission.h"')
        source = once(source, '    { return ts_last_packet; }', '    { return timestamp_state->value.packet_time; }')
        source = once(source, '    { this->ts_last_packet = ts_last_packet; }',
                      '    { timestamp_state->value.packet_time = ts_last_packet; }')
        source = once(source, '    { return ts_last; }', '    { return timestamp_state->value.last; }')
        source = once(source, '    { this->ts_last = ts_last; }', '    { timestamp_state->value.last = ts_last; }')
        source = once(source, '    { return tf_flags; }', '    { return tf_flags | timestamp_state->value.flags; }')
        source = once(source, '    { this->tf_flags |= flags; }',
                      '    {\n        tf_flags |= flags & ~(TF_TSTAMP | TF_TSTAMP_ZERO);\n'
                      '        timestamp_state->value.flags |= flags & (TF_TSTAMP | TF_TSTAMP_ZERO);\n    }')
        source = once(source, '    { this->tf_flags &= ~flags; }',
                      '    {\n        tf_flags &= ~flags;\n        timestamp_state->value.flags &= ~flags;\n    }\n\n'
                      '    std::shared_ptr<TcpTimestampState> get_timestamp_state() const\n'
                      '    { return timestamp_state; }')
        source = once(source, '    uint32_t ts_last_packet = 0;\n    uint32_t ts_last = 0;       // last timestamp (for PAWS)',
                      '    std::shared_ptr<TcpTimestampState> timestamp_state = std::make_shared<TcpTimestampState>();')
    elif name == 'tcp_stream_tracker.cc':
        source = once(source, '    ts_last = ts_last_packet = 0;', '    timestamp_state->reset();')
        import re
        source = re.sub(r'\bts_last_packet\b', 'timestamp_state->value.packet_time', source)
        source = re.sub(r'\bts_last\b', 'timestamp_state->value.last', source)
        assert source.count('tf_flags |= normalizer.get_tcp_timestamp(tsd, false);') == 4
        source = source.replace('tf_flags |= normalizer.get_tcp_timestamp(tsd, false);',
                                'set_tf_flags(normalizer.get_tcp_timestamp(tsd, false));')
        assert source.count('tf_flags |= TF_TSTAMP_ZERO;') == 4
        source = source.replace('tf_flags |= TF_TSTAMP_ZERO;', 'set_tf_flags(TF_TSTAMP_ZERO);')
    else:
        raise ValueError(name)
    return source.encode()


def apply(previous_root, target):
    previous_root = previous_root.resolve(strict=True)
    source = previous_root / 'source'
    evidence = json.loads((HERE.parent / 'tcp-timestamp-build-validation.json').read_text())
    manifest = previous_root / 'repaired/source-hashes.json'
    if evidence['upstream_commit'] != COMMIT or digest(manifest) != evidence['source_manifest_sha256']:
        raise ValueError('previous build is not the recorded timestamp repair')
    before = json.loads(manifest.read_text())
    actual = {p.relative_to(source).as_posix(): digest(p) for p in sorted(source.rglob('*'))
              if p.is_file() and '.git' not in p.relative_to(source).parts}
    if actual != before:
        raise ValueError('previous source differs from its build manifest')
    target = target.resolve()
    if target.exists() or target == source or source in target.parents or target in source.parents:
        raise ValueError('target must be a new separate source directory')
    updates = {PREFIX + name: patched(name, (source / PREFIX / name).read_bytes()) for name in MODIFIED}
    updates.update({PREFIX + name: (HERE / name).read_bytes() for name in ADDED})
    patch = ''.join(''.join(difflib.unified_diff(
        (source / path).read_text().splitlines(keepends=True) if path in before else [],
        data.decode().splitlines(keepends=True), fromfile='a/' + path if path in before else '/dev/null',
        tofile='b/' + path)) for path, data in updates.items())
    local = [Path(__file__), *(HERE / name for name in ADDED)]
    report = {'upstream_commit': COMMIT, 'scope': 'Separate cumulative source copy; build and packet validation required.',
              'previous_source_manifest_sha256': digest(manifest),
              'before_sha256': {path: before.get(path) for path in updates},
              'after_sha256': {path: hashlib.sha256(data).hexdigest() for path, data in updates.items()},
              'local_source_sha256': {str(p.relative_to(ROOT)): digest(p) for p in local},
              'patch_sha256': hashlib.sha256(patch.encode()).hexdigest()}
    shutil.copytree(source, target, ignore=shutil.ignore_patterns('.git'))
    for path, data in updates.items():
        (target / path).write_bytes(data)
    (target / 'ax-tcp-timestamp-admission.patch').write_text(patch)
    (target / 'ax-tcp-timestamp-admission-source-validation.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--previous-build-root', type=Path, required=True)
    parser.add_argument('--target-source', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(apply(args.previous_build_root, args.target_source), indent=2))


if __name__ == '__main__':
    main()
