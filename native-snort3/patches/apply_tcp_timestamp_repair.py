#!/usr/bin/env python3
"""Apply strict timestamp negotiation/PAWS repair to a verified source copy."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FILES = ('src/stream/tcp/tcp_normalizer.cc', 'src/stream/tcp/tcp_session.cc',
         'src/stream/tcp/tcp_stream_tracker.cc', 'src/stream/tcp/tcp_state_syn_recv.cc')
COMMIT = '14aeb09f5a0856812dbe08ead3c21f99e8860aa0'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError('unexpected source around: ' + before[:100])
    return source.replace(before, after, 1)


def patched(relative, original):
    source = original.decode()
    if relative == 'src/stream/tcp/tcp_state_syn_recv.cc':
        before = ('bool TcpStateSynRecv::syn_ack_sent(TcpSegmentDescriptor& tsd, TcpStreamTracker& trk)\n'
                  '{\n'
                  '    trk.finish_server_init(tsd);\n'
                  '    trk.normalizer.ecn_tracker(tsd.get_tcph());')
        return replace_once(source, before, before + '\n'
            '    // Account for the SYN-ACK acknowledgement of opening data.\n'
            '    // PAWS updates use this last-ACK boundary on later segments.\n'
            '    trk.update_tracker_ack_sent(tsd);').encode()
    if relative == 'src/stream/tcp/tcp_session.cc':
        return replace_once(source,
            '            check_flow_missed_3whs();',
            '            // Data on the opening SYN (for example TCP Fast Open)\n'
            '            // is not evidence of a missed handshake. Downgrading\n'
            '            // here would disable PAWS for the whole connection.\n'
            '            if ( !tsd.get_tcph()->is_syn_only() )\n'
            '                check_flow_missed_3whs();').encode()
    if relative == 'src/stream/tcp/tcp_stream_tracker.cc':
        source = replace_once(source,
            'void TcpStreamTracker::finish_client_init(const TcpSegmentDescriptor& tsd)\n'
            '{\n'
            '    Flow* flow = tsd.get_flow();\n'
            '    rcv_nxt = tsd.get_end_seq();',
            'void TcpStreamTracker::finish_client_init(const TcpSegmentDescriptor& tsd)\n'
            '{\n'
            '    Flow* flow = tsd.get_flow();\n'
            '    // SYN data is validated and queued after handshake state setup.\n'
            '    // Advancing over it here misclassifies that data as a duplicate.\n'
            '    rcv_nxt = tsd.get_tcph()->is_syn() ? tsd.get_seq() + 1 : tsd.get_end_seq();')
        return replace_once(source, '        r_win_base = tsd.get_end_seq();',
                            '        r_win_base = rcv_nxt;').encode()
    if relative != FILES[0]:
        raise ValueError('unexpected repair target: ' + relative)
    source = replace_once(source,
        '    // drop packet if sequence num is invalid',
        '    // The opening SYN precedes any advertised peer receive window.\n'
        '    // Configured SYN-payload trimming already runs before this path;\n'
        '    // queue permitted data without inventing a zero peer window.\n'
        '    if ( tsd.get_tcph()->is_syn_only() )\n'
        '        return NORM_OK;\n\n'
        '    // drop packet if sequence num is invalid')
    source = replace_once(source,
        '    if ( peer_ts_last && ( ( (int)( ( tsd.get_timestamp() - peer_ts_last ) + tns.paws_ts_fudge ) ) < 0 ) )',
        '    // RFC 7323 serial arithmetic: zero is a real clock value, and a\n'
        '    // one-tick backward step is still older. Do not apply OS tolerances.\n'
        '    if ( ( (tsd.get_timestamp() - peer_ts_last) & 0x80000000u ) != 0 )')
    source = replace_once(source,
        '        bool check_ts = is_paws_ts_checked_required(tns, tsd);\n\n'
        '        if ( check_ts )\n'
        '            return validate_paws_timestamp(tns, tsd);\n'
        '        else\n'
        '            return ACTION_NOTHING;',
        '        // Negotiation depends on option presence, not its clock value.\n'
        '        // Historical OS zero-value quirks must not revoke protection.\n'
        '        return validate_paws_timestamp(tns, tsd);')
    source = replace_once(source,
        'int TcpNormalizer::handle_paws_no_timestamps(\n'
        '    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)\n'
        '{\n'
        '    tns.tcp_ts_flags = get_tcp_timestamp(tns, tsd, true);',
        'int TcpNormalizer::handle_paws_no_timestamps(\n'
        '    TcpNormalizerState& tns, TcpSegmentDescriptor& tsd)\n'
        '{\n'
        '    // RFC 7323 section 3.2: an option outside a negotiated handshake\n'
        '    // is ignored. In particular it cannot enable late PAWS tracking,\n'
        '    // trigger zero-value rejection, or rewrite the packet options.\n'
        '    if ( !tsd.get_tcph()->is_syn() )\n'
        '    {\n'
        '        tns.tcp_ts_flags = TF_NONE;\n'
        '        tsd.set_timestamp(0);\n'
        '        return ACTION_NOTHING;\n'
        '    }\n\n'
        '    tns.tcp_ts_flags = get_tcp_timestamp(tns, tsd, true);')
    return source.encode()


def apply(previous_root, target):
    previous_root = previous_root.resolve(strict=True)
    source = previous_root / 'source'
    evidence = json.loads((HERE.parent / 'fragment-identity-build-validation.json').read_text())
    manifest = previous_root / 'repaired/source-hashes.json'
    if evidence['upstream_commit'] != COMMIT or digest(manifest) != evidence['builds']['repaired']['files']['source-hashes.json']:
        raise ValueError('previous build is not the recorded cumulative source')
    expected = json.loads(manifest.read_text())
    actual = {p.relative_to(source).as_posix(): digest(p) for p in sorted(source.rglob('*'))
              if p.is_file() and '.git' not in p.relative_to(source).parts}
    if actual != expected:
        raise ValueError('previous source differs from its recorded build')
    target = target.resolve()
    if target.exists() or target == source or source in target.parents or target in source.parents:
        raise ValueError('target must be a new separate source directory')
    originals = {name: (source / name).read_bytes() for name in FILES}
    updates = {name: patched(name, data) for name, data in originals.items()}
    patch = ''.join(''.join(difflib.unified_diff(originals[name].decode().splitlines(keepends=True),
        updates[name].decode().splitlines(keepends=True), fromfile='a/' + name, tofile='b/' + name)) for name in FILES)
    report = {'upstream_commit': COMMIT, 'scope': 'Separate source copy; build and packet validation required.',
              'previous_source_manifest_sha256': digest(manifest),
              'before_sha256': {name: hashlib.sha256(data).hexdigest() for name, data in originals.items()},
              'after_sha256': {name: hashlib.sha256(data).hexdigest() for name, data in updates.items()},
              'local_source_sha256': {str(Path(__file__).relative_to(ROOT)): digest(Path(__file__))},
              'patch_sha256': hashlib.sha256(patch.encode()).hexdigest()}
    shutil.copytree(source, target, ignore=shutil.ignore_patterns('.git'))
    for name, data in updates.items():
        (target / name).write_bytes(data)
    (target / 'ax-tcp-timestamp.patch').write_text(patch)
    (target / 'ax-tcp-timestamp-source-validation.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--previous-build-root', type=Path, required=True)
    parser.add_argument('--target-source', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(apply(args.previous_build_root, args.target_source), indent=2))


if __name__ == '__main__':
    main()
