#!/usr/bin/env python3
"""File-only rejection/admission tests for TCP timestamp state changes."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile

import tcp_timestamp_replay as timestamps

replay, tcp, framing = timestamps.replay, timestamps.tcp, timestamps.framing


def fixtures():
    for version, (agent, dns, broker, _) in replay.ADDRESSES.items():
        for target, port, role in ((dns, 53, 'dns'), (broker, 443, 'broker')):
            for client in (False, True):
                for clock_name, clock in (('normal', 100), ('zero', 0), ('wrap', 0xfffffffe)):
                    for opening in ('plain', 'fastopen', 'opening-data'):
                        start = timestamps.conversation(version, agent, target, port, 3, clock, client, 'valid', opening)
                        offset = 0 if opening == 'plain' else 8
                        src, dst, sp, dp, seq, ack = ((agent, target, 45000, port, 101 + offset, 701 + offset) if client
                            else (target, agent, port, 45000, 701 + offset, 101 + offset))
                        variants = ['plain', 'forward', 'reverse'] + (['hbh'] if version == 6 else [])
                        for variant in variants:
                            for mode in ('reject-advance', 'accept-advance', 'reject-same', 'accept-same',
                                         'reject-old', 'reject-missing'):
                                rejected = mode.startswith('reject-')
                                advance = mode.endswith('advance')
                                value = clock + (1000 if advance else 0 if mode.endswith('old') else 1)
                                option = b'' if mode.endswith('missing') else timestamps.timestamp(value, clock + 1)
                                fragmented = variant in ('forward', 'reverse')
                                payload = b'abcdefgh' if fragmented else b''
                                segment = tcp.tcp(src, dst, sp, dp, option, 16, seq, ack, payload)
                                packets = framing.wire(src, dst, segment, version, fragmented, variant == 'reverse',
                                                       identifier=5000, hop=13 if rejected else 64, hbh=variant == 'hbh')
                                # Continue past candidate data. If that packet was
                                # denied, this is a legal out-of-order segment.
                                # Reusing its sequence span would also exercise
                                # native retransmission/overlap normalization.
                                subject_seq = seq + len(payload)
                                subject = tcp.tcp(src, dst, sp, dp, timestamps.timestamp(clock + 2, clock + 1),
                                                  24, subject_seq, ack, b'0123456789abcdef')
                                frames = list(start['frames'][:4]) + packets
                                frames += framing.wire(src, dst, subject, version, identifier=3004)
                                denied = [4] if rejected and not fragmented else []
                                groups = [list(range(4, 4 + len(packets)))] if rejected and fragmented else []
                                expected = []
                                if mode in ('reject-advance', 'reject-same'):
                                    expected.append('1:9202999:1')
                                elif mode == 'reject-old':
                                    expected.append('129:4:1')
                                elif mode == 'reject-missing':
                                    expected.append('129:14:1')
                                if mode == 'accept-advance':
                                    denied.append(len(frames) - 1)
                                    expected.append('129:4:1')
                                    # A later valid timestamp must recover without reconnecting.
                                    recovery = tcp.tcp(src, dst, sp, dp, timestamps.timestamp(clock + 1001, clock + 1),
                                                       24, subject_seq, ack, b'0123456789abcdef')
                                    frames += framing.wire(src, dst, recovery, version, identifier=5001)
                                yield {'name': f'v{version}-{role}-{"client" if client else "server"}-{clock_name}-{opening}-{variant}-{mode}',
                                       'category': mode, 'frames': frames, 'denied_indices': denied,
                                       'incomplete_groups': groups, 'required_events': expected}


def run(snort, plugin, config, directory, item):
    result = framing.run(snort, plugin, config, directory, item)
    result['required_events_observed'] = all(
        any(e['rule'] == rule and e['action'] == 'drop' for e in result.get('events', []))
        for rule in item['required_events'])
    result['passed'] = result['passed'] and result['required_events_observed']
    return result


def validate(snort, plugin, workers):
    assert __debug__
    snort, plugin = snort.resolve(strict=True), plugin.resolve(strict=True)
    items = list(fixtures())
    assert len({item['name'] for item in items}) == len(items)
    sources = [Path(__file__), Path(timestamps.__file__), Path(framing.__file__), Path(tcp.__file__), Path(replay.__file__),
               replay.NATIVE / 'protocol-ips.lua', replay.NATIVE / 'protocol-validation.rules',
               replay.NATIVE / 'generate_dns_perimeter.py']
    hashes = {str(p.relative_to(replay.ROOT)): replay.digest(p.read_bytes()) for p in sources}
    binary_hash = replay.digest(snort.read_bytes())
    libraries = {p.name: replay.digest(p.read_bytes()) for p in sorted(plugin.glob('*.so'))}
    with tempfile.TemporaryDirectory(prefix='ax-timestamp-admission-') as temporary:
        directory = Path(temporary)
        config = directory / 'dns.lua'
        config.write_text(replay.generator.render(replay.generator.load(replay.NATIVE / 'dns-perimeter.example.json'), False)
                          + '\nips.rules = ips.rules .. [[\ndrop tcp any any -> any any (msg:"AX test rejected timestamp update"; ttl:13; sid:9202999; rev:1;)\n]]\n'
                          + 'ips.states = ips.states .. "\\ndrop ( gid:1; sid:9202999; enable:yes; )"\n')
        config_hash = replay.digest(config.read_bytes())
        with ThreadPoolExecutor(max_workers=workers) as pool:
            cases = list(pool.map(lambda item: run(snort, plugin, config, directory, item), items))
    assert hashes == {str(p.relative_to(replay.ROOT)): replay.digest(p.read_bytes()) for p in sources}
    assert binary_hash == replay.digest(snort.read_bytes())
    assert libraries == {p.name: replay.digest(p.read_bytes()) for p in sorted(plugin.glob('*.so'))}
    failures = [case['name'] for case in cases if not case['passed']]
    return {'scope': 'Local file-only inline DAQ replay. SID 9202999 is a synthetic rejection control, not a production signature.',
            'source_sha256': hashes, 'config_sha256': config_hash, 'snort_binary_sha256': binary_hash,
            'plugin_sha256': libraries, 'summary': {'cases': len(cases), 'passed': len(cases) - len(failures),
            'failures': failures, 'categories': dict(Counter(case['category'] for case in cases))}, 'cases': cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snort', type=Path, required=True)
    parser.add_argument('--plugin-path', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--workers', type=int, choices=range(1, 9), default=4)
    args = parser.parse_args()
    report = validate(args.snort, args.plugin_path, args.workers)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: len(v) if k == 'failures' else v for k, v in report['summary'].items()}))
    raise SystemExit(bool(report['summary']['failures']))


if __name__ == '__main__':
    main()
