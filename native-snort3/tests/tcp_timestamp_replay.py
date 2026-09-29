#!/usr/bin/env python3
"""File-only RFC 7323 negotiation, missing-option, PAWS and recovery checks."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import struct
import tempfile

import tcp_sack_replay as framing

tcp = framing.tcp
replay = framing.replay


def timestamp(value, echo):
    return tcp.padded(bytes([8, 10]) + struct.pack('!II', value & 0xffffffff, echo & 0xffffffff))


def conversation(version, agent, target, port, mask, clock, client, mode, variant):
    negotiated = mask == 3
    fragmented_handshake = variant.startswith(('syn-', 'synack-', 'bothsyn-'))
    syn_data = b'abcdefgh' if variant in ('fastopen', 'opening-data') or (version == 6 and fragmented_handshake) else b''
    fast_open = bytes([34, 6]) + b'cook' if syn_data and variant != 'opening-data' else b''
    next_client, next_server = 101 + len(syn_data), 701 + len(syn_data)
    # Both clocks have the same starting value, but their negotiation and
    # comparison histories remain directional. The wrap case crosses 2**32.
    offers = [tcp.padded((timestamp(clock, 0)[:10] if mask & 1 else b'') + fast_open),
              tcp.padded((timestamp(clock, clock)[:10] if mask & 2 else b'') + fast_open)]
    stages = [(agent, target, 45000, port, offers[0], 2, 100, 0, syn_data, False),
              (target, agent, port, 45000, offers[1], 18, 700, next_client, syn_data, False),
              (agent, target, 45000, port, timestamp(clock + 1, clock) if negotiated else b'',
               16, next_client, next_server, b'', False)]
    src, dst, sp, dp, seq, ack = ((agent, target, 45000, port, next_client, next_server) if client else
                                 (target, agent, port, 45000, next_server, next_client))
    # A valid pure ACK establishes a recent value before each subject. No
    # payload is admitted until the subject/recovery, so denial cannot be
    # confused with an ordinary retransmission already queued by the engine.
    stages.append((src, dst, sp, dp, timestamp(clock + 1, clock + 1) if negotiated else b'',
                   16, seq, ack, b'', False))
    body = b'0123456789abcdef'
    if mode in ('unnegotiated-chain', 'unnegotiated-zero'):
        stages.extend([(src, dst, sp, dp, timestamp(0 if mode.endswith('zero') else 1000, 2000), 16, seq, ack, b'', False),
                       (dst, src, dp, sp, timestamp(2000, 1000), 16, ack, seq, b'', False),
                       (src, dst, sp, dp, b'', 24, seq, ack, body, False)])
    else:
        options = b'' if mode in ('missing', 'recover-missing', 'rst-missing') else timestamp(
            clock if mode in ('old', 'recover-old', 'rst-old') else clock + (1 if mode == 'equal' else 2), clock + 1)
        if mode == 'valid' and not negotiated:
            options = b''
        denied = negotiated and mode in ('missing', 'old', 'recover-missing', 'recover-old')
        stages.append((src, dst, sp, dp, options, 20 if mode.startswith('rst-') else 24,
                       seq, ack, b'' if mode.startswith('rst-') else body, denied))
        if mode.startswith('recover-'):
            stages.append((src, dst, sp, dp, timestamp(clock + 2, clock + 1), 24, seq, ack, body, False))
    frames, denied_indices, incomplete_groups = [], [], []
    for index, (source, destination, sport, dport, options, flags, sequence, acknowledgement, data, denied) in enumerate(stages):
        fragment = ((index == 0 and variant.startswith(('syn-', 'bothsyn-'))) or
                    (index == 1 and variant.startswith(('synack-', 'bothsyn-'))) or
                    (index >= 4 and variant.startswith('subject-')))
        segment = tcp.tcp(source, destination, sport, dport, options, flags, sequence, acknowledgement, data)
        packets = framing.wire(source, destination, segment, version, fragment, variant.endswith('reverse'),
                               identifier=3000 + index, hbh=variant == 'hbh')
        first = len(frames)
        frames.extend(packets)
        if denied:
            if fragment:
                incomplete_groups.append(list(range(first, len(frames))))
            else:
                denied_indices.append(first)
    return {'frames': frames, 'denied_indices': denied_indices, 'incomplete_groups': incomplete_groups,
            'negotiated': negotiated}


def fixtures():
    for version, (agent, dns, broker, _) in replay.ADDRESSES.items():
        for target, port, role in ((dns, 53, 'dns'), (broker, 443, 'broker')):
            for mask in (0, 1, 3):
                for clock_name, clock in (('normal', 100), ('zero', 0), ('wrap', 0xfffffffe)):
                    for client in (False, True):
                        modes = ['valid', 'equal', 'missing', 'old', 'rst-missing', 'rst-old']
                        modes += ['recover-missing', 'recover-old'] if mask == 3 else ['unnegotiated-chain', 'unnegotiated-zero']
                        for mode in modes:
                            variants = ['plain']
                            if version == 6:
                                variants.append('hbh')
                            if mode in ('valid', 'missing', 'old', 'recover-missing', 'recover-old'):
                                variants += ['subject-forward', 'subject-reverse']
                            if mode in ('valid', 'missing', 'old'):
                                variants += ['fastopen', 'opening-data', 'syn-forward', 'syn-reverse', 'synack-forward', 'synack-reverse',
                                             'bothsyn-forward', 'bothsyn-reverse']
                            for variant in variants:
                                name = f'v{version}-{role}-mask{mask}-{clock_name}-{"client" if client else "server"}-{mode}-{variant}'
                                yield {'name': name, 'category': mode, **conversation(version, agent, target, port, mask, clock, client, mode, variant)}


def run(snort, plugin, config, directory, item):
    # Reuse the exact forwarding oracle from the admission-state audit: a
    # rejected datagram may leave an orphan fragment, never a complete pair.
    return framing.run(snort, plugin, config, directory, item)


def validate(snort, plugin, workers):
    assert __debug__
    snort, plugin = snort.resolve(strict=True), plugin.resolve(strict=True)
    items = list(fixtures())
    assert len({i['name'] for i in items}) == len(items)
    sources = [Path(__file__), Path(framing.__file__), Path(tcp.__file__), Path(replay.__file__),
               replay.NATIVE / 'protocol-ips.lua', replay.NATIVE / 'protocol-validation.rules',
               replay.NATIVE / 'plugins/tcp_sack_option.cc', replay.NATIVE / 'plugins/tcp_sack_state.h',
               replay.NATIVE / 'generate_dns_perimeter.py']
    hashes = {str(p.relative_to(replay.ROOT)): replay.digest(p.read_bytes()) for p in sources}
    with tempfile.TemporaryDirectory(prefix='ax-timestamp-replay-') as tmp:
        directory = Path(tmp)
        config = directory / 'dns.lua'
        config.write_text(replay.generator.render(replay.generator.load(replay.NATIVE / 'dns-perimeter.example.json'), False))
        config_hash = replay.digest(config.read_bytes())
        with ThreadPoolExecutor(max_workers=workers) as pool:
            cases = list(pool.map(lambda item: run(snort, plugin, config, directory, item), items))
    assert hashes == {str(p.relative_to(replay.ROOT)): replay.digest(p.read_bytes()) for p in sources}
    failures = [c['name'] for c in cases if not c['passed']]
    return {'scope': 'File-only inline DAQ verdicts and forwarded bytes. No live interface or deployed routing.',
            'source_sha256': hashes, 'config_sha256': config_hash,
            'snort_binary_sha256': replay.digest(snort.read_bytes()),
            'plugin_sha256': {p.name: replay.digest(p.read_bytes()) for p in sorted(plugin.glob('*.so'))},
            'summary': {'cases': len(cases), 'passed': len(cases) - len(failures), 'failures': failures,
                        'accepted_controls': sum(c['allowed'] for c in cases),
                        'categories': dict(Counter(c['category'] for c in cases))}, 'cases': cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snort', type=Path, required=True)
    parser.add_argument('--plugin-path', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--workers', type=int, choices=range(1, 9), default=4)
    args = parser.parse_args()
    report = validate(args.snort, args.plugin_path, args.workers)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v if k != 'failures' else len(v) for k, v in report['summary'].items()}))
    raise SystemExit(bool(report['summary']['failures']))


if __name__ == '__main__':
    main()
