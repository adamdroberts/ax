#!/usr/bin/env python3
"""Generate deterministic, synthetic packet fixtures; never opens a socket."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import struct


def checksum(data):
    if len(data) & 1:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data)//2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def ip4(payload, protocol=17, first=0x45, total=None, ttl=64):
    src, dst = ipaddress.ip_address('192.0.2.10').packed, ipaddress.ip_address('198.51.100.20').packed
    header = struct.pack('!BBHHHBBH4s4s', first, 0, total if total is not None else 20+len(payload), 1234, 0, ttl, protocol, 0, src, dst)
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    return header + payload


def ip6(payload, protocol=17, source='2001:db8::1', length=None, hop_limit=64,
        destination='2001:db8::2'):
    src, dst = ipaddress.ip_address(source).packed, ipaddress.ip_address(destination).packed
    return struct.pack('!IHBB16s16s', 6 << 28, len(payload) if length is None else length, protocol, hop_limit, src, dst) + payload


def udp(payload=b'hello', length=None, ipv6=False, source='2001:db8::1', zero=False):
    body = struct.pack('!HHHH', 50000, 9999, len(payload)+8 if length is None else length, 0) + payload
    if ipv6 and not zero:
        pseudo = ipaddress.ip_address(source).packed + ipaddress.ip_address('2001:db8::2').packed + struct.pack('!I3xB',len(body),17)
        value = checksum(pseudo+body) or 0xffff
        body = body[:6] + struct.pack('!H',value) + body[8:]
    return body


def tcp(offset=5, flags=2):
    body = struct.pack('!HHIIBBHHH',50000,80,100,0,offset<<4,flags,65535,0,0)
    pseudo=ipaddress.ip_address('192.0.2.10').packed+ipaddress.ip_address('198.51.100.20').packed+struct.pack('!BBH',0,6,len(body))
    return body[:16]+struct.pack('!H',checksum(pseudo+body))+body[18:]


def icmp4():
    body=struct.pack('!BBHHH',8,0,0,1,1)+b'hello'
    return body[:2]+struct.pack('!H',checksum(body))+body[4:]


def nd_message(kind=135, code=0, short=False, option_bytes=0,
               source='fe80::1', destination='fe80::2', target='fe80::2',
               options=None, na_flags=0x60000000, redirect_target='fe80::3',
               redirect_destination='2001:db8::2'):
    """RFC 4861 minimum-size ND messages with a valid ICMPv6 checksum."""
    target = ipaddress.ip_address(target).packed
    bodies = {
        133: struct.pack('!I', 0),
        134: struct.pack('!BBHII', 64, 0, 1800, 0, 0),
        135: struct.pack('!I', 0) + target,
        136: struct.pack('!I', na_flags) + target,
        137: struct.pack('!I', 0) + ipaddress.ip_address(redirect_target).packed
             + ipaddress.ip_address(redirect_destination).packed,
    }
    if option_bytes % 8:
        raise ValueError('ND options must use eight-byte units')
    # Unknown nonzero-length options must be ignored by receivers (RFC 4861).
    if options is None:
        options = bytes.fromhex('fd01000000000000') * (option_bytes // 8)
    body = struct.pack('!BBH', kind, code, 0) + bodies[kind] + options
    if short:
        body = body[:-1]
    pseudo = (ipaddress.ip_address(source).packed
              + ipaddress.ip_address(destination).packed
              + struct.pack('!I3xB', len(body), 58))
    return body[:2] + struct.pack('!H', checksum(pseudo + body)) + body[4:]


def nd_packet(kind=135, code=0, hop_limit=255, short=False,
              source='fe80::1', destination='fe80::2', **message_options):
    message = nd_message(kind, code, short, source=source, destination=destination,
                         **message_options)
    return packet(ip6(message, 58, source=source, destination=destination,
                      hop_limit=hop_limit), 6)


def fragmented_nd(atomic=False, kind=135, option_bytes=0):
    body = nd_message(kind=kind, option_bytes=option_bytes)
    fragments = [(0, body)] if atomic else [(1, body[:8]), (8, body[8:])]
    return [packet(ip6(struct.pack('!BBHI', 58, 0, field, 0x12345678) + part,
                       44, source='fe80::1', destination='fe80::2', hop_limit=255), 6)
            for field, part in fragments]


def packet(payload, version=4):
    return bytes.fromhex('020000000002020000000001')+struct.pack('!H',0x86dd if version==6 else 0x0800)+payload


def cases():
    yield 'valid-ipv4-udp-zero-checksum',packet(ip4(udp())),None
    yield 'valid-ipv4-udp-large',packet(ip4(udp(b'a'*5000))),None
    yield 'valid-ipv4-tcp-syn',packet(ip4(tcp(),6)),None
    yield 'valid-ipv4-icmp-echo',packet(ip4(icmp4(),1)),None
    yield 'valid-ipv6-udp',packet(ip6(udp(ipv6=True)),6),None
    for kind in range(133, 138):
        yield f'valid-ipv6-nd-{kind}', nd_packet(kind), None
    yield 'ipv4-wrong-version',packet(ip4(udp(),first=0x65)),[116,1]
    yield 'ipv4-short-ihl',packet(ip4(udp(),first=0x44)),[116,2]
    yield 'ipv4-total-below-header',packet(ip4(udp(),total=10)),[116,3]
    yield 'ipv4-declared-length-truncated',packet(ip4(udp(),total=200)),[116,6]
    yield 'tcp-header-truncated',packet(ip4(b'\x00'*10,6)),[116,45]
    yield 'tcp-offset-below-minimum',packet(ip4(tcp(offset=4),6)),[116,46]
    yield 'tcp-offset-exceeds-packet',packet(ip4(tcp(offset=6),6)),[116,47]
    yield 'tcp-syn-fin',packet(ip4(tcp(flags=3),6)),[116,420]
    yield 'udp-header-truncated',packet(ip4(b'\x00'*4)),[116,95]
    yield 'udp-length-below-header',packet(ip4(udp(length=4))),[116,96]
    yield 'icmpv4-header-truncated',packet(ip4(b'\x08\x00\x00',1)),[116,426]
    yield 'ipv6-declared-length-truncated',packet(ip6(udp(ipv6=True),length=200),6),[116,275]
    yield 'ipv6-multicast-source',packet(ip6(udp(ipv6=True,source='ff02::1'),source='ff02::1'),6),[116,277]
    yield 'ipv6-udp-zero-checksum',packet(ip6(udp(ipv6=True,zero=True)),6),[116,406]
    for kind in range(133, 138):
        code_rule = [116, 287 if kind == 133 else 288] if kind in (133, 134) else [1, 9201001]
        yield f'ipv6-nd-{kind}-invalid-code', nd_packet(kind, code=1), code_rule
        yield f'ipv6-nd-{kind}-invalid-hop-limit', nd_packet(kind, hop_limit=254), [1, 9201002]
        yield f'ipv6-nd-{kind}-truncated', nd_packet(kind, short=True), [116, 105]
    yield 'ipv6-nd-reassembled-fragments', fragmented_nd(), [1, 9201003]
    for kind in range(133, 138):
        for padding in (0, 256, 4096):
            yield (f'ipv6-nd-{kind}-atomic-fragment-{padding}',
                   fragmented_nd(atomic=True, kind=kind, option_bytes=padding), [116, 458])
    # This is legal IPv6 traffic, rejected by the profile's stricter local policy.
    fragment = struct.pack('!BBHI', 17, 0, 0, 0x12345678) + udp(ipv6=True)
    yield 'policy-reject-valid-ipv6-atomic-udp', packet(ip6(fragment, 44), 6), [116, 458]
    for kind, sid in ((134, 9201004), (137, 9201005)):
        yield f'ipv6-nd-{kind}-global-source', nd_packet(kind, source='2001:db8::1'), [1, sid]
    # Regression: the default three-event log quota consumed only advisory
    # decoder events and suppressed the subsequent blocking code rule.
    extensions = (bytes.fromhex('3c001e0400000000')
                  + bytes.fromhex('2b00000000000000')
                  # Unknown routing type with zero segments must be ignored.
                  # Type2/segments0 is only an internal post-routing form,
                  # not a valid original-wire control (RFC6275 11.3.3).
                  + bytes.fromhex('3a02fd0000000000')
                  + ipaddress.ip_address('fe80::1').packed)
    for code in (0, 1):
        message = nd_message(code=code, source='fe80::1', destination='fe80::1')
        frame = packet(ip6(extensions + message, 0, source='fe80::1',
                           destination='fe80::1', hop_limit=255), 6)
        name = 'ipv6-advisories-before-block' if code else 'valid-ipv6-multiple-advisories'
        yield name, frame, [1, 9201001] if code else None
    # IPv6 extension-option lengths are octets, unlike ND's eight-octet
    # units. Zero-data unknown options here are valid and test event pressure.
    for count, code in ((8, 0), (8, 1), (9, 0)):
        extensions = b''.join(bytes([58 if index == count - 1 else 60, 255])
                              + b'\x1e\x00' * 1023 for index in range(count))
        frame = packet(ip6(extensions + nd_message(code=code), 60,
                           source='fe80::1', destination='fe80::2', hop_limit=255), 6)
        expected = [116, 456] if count == 9 else [1, 9201001] if code else None
        name = ('policy-reject-ipv6-extension-budget-exceeded' if count == 9 else
                'ipv6-many-options-invalid-nd-code' if code else 'valid-ipv6-many-extension-options')
        yield name, frame, expected


def plugin_cases():
    unknown = bytes.fromhex('fd01000000000000')
    source_link_layer = bytes.fromhex('0101020000000001')
    for kind in range(133, 138):
        for name, options in (
                ('unknown-zero-length', b'\xfd\0'),
                ('reserved-zero-length', b'\0\0'),
                ('unknown-then-zero-length', unknown + b'\x01\0'),
                ('option-overrun', b'\x01\x02' + b'\0' * 6),
                ('trailing-option-byte', unknown + b'\x01')):
            yield f'ipv6-nd-{kind}-{name}', nd_packet(kind, options=options), [1, 9201006]
        yield (f'valid-ipv6-nd-{kind}-unknown-options',
               nd_packet(kind, options=unknown + source_link_layer), None)
    for kind in (135, 136):
        yield (f'ipv6-nd-{kind}-multicast-target',
               nd_packet(kind, target='ff02::1'), [1, 9201007])
    yield ('ipv6-na-multicast-destination-solicited',
           nd_packet(136, destination='ff02::1'), [1, 9201007])
    yield ('valid-ipv6-na-multicast-unsolicited',
           nd_packet(136, destination='ff02::1', na_flags=0x20000000), None)
    yield ('ipv6-rs-unspecified-source-with-link-layer',
           nd_packet(133, source='::', destination='ff02::2', options=source_link_layer), [1, 9201007])
    yield ('valid-ipv6-rs-unspecified-source',
           nd_packet(133, source='::', destination='ff02::2'), None)
    yield ('ipv6-ns-unspecified-source-with-link-layer',
           nd_packet(135, source='::', destination='ff02::1:ff00:2', options=source_link_layer), [1, 9201007])
    yield ('valid-ipv6-ns-unspecified-source',
           nd_packet(135, source='::', destination='ff02::1:ff00:2'), None)
    yield ('ipv6-ns-unspecified-source-unicast-destination',
           nd_packet(135, source='::'), [1, 9201007])
    yield ('ipv6-ns-unspecified-source-wrong-multicast-destination',
           nd_packet(135, source='::', destination='ff02::1'), [1, 9201007])
    yield ('ipv6-redirect-multicast-inner-destination',
           nd_packet(137, redirect_destination='ff02::1'), [1, 9201007])
    yield ('ipv6-redirect-invalid-target',
           nd_packet(137, redirect_target='2001:db8::3'), [1, 9201007])
    yield ('valid-ipv6-redirect-target-is-destination',
           nd_packet(137, redirect_target='2001:db8::2'), None)


def extension_cases():
    # Hop-by-Hop alone must remain valid; generic extension-order advisories
    # cannot distinguish its mandatory position from other legal orders.
    for tail in ('nd', 'udp', 'none'):
        protocol = {'nd': 58, 'udp': 17, 'none': 59}[tail]
        src, dst = ('fe80::1', 'fe80::2') if tail == 'nd' else ('2001:db8::1', '2001:db8::2')
        payload = nd_message() if tail == 'nd' else udp(ipv6=True) if tail == 'udp' else b''
        for label, kinds in [('valid', [0]), ('misplaced', [60, 0]), ('repeated', [0, 0])]:
            headers = b''.join(bytes([kinds[i + 1] if i + 1 < len(kinds) else protocol, 0])
                               + b'\0' * 6 for i in range(len(kinds)))
            name = f'valid-ipv6-hop-first-{tail}' if label == 'valid' else f'ipv6-hop-{label}-{tail}'
            yield name, packet(ip6(headers + payload, kinds[0], source=src,
                                   destination=dst, hop_limit=255), 6), None if label == 'valid' else [1, 9201008]

    # These are AH shape controls only: no SA or ICV authentication is claimed.
    # Exercise AH both behind Destination Options and directly after IPv6.
    # The pinned decoder's advisory 116:281 must not mask these shape checks.
    for version in (4, 6):
        for size in (8, 12, 16, 20, 24):
            header = (bytes([58 if version == 6 else 1, size // 4 - 2])
                      + struct.pack('!HI', 0, 256)
                      + (struct.pack('!I', 1) + b'\0' * size)[:size - 8])
            malformed = size < 12 or (version == 6 and size % 8 != 0)
            name = f'ipv{version}-ah-length-{size}' if malformed else f'valid-ipv{version}-ah-shape-{size}'
            payload = (packet(ip6(bytes([51, 0]) + b'\0' * 6 + header + nd_message(), 60,
                                  source='fe80::1', destination='fe80::2', hop_limit=255), 6)
                       if version == 6 else packet(ip4(header + icmp4(), 51)))
            yield name, payload, [1, 9201009] if malformed else None
            if version == 6:
                name = f'ipv6-direct-ah-length-{size}' if malformed else f'valid-ipv6-direct-ah-shape-{size}'
                yield (name, packet(ip6(header + nd_message(), 51, source='fe80::1',
                                       destination='fe80::2', hop_limit=255), 6),
                       [1, 9201009] if malformed else None)
    yield ('policy-reject-ipv6-unadmitted-base-next-header',
           packet(ip6(b'\x41' * 64, 253), 6), [1, 9201011])


def first_fragment_cases():
    def chain(kinds, tail):
        result = b''
        for i, kind in enumerate(kinds):
            following = kinds[i + 1] if i + 1 < len(kinds) else tail
            result += (bytes([following, 2]) + struct.pack('!HII', 0, 256, 1) + b'\0' * 4
                       if kind == 51 else bytes([following, 0]) + b'\0' * 6)
        return result

    def fragments(pre, post, split, reverse=False, upper=17):
        body = chain(post, upper) + udp(b'a' * 64, ipv6=True)
        frames = []
        for field, part in ((1, body[:split]), (split, body[split:])):
            fragment = struct.pack('!BBHI', post[0] if post else upper, 0, field, 0xabcdef02) + part
            frames.append(packet(ip6(chain(pre, 44) + fragment, pre[0] if pre else 44), 6))
        return frames[::-1] if reverse else frames

    for post in ([], [60], [60, 60], [60, 51]):
        for split in (8, 16, 24, 32):
            complete = split >= len(chain(post, 17)) + 8
            label = '-'.join(map(str, post)) or 'none'
            name = ('valid-' if complete else '') + f'ipv6-first-fragment-{label}-split-{split}'
            yield name, fragments([], post, split), None if complete else [1, 9201010]
    for reverse in (False, True):
        label = 'reverse' if reverse else 'forward'
        yield (f'ipv6-fragment-before-hop-{label}', fragments([], [0], 32, reverse), [1, 9201008])
        yield (f'valid-ipv6-hop-before-fragment-{label}', fragments([0], [], 32, reverse), None)
    yield ('policy-reject-ipv6-first-fragment-unknown-upper',
           fragments([], [], 8, upper=253), [1, 9201010])
    # Ethernet padding cannot complete a header missing from the IP-bounded
    # first fragment, and unrelated padding must not invalidate a complete one.
    yield ('ipv6-first-fragment-padding-cannot-complete-header',
           [frame + b'\0' * 64 for frame in fragments([], [60], 8)], [1, 9201010])
    yield ('valid-ipv6-first-fragment-with-link-padding',
           [frame + b'\xff' * 64 for frame in fragments([], [60], 16)], None)
    yield ('ipv6-incomplete-first-fragment-arrives-last',
           fragments([], [60, 51], 16, reverse=True), [1, 9201010])
    different_next = fragments([], [], 8)
    # Only the original offset-zero fragment supplies the reconstructed Next
    # Header; a noninitial fragment must not be parsed as a fresh header chain.
    last = bytearray(different_next[-1])
    last[14 + 40] = 0
    different_next[-1] = bytes(last)
    yield 'valid-ipv6-noninitial-fragment-different-next-header', different_next, None


def generate(output, include_plugin=True):
    output.mkdir(parents=True,exist_ok=True)
    manifest=[]
    selected = list(cases()) + (list(plugin_cases()) + list(extension_cases())
                              + list(first_fragment_cases()) if include_plugin else [])
    for name,data,expected in selected:
        packets = data if isinstance(data, list) else [data]
        capture = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        for index, frame in enumerate(packets):
            capture += struct.pack('<IIII', 1700000000, index * 1000, len(frame), len(frame)) + frame
        path=output/(name+'.pcap')
        path.write_bytes(capture)
        category = 'policy_rejection' if name.startswith('policy-reject-') else 'valid' if expected is None else 'malformed'
        manifest.append({'name':name,'file':path.name,'sha256':hashlib.sha256(capture).hexdigest(), 'category': category,
                         'packets':len(packets),'expected_drop_rule':expected})
    (output/'manifest.json').write_text(json.dumps({'version':1,'cases':manifest},indent=2)+'\n')
    return manifest


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    parser.add_argument('--without-plugin', action='store_true')
    args=parser.parse_args()
    print(json.dumps({'cases':len(generate(args.output, not args.without_plugin)),'output':str(args.output)},indent=2))
