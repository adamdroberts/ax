#!/usr/bin/env python3
"""File-only TCP option geometry, padding and sender-context regression audit."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import struct
import tempfile

import dns_perimeter_replay as replay


def padded(options):
    return options + bytes(-len(options) % 4)


def tcp(source, destination, sport, dport, options=b"", flags=2, seq=100, ack=0, data=b""):
    assert len(options) <= 40 and len(options) % 4 == 0
    body = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, (5 + len(options)//4) << 4,
                       flags, 32768, 0, 0) + options + data
    checksum = replay.checksum(replay.pseudo(source, destination, 6, len(body)) + body)
    return body[:16] + struct.pack("!H", checksum) + body[18:]


def samples():
    for name, options in [
        ("none", b""), ("zero-pad", bytes(4)), ("nop", bytes([1])*4),
        ("max-nop", bytes([1])*40), ("unknown", bytes([200,4,0,255])),
        ("unknown-short", bytes([200,2,0,0])), ("unaligned-unknown", bytes([1,200,3,255])),
        ("mss", bytes([2,4,5,180])), ("unaligned-mss", padded(bytes([1,2,4,5,180]))),
        ("sack-permitted", bytes([4,2,1,1])), ("timestamp", padded(bytes([8,10])+bytes(8))),
        ("fast-open-request", bytes([34,2,1,1])),
    ]:
        yield name, options, True, False
    for scale in (0,14,15,255):
        yield "window-scale-"+str(scale), bytes([3,3,scale,0]), True, False
    for at in (1,2,3,39):
        data=bytearray(40 if at==39 else 4);data[at]=1
        yield "nonzero-pad-"+str(at), bytes(data), False, False
    yield "nonzero-pad-255", bytes([0,255,255,255]), False, False
    yield "nonzero-pad-after-nop", bytes([1,0,0,1]), False, False
    for length in (0,1,5,255):
        yield "unknown-length-"+str(length), bytes([200,length,0,0]), False, False
    yield "unknown-truncated", bytes([1,1,1,200]), False, False
    yield "mss-without-syn", bytes([2,4,5,180]), False, True
    yield "sack-permitted-without-syn", bytes([4,2,1,1]), False, True
    for length in range(2,41):
        blocks=(length-2)//8
        body=b"".join(struct.pack("!II",711+i*20,721+i*20) for i in range(blocks))
        option=bytes([5,length])+(body+bytes(length-2))[:length-2]
        yield "sack-length-"+str(length), padded(option), length in (10,18,26,34), True


def fixtures():
    fragment_names={"zero-pad","nonzero-pad-3","mss","mss-without-syn", "sack-permitted-without-syn", "sack-length-3","sack-length-10"}
    for version,(agent,dns,broker,_) in replay.ADDRESSES.items():
        for source,destination,sport,dport,role in ((agent,dns,45000,53,"out-dns"),
                (agent,broker,45000,443,"out-broker"), (dns,agent,53,45000,"in-dns"),
                (broker,agent,443,45000,"in-broker")):
            for name,options,allowed,established in samples():
                handshake=[]
                if established:
                    permitted=bytes([4,2,1,1])
                    handshake=[
                        replay.frame(source,destination,6,tcp(source,destination,sport,dport,permitted)),
                        replay.frame(destination,source,6,tcp(destination,source,dport,sport,permitted,18,700,101)),
                        replay.frame(source,destination,6,tcp(source,destination,sport,dport,b"",16,101,701)),
                    ]
                subject=tcp(source,destination,sport,dport,options,16 if established else 2,
                            101 if established else 100,701 if established else 0)
                base=f"v{version}-{role}-{name}"
                yield replay.case(base,handshake+[replay.frame(source,destination,6,subject)],allowed,
                                  kind="stream_deny" if established else "single",category=name)
                if version==6:
                    ext=bytes([6,0])+bytes(6)
                    yield replay.case(base+"-hbh",handshake+[replay.frame(source,destination,6,subject,extensions=ext,first=0)],allowed,
                                      kind="stream_deny" if established else "single",category=name)
                if role!="out-dns" or name not in fragment_names:
                    continue
                subject=tcp(source,destination,sport,dport,options,16 if established else 2,
                            101 if established else 100,701 if established else 0,b"a"*24)
                split=16 if version==4 else (20+len(options)+7)//8*8
                fragments=[replay.frame(source,destination,6,subject[:split],fragment=(0,True)),
                           replay.frame(source,destination,6,subject[split:],fragment=(split,False))]
                for order,packets in (("forward",fragments),("reverse",list(reversed(fragments)))):
                    yield replay.case(base+"-fragment-"+order,handshake+packets,allowed,kind="fragments",category=name)


def validate(snort,plugin,workers):
    assert __debug__, "audit requires assertions"
    snort,plugin=snort.resolve(strict=True),plugin.resolve(strict=True)
    items=list(fixtures())
    assert len({i['name'] for i in items})==len(items)
    sources=[Path(__file__),replay.HERE/'dns_perimeter_replay.py',replay.HERE/'next_header_policy.py',
             replay.NATIVE/'protocol-ips.lua',replay.NATIVE/'protocol-validation.rules',
             replay.NATIVE/'protocol-builtins.rules',replay.NATIVE/'protocol.states',
             replay.NATIVE/'generate_dns_perimeter.py',replay.NATIVE/'dns-perimeter.example.json',
             replay.NATIVE/'dns-perimeter.rules',replay.NATIVE/'plugins/ax_nd_options.cc']
    source_hashes={str(p.relative_to(replay.ROOT)):replay.digest(p.read_bytes()) for p in sources}
    with tempfile.TemporaryDirectory(prefix='ax-tcp-options-replay-') as tmp:
        directory=Path(tmp);config=directory/'dns.lua'
        config.write_text(replay.generator.render(replay.generator.load(replay.NATIVE/'dns-perimeter.example.json'),False))
        config_hash=replay.digest(config.read_bytes())
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results=list(pool.map(lambda item:replay.run_case(snort,plugin,config,directory,item,replay.profiles.environment(False)),items))
    assert source_hashes=={str(p.relative_to(replay.ROOT)):replay.digest(p.read_bytes()) for p in sources}
    failures=[i['name'] for i in results if not i['passed']]
    return {'scope':'Synthetic file-only inline DAQ verdicts and forwarded packet bytes; no live interface or deployment.',
            'snort_binary_sha256':replay.digest(snort.read_bytes()),
            'plugin_sha256':{p.name:replay.digest(p.read_bytes()) for p in sorted(plugin.glob('*.so'))},
            'source_sha256':source_hashes,'config_sha256':config_hash,
            'summary':{'cases':len(results),'passed':len(results)-len(failures),'failures':failures,
                       'accepted_controls':sum(i['allowed'] for i in items),'denied_cases':sum(not i['allowed'] for i in items),
                       'new_rule_observed':sum(any(e['rule']=='1:9201017:1' for e in i.get('events',[])) for i in results)},
            'cases':results}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snort',type=Path,required=True)
    parser.add_argument('--plugin-path',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--workers',type=int,choices=range(1,9),default=4)
    args=parser.parse_args()
    report=validate(args.snort,args.plugin_path,args.workers)
    args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report['summary']))
    raise SystemExit(bool(report['summary']['failures']))


if __name__=='__main__':
    main()
