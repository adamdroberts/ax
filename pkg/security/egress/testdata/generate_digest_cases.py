"""Independent Content-Digest fixtures: RFC 9530 bytes and RFC 8941 syntax."""
import argparse
import base64
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=Path(__file__).with_name('content_digest_cases.json'))
    output = parser.parse_args().output
    cases = []
    body = b'{"hello": "world"}\n'

    def digest(data, algorithm='sha-256'):
        value = hashlib.new(algorithm.replace('-', ''), data).digest()
        return algorithm + '=:' + base64.b64encode(value).decode() + ':'

    good, strong = digest(body), digest(body, 'sha-512')
    empty = digest(b'')
    assert good == 'sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:'
    assert empty == 'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:'

    def add(name, values=None, accepted=True, data=body, method='GET', status=200,
            extra=(), request=None, framing='fixed', stage='body', interim=False):
        headers = list(extra)
        headers.extend(('Content-Digest', value) for value in values or [])
        payload = data
        if framing == 'fixed':
            headers.append(('Content-Length', str(len(data))))
        elif framing == 'chunked':
            cut = max(1, len(data)//2)
            payload = b''.join(f'{len(p):X}; tag="ignored"\r\n'.encode()+p+b'\r\n' for p in (data[:cut], data[cut:]) if p) + b'0;done\r\n\r\n'
            headers.append(('Transfer-Encoding', 'chunked'))
        wire = f'HTTP/1.1 {status} Response\r\n'.encode()+b''.join(f'{k}: {v}\r\n'.encode() for k,v in headers)+b'\r\n'+payload
        if interim:
            wire = b'HTTP/1.1 103 Early Hints\r\n'+b''.join(f'Content-Digest: {v}\r\n'.encode() for v in values or [])+b'\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'
            data = b'ok'
        cases.append({'name':name, 'method':method, 'status':status, 'request_headers':request or {},
                      'headers':headers, 'body_base64':base64.b64encode(data).decode(),
                      'wire_base64':base64.b64encode(wire).decode(), 'accepted':accepted,
                      'rejection_stage':None if accepted else stage, 'interim':interim})

    for name, values in [('absent',None),('sha256',[good]),('sha512',[strong]),('both',[good+', '+strong]),
                         ('separate-fields',[good,strong]),('spaces',['  '+good+'  ,    '+strong+'  ']),
                         ('unpadded',[good[:-2]+':']),('unknown-alongside',[good+', private=:eA==:']),
                         ('weak-alongside',[good+', md5=:eA==:']),('empty-unknown-alongside',[good+', private=::'])]:
        add(name,values)
    # RFC 8941 receivers tolerate nonzero unused pad bits; decoded bytes match.
    add('nonzero-pad-bits',[good.replace('FabDg=','FabDh=')])
    parameters = ['flag','flag=?1','flag=?0','n=-999999999999999','n=0001','n=-0',
                  'n=999999999999.999','n=-0.001','text="comma,; equals=colon:"',
                  'text="escaped\\\"quote\\\\slash"','token=UPPER/a:b','token=*',
                  'binary=:eA==:','binary=::','flag;flag=?0','   flag;   n=1']
    for i, param in enumerate(parameters):add(f'parameter-{i}',[good+';'+param])
    parameter_limit=''.join(';p'+str(i) for i in range(256))
    add('parameter-limit',[good+parameter_limit])
    def member_fields(count):
        members=[good]+['a'+str(i)+'=::' for i in range(count-1)]
        return [', '.join(members[i:i+128]) for i in range(0,len(members),128)]
    add('member-limit',member_fields(1024))
    bad_values = {
        'empty':'', 'spaces-only':'  ', 'unknown-only':'private=:eA==:', 'weak-only':'md5=:eA==:',
        'duplicate':good+', '+good, 'duplicate-conflict':good+', '+digest(b'wrong'),
        'uppercase-key':good.replace('sha-256','SHA-256'), 'underscore-first':'_sha=::, '+good,
        'digit-first':'1sha=::, '+good, 'key-slash':'sha/256=::, '+good,
        'space-before-equals':good.replace('=:', ' =:',1), 'space-after-equals':good.replace('=:', '= :',1),
        'missing-equals':good.replace('=:', ':',1), 'quoted-value':'sha-256="abc"',
        'boolean-value':'sha-256=?1', 'integer-value':'sha-256=1', 'bare-key':'sha-256',
        'inner-list':'sha-256=(:eA==:)', 'token-value':'sha-256=abc',
        'missing-colon':good[:-1], 'base64url':good.replace('/','_'),
        'base64-space':good.replace('RK/','RK /'), 'base64-junk':good.replace('RK/','RK!'),
        'base64-short-quantum':'sha-256=:A:', 'base64-excess-padding':good[:-1]+'=:',
        'base64-middle-padding':good.replace('RK/','R=/'),
        'empty-known':'sha-256=::',
        'short-known':'sha-256=:'+base64.b64encode(b'x'*31).decode()+':',
        'long-known':'sha-256=:'+base64.b64encode(b'x'*33).decode()+':',
        'short-sha512':'sha-512=:'+base64.b64encode(b'x'*63).decode()+':',
        'leading-comma':','+good, 'trailing-comma':good+',', 'empty-member':good+',, '+strong,
        'no-comma':good+' '+strong, 'trailing-junk':good+'x',
        'uppercase-param':good+';X=1', 'empty-param':good+';', 'space-before-param':good+' ;x',
        'param-missing-value':good+';x=', 'param-invalid-escape':good+';x="\\n"',
        'param-unclosed-string':good+';x="', 'param-inner-list':good+';x=(1)',
        'param-boolean':good+';x=?2', 'param-positive-sign':good+';x=+1',
        'param-wide-integer':good+';x=1000000000000000', 'param-wide-decimal':good+';x=1000000000000.1',
        'param-four-decimals':good+';x=0.1234', 'param-no-decimals':good+';x=1.',
        'param-date-outside-8941':good+';x=@1', 'param-display-outside-8941':good+';x=%"a"',
        'parameter-over-limit':good+''.join(';p'+str(i) for i in range(257)),
    }
    for name,value in bad_values.items():add(name,[value],False,stage='headers')
    add('member-over-limit',member_fields(1025),False,stage='headers')
    add('duplicate-across-fields',[good,good],False,stage='headers')
    add('unknown-duplicate-across-fields',[good+', a=::','a=::'],False,stage='headers')
    for framing in ('fixed','chunked','close'):
        for algorithm in ('sha-256','sha-512'):
            add('framing-'+framing+'-'+algorithm,[digest(body,algorithm)],framing=framing)
            add('mismatch-'+framing+'-'+algorithm,[digest(b'wrong',algorithm)],False,framing=framing)
        add('one-of-two-mismatch-'+framing,[good+', '+digest(b'wrong','sha-512')],False,framing=framing)
        add('empty-'+framing,[empty],data=b'',framing=framing)
        partial=body[:7]
        add('partial-content-'+framing,[digest(partial)],data=partial,status=206,
            extra=[('Content-Range',f'bytes 0-6/{len(body)}')],request={'Range':'bytes=0-6'},framing=framing)
        add('partial-wrong-representation-'+framing,[good],False,data=partial,status=206,
            extra=[('Content-Range',f'bytes 0-6/{len(body)}')],request={'Range':'bytes=0-6'},framing=framing)
    for method,status in [('HEAD',200),('GET',204),('GET',205),('GET',304)]:
        request={'If-None-Match':'*'} if status==304 else None
        add(f'bodyless-{method}-{status}',[empty],data=b'',method=method,status=status,request=request,framing='close')
        add(f'bodyless-mismatch-{method}-{status}',[good],False,data=b'',method=method,status=status,request=request,framing='close',stage='headers')
    add('interim-empty',[empty],interim=True)
    add('interim-mismatch',[good],False,interim=True,stage='headers')
    add('interim-invalid',['sha-256=bad'],False,interim=True,stage='headers')
    add('connection-nomination',[good],False,extra=[('Connection','content-digest')],stage='headers')
    mime=b'--b\r\nContent-Range: bytes 0-1/2\r\nContent-Digest: MIME metadata is separate\r\n\r\nok\r\n--b--\r\n'
    add('multipart-envelope',[digest(mime)],data=mime,status=206,extra=[('Content-Type','multipart/byteranges; boundary=b')],request={'Range':'bytes=0-0,1-'})
    add('multipart-wrong-representation',[digest(b'ok')],False,data=mime,status=206,extra=[('Content-Type','multipart/byteranges; boundary=b')],request={'Range':'bytes=0-0,1-'})
    for name,data in [('unicode','é🌍'.encode()),('line-endings',b'a\r\nb\n'),('bom',b'\xef\xbb\xbftext')]:
        add('exact-octets-'+name,[digest(data)],data=data)
        add('altered-octets-'+name,[digest(data+b' ')],False,data=data)
    add('per-member-parameter-limits',[good+parameter_limit+', '+strong+parameter_limit])
    add('member-64-character-key',[good+', '+'a'*64+'=::'])
    add('parameter-64-character-key',[good+';'+'a'*64])
    assert len({case['name'] for case in cases}) == len(cases)
    output.write_text(json.dumps({'version':1,'cases':cases},indent=2)+'\n')
    print(json.dumps({'cases':len(cases),'accepted':sum(c['accepted'] for c in cases),'denied':sum(not c['accepted'] for c in cases)}))


if __name__=='__main__':main()
