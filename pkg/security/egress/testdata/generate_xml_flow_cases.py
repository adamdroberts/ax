"""HTTP selection/framing fixtures for XML; independent of production parsers."""
import argparse
import base64
import json
from pathlib import Path


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=Path(__file__).with_name('xml_response_flow_cases.json'))
    output=parser.parse_args().output
    cases=[]
    def add(name,body,accepted,media='application/xml',status=200,method='GET',extra=(),request=None,framings=('fixed','chunked','close')):
        for framing in framings:
            fields=list(extra)
            if media is not None: fields.append(('Content-Type',media))
            payload=body
            if framing=='fixed': fields.append(('Content-Length',str(len(body))))
            elif framing=='chunked':
                cut=max(1,len(body)//2)
                payload=b''.join(f'{len(p):x}\r\n'.encode()+p+b'\r\n' for p in (body[:cut],body[cut:]) if p)+b'0\r\n\r\n'
                fields.append(('Transfer-Encoding','chunked'))
            wire=f'HTTP/1.1 {status} Response\r\n'.encode()+b''.join(f'{k}: {v}\r\n'.encode() for k,v in fields)+b'\r\n'+payload
            cases.append({'name':name+'-'+framing,'method':method,'request_headers':request or {},'accepted':accepted,'wire_base64':base64.b64encode(wire).decode(),'body_base64':base64.b64encode(body).decode()})
    good,bad=b'<r>ok</r>',b'<r>&undefined;</r>'
    for i,media in enumerate(['application/xml','text/xml','IMAGE/SVG+XML; charset="UTF-8"','application/xhtml+xml','model/example+xml']):
        add(f'media-{i}-good',good,True,media)
        add(f'media-{i}-bad',bad,False,media)
    for i,media in enumerate(['text/plain',None,'text/plain; note="application/xml"','application/xml-seq']):
        add(f'opaque-media-{i}',bad,True,media)
    for status in (201,302,400,500): add(f'status-{status}',bad,False,status=status)
    for method,status in [('HEAD',200),('GET',204),('GET',205),('GET',304)]:
        request={'If-None-Match':'*'} if status==304 else None
        add(f'bodyless-{method}-{status}',b'',True,status=status,method=method,request=request,framings=('close',))
    for framing in ('fixed','chunked','close'):
        add('complete-single',bad,False,status=206,extra=[('Content-Range',f'bytes 0-{len(bad)-1}/{len(bad)}')],request={'Range':'bytes=0-'},framings=(framing,))
        add('incomplete-single',bad,True,status=206,extra=[('Content-Range',f'bytes 0-{len(bad)-1}/{len(bad)+10}')],request={'Range':'bytes=0-'},framings=(framing,))
        add('unknown-single',bad,True,status=206,extra=[('Content-Range',f'bytes 0-{len(bad)-1}/*')],request={'Range':'bytes=0-'},framings=(framing,))
    def multipart(name,parts,accepted):
        body=b''
        for first,data,total,kind in parts:
            body+=f'--selection\r\nContent-Range: bytes {first}-{first+len(data)-1}/{total}\r\n'.encode()
            if kind is not None: body+=f'Content-Type: {kind}\r\n'.encode()
            body+=b'\r\n'+data+b'\r\n'
        body+=b'--selection--\r\n'
        add(name,body,accepted,'multipart/byteranges; boundary=selection',206,request={'Range':'bytes=0-0,1-'})
    for name,data,valid in [('good',good,True),('bad',bad,False)]:
        n,cut=len(data),len(data)//2
        multipart(name+'-untyped-prefix',[(0,data[:cut],n,None),(cut,data[cut:],n,'text/xml')],valid)
        multipart(name+'-known-last',[(0,data[:cut],'*','text/xml'),(cut,data[cut:],n,None)],valid)
        multipart(name+'-reordered-overlap',[(cut,data[cut:],n,'application/xml'),(0,data[:cut+2],n,'application/xml')],valid)
        multipart(name+'-duplicate',[(0,data,n,'application/xml'),(0,data,n,'application/xml')],valid)
        multipart(name+'-typed-fragment',[(0,data,n,None),(1,data[1:3],n,'image/svg+xml')],valid)
    n,cut=len(bad),len(bad)//2
    multipart('gap',[(0,bad[:cut-1],n,'application/xml'),(cut,bad[cut:],n,'application/xml')],True)
    multipart('unknown',[(0,bad[:cut],'*','application/xml'),(cut,bad[cut:],'*','application/xml')],True)
    multipart('all-text',[(0,bad[:cut],n,'text/plain'),(cut,bad[cut:],n,'text/plain')],True)
    for name,data in [('xml',good),('json',b'{"ok":true}')]:
        n,cut=len(data),len(data)//2
        multipart('conflicting-contracts-'+name,[(0,data[:cut],n,'application/xml'),(cut,data[cut:],n,'application/json')],False)
    assert len({c['name'] for c in cases})==len(cases)
    output.write_text(json.dumps({'version':1,'cases':cases},indent=2)+'\n')
    print(f'{len(cases)} flow cases: {sum(c["accepted"] for c in cases)} accepted, {sum(not c["accepted"] for c in cases)} denied')


if __name__=='__main__':main()
