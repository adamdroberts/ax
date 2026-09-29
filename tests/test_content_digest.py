"""Content-Digest is checked before MCP delivery; raw content is preserved."""
import base64
import hashlib
import json
import unittest
from test_http_protocol import ROOT, WireSocket, FakeResponse, FakeOpener, proxy


class ContentDigestTests(unittest.TestCase):
    def test_repeated_digest_fields_preserved(self):
        body=b'ok'
        values=[algorithm+'=:'+base64.b64encode(factory(body).digest()).decode()+':'
                for algorithm,factory in [('sha-256',hashlib.sha256),('sha-512',hashlib.sha512)]]
        fields=[('Content-Digest',values[0]),('cOnTeNt-DiGeSt',values[1])]
        response=FakeResponse(body=body,headers=fields)
        server=proxy.MCPServer(proxy.SnortEngine(),opener=FakeOpener(response))
        result=server._response_data(response,method='GET')
        self.assertEqual([v for k,v in result['headers'].items() if k.lower()=='content-digest'],[', '.join(values)])
        self.assertEqual(result['header_values']['content-digest'],values)
        self.assertEqual(result['body'].encode(),body)

    def test_maximum_content_digest(self):
        body=b'x'*proxy.MAX_RESPONSE_BYTES
        value='sha-256=:'+base64.b64encode(hashlib.sha256(body).digest()).decode()+':'
        proxy.validate_content_digest({'content-digest':[value]},body)
        with self.assertRaises(proxy.ProtocolPolicyError):
            proxy.validate_content_digest({'content-digest':[value]},body[:-1]+b'y')
        with self.assertRaises(proxy.ProtocolPolicyError):
            proxy.validate_response_metadata({'content-digest':[]})

    def test_content_digest_before_delivery(self):
        cases=json.loads((ROOT/'pkg/security/egress/testdata/content_digest_cases.json').read_text())['cases']
        for case in cases:
            with self.subTest(name=case['name']):
                wire=base64.b64decode(case['wire_base64'])
                body=base64.b64decode(case['body_base64'])
                calls,captured=[],[]
                class Opener:
                    def open(self, request, timeout):
                        calls.append(request)
                        response=proxy.StrictHTTPResponse(WireSocket(wire),method=request.get_method())
                        response.begin()
                        response.code=response.status
                        return response
                engine=proxy.SnortEngine()
                engine.load_rules('drop tcp any any -> any any (content:"forbidden-marker"; sid:1;)')
                server=proxy.MCPServer(engine,allowed_origins=['https://api.example.com'],opener=Opener())
                server._send_response=lambda request_id,result:captured.append(result)
                server._execute_http_request(1,{'url':'https://api.example.com/digest','method':case['method'],'headers':case['request_headers']})
                self.assertEqual(len(calls),1)
                self.assertEqual(not captured[-1]['isError'],case['accepted'],captured[-1]['content'][0]['text'][:150])
                if case['accepted']:
                    value=json.loads(captured[-1]['content'][0]['text'])
                    self.assertEqual(value['body'].encode(),body)
                if case['rejection_stage']=='headers':
                    self.assertEqual(server.response_bytes,0)
                elif not case['interim']:
                    self.assertEqual(server.response_bytes,len(wire.split(b'\r\n\r\n',1)[1]))


if __name__=='__main__':unittest.main()
