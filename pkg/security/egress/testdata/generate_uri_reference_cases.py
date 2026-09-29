"""RFC 3986 / RFC 9110 URI-reference metadata fixtures; no network access."""
import json
from pathlib import Path

# Verdicts are authored from component grammar, not a URL library's recovery.
VALID = [
    "", ".", "..", "/", "./", "../report", "report", "./a:b", "a/b:c", "a//b",
    "?", "?q=a/b?c", "/report?x=1&y=2", "/a;b=@c,+$!&'()*=~_-.",
    "/%00/%FF/%5c/%2f/%23", "/%e2%82%ac", "//example.test/path", "//example.test:",
    "http://example.test", "HTTPS://EXAMPLE.TEST/a", "https://example.test:443/a",
    "https://example.test:/a", "https://example.test:0/a", "https://example.test:65536/a",
    "https://example.test:000443/a", "https://%65xample.test/a", "https://exa!mple.test/a",
    "https://a_b.test/a", "https://example.test./a", "https://127.0.0.1/",
    "https://999.999.999.999/", "https://[2001:db8::1]/", "https://[::ffff:192.0.2.1]:443/a",
    "https://[2001:DB8:0:0:0:0:0:1]/", "https://[v1.a:b]/", "https://[Vf.a!$&'()*+,;=:_~]/",
    "mailto:team@example.test", "urn:example:a:b", "data:text/plain,ok", "tel:+12345",
    "x+v-1.2:", "file:///tmp/report", "ftp://user:pass@example.test/a", "x://",
    "x://:123/path", "x:/path", "x:rootless/a", "x://user%40id:pass@example.test/a",
    "x://@example.test/a", "https://example.test/a,b", "/a%20b", "/x?uri=https://example.test/a",
]
FRAGMENTS = ["#", "#part", "/path#part", "/path?q#part", "https://example.test/#part", "urn:a#b", "/path#x?y/z", "/#%23"]
INVALID = [
    "/a b", "/a\\b", "/<a>", '/"a"', "/a`b", "/a{b}", "/a|b", "/a^b", "/a[b]",
    "/%", "/%0", "/%G0", "/%0G", "/%2/", "/a?%", "/a?x=[b]", "/a#%", "/a#x[y]", "/a#b#c",
    ":a", "1x:a", "+x:a", "x_y:a", "./a b", "//", "///path", "//:443/path",
    "http:", "http:/path", "https:relative", "HTTP:?q", "http://", "https:///path",
    "http://?query", "https://#part", "http://user@example.test/a", "HTTPS://u:p@example.test/a",
    "//user@example.test/a", "//u:p@example.test/a", "x://u@v@example.test/a",
    "https://example.test:abc/", "https://example.test:-1/", "https://example.test:+1/",
    "https://example.test:1:2/", "https://2001:db8::1/", "https://[2001:db8::1/",
    "https://2001:db8::1]/", "https://[2001:db8::1]tail/", "https://[2001:db8::1]:x/",
    "https://[127.0.0.1]/", "https://[]/", "https://[2001::db8::1]/", "https://[gggg::1]/",
    "https://[::ffff:192.168.001.1]/", "https://[fe80::1%25eth0]/", "https://[fe80::1%eth0]/",
    "https://[v.a]/", "https://[v1.]/", "https://[vG.a]/", "https://[v1.%61]/",
    "https://[v1.a@b]/", "https://[v1.a[b]]/", "https://exa mple.test/", "https://example.test%/",
    "https://example.test%0/", "https://example.test%GG/", "x://user%GG@example.test/a",
    "x://user[info]@example.test/a", "x://user\\info@example.test/a",
]


def build():
    responses, requests = [], []
    samples = [("valid-"+str(i), v, True) for i,v in enumerate(VALID)]
    samples += [("fragment-"+str(i), v, None) for i,v in enumerate(FRAGMENTS)]
    samples += [("invalid-"+str(i), v, False) for i,v in enumerate(INVALID)]
    for field in ("Location", "Content-Location"):
        for name, value, accepted in samples:
            accepted = (field == "Location") if accepted is None else accepted
            responses.append({"name": field.lower()+"-"+name, "headers": [[field,value]], "accepted": accepted})
            if field == "Content-Location":
                requests.append({"name":name,"accepted":accepted,"arguments":{"url":"https://api.example.com/metadata","method":"POST","body":"ok","headers":{field:value}}})
        for name, size, accepted in (("recommended-uri-capacity",8000,True),("field-capacity",8192-len(field)-4,True),("field-over-capacity",8193-len(field)-4,False)):
            value="/"+"a"*(size-1)
            responses.append({"name":field.lower()+"-"+name,"headers":[[field,value]],"accepted":accepted})
            if field == "Content-Location":
                requests.append({"name":name,"accepted":accepted,"arguments":{"url":"https://api.example.com/metadata","method":"POST","body":"ok","headers":{field:value}}})
        for second in (field,field.lower()):
            responses.append({"name":field.lower()+"-duplicate-"+second,"headers":[[field,"/one"],[second,"/two"]],"accepted":False})
        responses.append({"name":field.lower()+"-connection","headers":[["Connection",field],[field,"/one"]],"accepted":False})
    requests.append({"name":"case-variant-duplicate","accepted":False,"arguments":{"url":"https://api.example.com/metadata","method":"POST","body":"ok","headers":{"Content-Location":"/one","content-location":"/two"}}})
    responses.append({"name":"independent-fields","headers":[["Location","/new#part"],["Content-Location","/representation"]],"accepted":True})
    return {"description":"URI grammar and HTTP reference metadata policy; accepted labels never authorize access. Ports and registered names are syntactic labels, not reachability claims. MIME URI fields have a separate contract.","references":["https://www.rfc-editor.org/rfc/rfc3986.html","https://www.rfc-editor.org/rfc/rfc9110.html#section-8.7","https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2"],"requests":requests,"responses":responses}


if __name__ == "__main__":
    target=Path(__file__).with_name("uri_reference_cases.json")
    target.write_text(json.dumps(build(),indent=2)+"\n")
