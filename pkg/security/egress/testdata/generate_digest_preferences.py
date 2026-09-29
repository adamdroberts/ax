"""RFC 9530 preference syntax and non-authority controls; no parser imports."""
import argparse
import base64
import hashlib
import json
from pathlib import Path


def corpus():
    requests, responses = [], []
    def add(name, fields, accepted=True, request=True, response=True, interim=False, method="GET", status=200, data=b"hello"):
        if request:
            headers = {"Content-Type": "text/plain"}
            for key, value in fields:
                headers[key] = headers[key] + ", " + value if key in headers else value
            request_accepted = accepted and all(len(k)+len(v)+4 <= 8192 and v == v.strip(" ") for k,v in headers.items())
            requests.append({"name":name, "accepted":request_accepted, "arguments":{
                "url":"https://api.example.com/preferences", "method":"POST", "headers":headers, "body":"hello"}})
        if response:
            headers = fields + ([] if status == 204 else [("Content-Length", str(len(data)))])
            reason = "OK" if status == 200 else "Response"
            wire = f"HTTP/1.1 {status} {reason}\r\n".encode() + b"".join(f"{k}: {v}\r\n".encode() for k,v in headers) + b"\r\n" + data
            if interim:
                wire = b"HTTP/1.1 103 Early Hints\r\n" + b"".join(f"{k}: {v}\r\n".encode() for k,v in fields) + b"\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
            responses.append({"name":name, "accepted":accepted, "method":method, "status":status,
                              "headers":headers, "request_headers":{"If-None-Match":"*"} if status == 304 else {}, "body_base64":base64.b64encode(data).decode(),
                              "wire_base64":base64.b64encode(wire).decode(), "interim":interim})

    add("absent", [])
    for field in ["Want-Content-Digest", "Want-Repr-Digest"]:
        prefix = field.lower() + "-"
        values = [
            ("empty", "", True), ("zero", "sha-256=0", True), ("one", "sha-256=1", True),
            ("ten", "sha-512=10", True), ("eleven", "sha-256=11", False),
            ("negative", "sha-256=-1", False), ("negative-zero", "sha-256=-0", True),
            ("leading-zero", "sha-256=00010", True),
            ("fifteen-digits", "sha-256=" + "0"*14 + "1", True),
            ("sixteen-digits", "sha-256=" + "0"*15 + "1", False),
            ("huge-integer", "sha-256=999999999999999", False),
            ("huge-negative", "sha-256=-999999999999999", False),
            ("positive-sign", "sha-256=+1", False), ("decimal", "sha-256=1.0", False),
            ("zero-decimal", "sha-256=0.0", False), ("exponent", "sha-256=1e0", False),
            ("quoted-number", 'sha-256="1"', False), ("boolean", "sha-256=?1", False),
            ("bare-key", "sha-256", False), ("byte-sequence", "sha-256=:MQ==:", False),
            ("inner-list", "sha-256=(1)", False), ("unknown-algorithm", "future=10", True),
            ("deprecated-preference-only", "md5=10", True), ("opaque-star-key", "*=0", True),
            ("uppercase-key", "SHA-256=1", False), ("missing-value", "sha-256=", False),
            ("missing-comma", "sha-256=1 sha-512=2", False), ("trailing-comma", "sha-256=1,", False),
            ("leading-comma", ",sha-256=1", False), ("empty-member", "sha-256=1,,sha-512=2", False),
            ("space-before-equals", "sha-256 =1", False), ("space-after-equals", "sha-256= 1", False),
            ("distinct-weights", "sha-256=1, sha-512=10, future=0", True),
            ("duplicate", "sha-256=1, sha-256=1", False),
            ("conflicting-duplicate", "sha-256=0, sha-256=10", False),
            ("parameters", 'sha-256=1;flag;n=-1;token=foo/bar;text="a,b";raw=:eA==:', True),
            ("duplicate-opaque-parameter", "sha-256=1;x=1;x=2", True),
            ("invalid-parameter", "sha-256=1;x=?2", False),
            ("date-parameter", "sha-256=1;x=@1", False),
            ("key-64-characters", "a"*64+"=10", True),
            ("parameter-limit", "sha-256=1"+"".join(";p"+str(i) for i in range(256)), True),
            ("parameter-over-limit", "sha-256=1"+"".join(";p"+str(i) for i in range(257)), False),
            ("member-limit", ", ".join("a"+str(i)+"=1" for i in range(1024)), True),
            ("member-over-limit", ", ".join("a"+str(i)+"=1" for i in range(1025)), False),
        ]
        for name, value, accepted in values:
            add(prefix+name, [(field,value)], accepted)
        for name, values, accepted in [
            ("repeated-distinct", ["sha-256=1", "sha-512=10"], True),
            ("repeated-duplicate", ["sha-256=1", "sha-256=2"], False),
            ("repeated-empty", ["", ""], False),
            ("empty-first", ["", "sha-256=1"], False),
            ("empty-last", ["sha-256=1", ""], False),
        ]:
            add(prefix+name, [(field,v) for v in values], accepted)
        add(prefix+"response-ows", [(field,"  sha-256=1  ")], request=False)
        add(prefix+"interim-valid", [(field,"sha-256=1")], request=False, interim=True)
        add(prefix+"interim-invalid", [(field,"sha-256=11")], False, request=False, interim=True)
        add(prefix+"connection-nomination", [(field,"sha-256=1"),("Connection",field.lower())], False, request=False)
        for method, status in [("HEAD",200),("GET",204),("GET",205),("GET",304)]:
            for suffix, weight, accepted in [("valid",1,True),("invalid",11,False)]:
                add(f"{prefix}{method}-{status}-{suffix}", [(field,f"sha-256={weight}")], accepted,
                    request=False, method=method, status=status, data=b"")

    good = "sha-256=:" + base64.b64encode(hashlib.sha256(b"hello").digest()).decode() + ":"
    wrong = "sha-256=:" + base64.b64encode(hashlib.sha256(b"other").digest()).decode() + ":"
    add("independent-preference-fields", [("Want-Content-Digest","sha-256=0"),("Want-Repr-Digest","sha-256=10")])
    for actual, wanted in [("Content-Digest","Want-Content-Digest"), ("Repr-Digest","Want-Repr-Digest")]:
        add(actual.lower()+"-valid-despite-zero-preference", [(wanted,"sha-256=0"),(actual,good)])
        add(actual.lower()+"-invalid-despite-zero-preference", [(wanted,"sha-256=0"),(actual,wrong)], False)
        add(actual.lower()+"-valid-unpreferred-algorithm", [(wanted,"sha-512=10"),(actual,good)])
        add(actual.lower()+"-weak-preference-does-not-admit-weak-digest", [(wanted,"md5=10"),(actual,"md5=:eA==:")], False)
    return {"requests":requests, "responses":responses}


if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,default=Path(__file__).with_name("digest_preference_cases.json"))
    parser.parse_args().output.write_text(json.dumps(corpus(),indent=2)+"\n")
