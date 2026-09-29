"""Reproducible bounded XML mutation audit; no network peers or resource loads.

Compare Go/Python admission and require every admitted ASCII document to parse
with the independent Expat namespace parser. Intentional local-policy rejections
are permitted. Unicode Fifth Edition name coverage belongs to the shared corpus.
The Go audit compiles an exact copy of xml_content.go with only its package name
changed and the production response-byte ceiling supplied by the small driver.
Ordinary, range and multipart transport integration is covered by the Go/Python
regression tests rather than this isolated parser audit.
"""
import argparse
import base64
import hashlib
import json
import random
import re
import subprocess
import sys
from pathlib import Path
from xml.parsers import expat

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "cmd/ax-mcp-proxy"))
import ax_mcp_proxy as proxy

GO_DRIVER = '''package main
import("bufio";"crypto/sha256";"encoding/hex";"encoding/json";"fmt";"os")
const MaxResponseBodyBytes=RESPONSE_LIMIT
func main(){
 f,err:=os.Open(os.Args[1]);if err!=nil{panic(err)};defer f.Close()
 scanner:=bufio.NewScanner(f);n,accepted:=0,0;var unsafe,mismatch []int;h:=sha256.New()
 for scanner.Scan(){var c struct{Data []byte;Oracle,Python bool};if err:=json.Unmarshal(scanner.Bytes(),&c);err!=nil{panic(err)}
 ok:=checkResponseXML(c.Data)==nil
 if ok{accepted++;h.Write([]byte{1})}else{h.Write([]byte{0})}
 if ok&&!c.Oracle{unsafe=append(unsafe,n)};if ok!=c.Python{mismatch=append(mismatch,n)};n++
 };if err:=scanner.Err();err!=nil{panic(err)}
 data,_:=json.Marshal(map[string]any{"executions":n,"accepted":accepted,"denied":n-accepted,"unsafe_acceptances":unsafe,"parity_mismatches":mismatch,"verdict_sha256":hex.EncodeToString(h.Sum(nil))})
 fmt.Println(string(data));if len(unsafe)+len(mismatch)>0{os.Exit(1)}
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--go", default="go")
    parser.add_argument("--cases", type=int, default=25000)
    parser.add_argument("--seed", type=int, default=7310305)
    args = parser.parse_args()
    if not 1 <= args.cases <= 1000000:
        parser.error("cases must be between 1 and 1000000")
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    corpus_path = Path(__file__).with_name("xml_response_cases.json")
    seeds = [base64.b64decode(c["document_base64"]) for c in json.loads(corpus_path.read_text())["cases"]]
    seeds = [b for b in seeds if b and b.isascii() and len(b) < 512 and b"<!DOCTYPE" not in b and b"<!ENTITY" not in b]
    rng = random.Random(args.seed)
    alphabet = b"<>/?!\"'= abcdef0123456789:;#x&\t\r\n-_[]%"
    accepted, unsafe, unique, verdicts = 0, [], set(), bytearray()
    inputs = out / "inputs.jsonl"
    with inputs.open("w") as stream:
        for i in range(args.cases):
            data = rng.choice(seeds)
            for _ in range(1+rng.randrange(4)):
                pos, mode = rng.randrange(len(data)+1), rng.randrange(4)
                piece = bytes(rng.choice(alphabet) for _ in range(1+rng.randrange(5)))
                if mode == 0:
                    data = data[:pos]+piece+data[pos:]
                elif mode == 1:
                    data = data[:pos]+data[pos+1+rng.randrange(5):]
                elif mode == 2:
                    data = data[:pos]+piece+data[pos+len(piece):]
                else:
                    data = data[:pos]+data[max(0,pos-5):pos]+data[pos:]
            try:
                proxy.validate_response_xml(data)
                ok = True
            except proxy.ProtocolPolicyError:
                ok = False
            oracle = expat.ParserCreate(namespace_separator="|")
            try:
                oracle.Parse(data, True)
                grammar = True
            except (expat.ExpatError, LookupError):
                grammar = False
            if ok and not grammar:
                unsafe.append(i)
            accepted += ok
            verdicts.append(int(ok))
            unique.add(hashlib.sha256(data).digest())
            stream.write(json.dumps({"data":base64.b64encode(data).decode(), "oracle":grammar, "python":ok},separators=(",",":"))+"\n")
    python = {"executions":args.cases, "unique_payloads":len(unique), "accepted":accepted, "denied":args.cases-accepted,
              "unsafe_acceptances":unsafe, "verdict_sha256":hashlib.sha256(verdicts).hexdigest(), "seed":args.seed, "oracle":expat.EXPAT_VERSION}
    (out / "python.json").write_text(json.dumps(python, indent=2)+"\n")
    response_source = (ROOT / "pkg/security/egress/response.go").read_text()
    limit = re.search(r"MaxResponseBodyBytes\s*=\s*(\d+)\s*<<\s*(\d+)", response_source)
    if not limit or int(limit[1]) << int(limit[2]) != proxy.MAX_RESPONSE_BYTES:
        raise RuntimeError("Go/Python byte ceilings must be reconciled before the isolated audit")
    production = (ROOT / "pkg/security/egress/xml_content.go").read_text()
    (out / "xml_content.go").write_text(production.replace("package egress", "package main", 1))
    (out / "main.go").write_text(GO_DRIVER.replace("RESPONSE_LIMIT", str(proxy.MAX_RESPONSE_BYTES)))
    process = subprocess.run([args.go,"run",str(out/"main.go"),str(out/"xml_content.go"),str(inputs)], capture_output=True, text=True)
    (out / "go.json").write_text(process.stdout)
    (out / "go.stderr").write_text(process.stderr)
    if process.returncode:
        raise RuntimeError("Go audit failed; inspect go.json and go.stderr")
    go = json.loads(process.stdout)
    if unsafe or go["executions"] != args.cases or go["verdict_sha256"] != python["verdict_sha256"]:
        raise RuntimeError("XML acceptance or parity violation; inspect recorded inputs")
    paths = [Path(__file__),corpus_path,ROOT/"cmd/ax-mcp-proxy/ax_mcp_proxy.py",ROOT/"pkg/security/egress/xml_content.go",ROOT/"pkg/security/egress/response.go"]
    summary = {"python":python,"go":go,"source_sha256":{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},"inputs_sha256":hashlib.sha256(inputs.read_bytes()).hexdigest()}
    (out / "summary.json").write_text(json.dumps(summary, indent=2)+"\n")
    print(json.dumps({"executions":args.cases,"unique_payloads":len(unique),"accepted":accepted,"unsafe_acceptances":0,"parity_mismatches":0}))


if __name__ == "__main__":
    main()
