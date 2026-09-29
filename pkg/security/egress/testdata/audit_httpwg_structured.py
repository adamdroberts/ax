"""Offline RFC 8941 digest grammar audit using pinned HTTPWG test data.

No upstream code is executed and no archive member is extracted. Original
dictionaries exercise Want-* fields. Single-line, comma-free Items and Lists
are embedded as one opaque parameter in each of the four digest fields. A
single-item List has the same item grammar; inner lists remain disallowed in
parameters. Outer SP is removed as the upstream field parser would remove it.
Comma-bearing and multiline item/list cases are excluded because embedding
could change their meaning. Verdicts come from upstream metadata plus explicit
field/edition/policy constraints, never from either production parser.

This checks admission verdicts, not generic Structured Fields value decoding,
serialization, transport integration, or complete RFC 9651 conformance.
"""

import argparse
import base64
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "cmd/ax-mcp-proxy"))
import ax_mcp_proxy as proxy

COMMIT = "00462dd7938b43bf596cb2af6a373d9c928a6cbe"
ARCHIVE_URL = "https://codeload.github.com/httpwg/structured-field-tests/tar.gz/" + COMMIT
ARCHIVE_SHA256 = "f989ae1f5c05f95a6e8bad81274a4acd3136079aef863fd91c20aa61d347cb6a"
PREFIX = "structured-field-tests-" + COMMIT + "/"
BODY = b"ok"
PREFERENCES = ("Want-Content-Digest", "Want-Repr-Digest")
INTEGRITY = ("Content-Digest", "Repr-Digest")
DUPLICATE_DICTIONARIES = {
    "dictionary.json#21": ("duplicate key dictionary", ["a=1,b=2,a=3"]),
    "key-generated.json#172": ("0x2c in dictionary key", ["a,a=1"]),
}

GO_DRIVER = '''package main
import("bufio";"crypto/sha256";"encoding/hex";"encoding/json";"fmt";"net/http";"os";
"github.com/google/ax/pkg/security/httpguard")
type variant struct{Field string;Values []string;Expected *bool;Python bool}
func main(){
 f,err:=os.Open(os.Args[1]);if err!=nil{panic(err)};defer f.Close()
 scanner:=bufio.NewScanner(f);scanner.Buffer(make([]byte,65536),2<<20)
 cases,n,accepted:=0,0,0;var unexpected,mismatch []string;h:=sha256.New()
 for scanner.Scan(){var c struct{ID string;Variants []variant}
 if err:=json.Unmarshal(scanner.Bytes(),&c);err!=nil{panic(err)};cases++
 for _,v:=range c.Variants{
 headers:=http.Header{v.Field:v.Values};var err error
 switch v.Field{
 case "Content-Digest":err=httpguard.CheckContentDigest(headers,[]byte("ok"))
 case "Repr-Digest":var d *httpguard.ContentDigests;d,err=httpguard.ParseRepresentationDigests(headers);if err==nil{err=d.CheckBody([]byte("ok"))}
 case "Want-Content-Digest","Want-Repr-Digest":err=httpguard.ValidateDigestPreferences(headers)
 default:panic("unknown field")
 };ok:=err==nil
 if ok{accepted++;h.Write([]byte{1})}else{h.Write([]byte{0})}
 if v.Expected!=nil&&ok!=*v.Expected{unexpected=append(unexpected,c.ID+"/"+v.Field)}
 if ok!=v.Python{mismatch=append(mismatch,c.ID+"/"+v.Field)};n++
 }};if err:=scanner.Err();err!=nil{panic(err)}
 data,_:=json.Marshal(map[string]any{"selected_cases":cases,"variant_executions":n,"accepted":accepted,"denied":n-accepted,"unexpected_verdicts":unexpected,"parity_mismatches":mismatch,"verdict_sha256":hex.EncodeToString(h.Sum(nil))})
 fmt.Println(string(data));if len(unexpected)+len(mismatch)>0{os.Exit(1)}
}
'''


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def later_type(value):
    if isinstance(value, dict):
        return value.get("__type") in ("date", "displaystring")
    return isinstance(value, list) and any(later_type(child) for child in value)


def select(identity, row):
    kind, raw = row["header_type"], row["raw"]
    if kind == "dictionary":
        return "original-dictionary", None
    if len(raw) != 1:
        return None, "multiline item/list embedding would change framing"
    if "," in raw[0]:
        return None, "comma-bearing item/list embedding could change structure"
    if kind == "list" and not row.get("must_fail") and len(row["expected"]) != 1:
        return None, "list has no single item to embed"
    return "opaque-parameter", None


def oracle(identity, row, mode, values):
    # The upstream invalid verdict has priority: policy does not make it valid.
    if row.get("must_fail"):
        return False, "upstream-invalid"
    expected = row["expected"]
    if later_type(expected):
        return False, "RFC 9651 type outside RFC 8941 field edition"
    if mode == "original-dictionary":
        if any(type(member[1][0]) is not int or not 0 <= member[1][0] <= 10 for member in expected):
            return False, "digest preferences require integer members in 0..10"
        # Upstream's decoded map intentionally hides earlier duplicate values.
        # These pinned cases are explicitly classified rather than reparsed with
        # the implementation being tested or inferred from a failing verdict.
        if identity in DUPLICATE_DICTIONARIES:
            assert (row["name"], row["raw"]) == DUPLICATE_DICTIONARIES[identity]
            return False, "local duplicate-algorithm prohibition"
        if len(expected) > 1024 or any(len(member[1][1]) > 256 for member in expected):
            return False, "local member/parameter ceiling"
    else:
        item = expected[0] if row["header_type"] == "list" else expected
        if isinstance(item[0], list):
            return False, "parameters cannot contain inner lists"
        if len(item[1]) + 1 > 256:
            return False, "local parameter ceiling including wrapper parameter"
    if any(any(ord(c) < 32 or ord(c) > 126 for c in value) for value in values):
        return False, "local visible-ASCII field policy"
    if len(values) > 128 or sum(map(len, values)) > 65536 or any(len(v) > 8192 for v in values):
        return False, "local field byte/line ceiling"
    if row.get("can_fail"):
        return None, "upstream permits either outcome; parity only"
    return True, "upstream-valid within field profile"


def variants(row, mode):
    if mode == "original-dictionary":
        return [(field, row["raw"]) for field in PREFERENCES]
    item = row["raw"][0].strip(" ")
    digest = base64.b64encode(hashlib.sha256(BODY).digest()).decode("ascii")
    return [(field, ["sha-256=0;probe=" + item]) for field in PREFERENCES] + [
        (field, ["sha-256=:" + digest + ":;probe=" + item]) for field in INTEGRITY]


def python_accepts(field, values):
    try:
        if field in PREFERENCES:
            proxy.parse_digest_preferences(values)
        else:
            proxy.validate_digest_members(proxy.parse_content_digest(values), BODY)
        return True
    except proxy.ProtocolPolicyError:
        return False


def read_catalog(archive):
    members = archive.getmembers()
    if len(members) > 100 or sum(m.size for m in members) > 4 << 20:
        raise ValueError("archive exceeds audit limits")
    if len({m.name for m in members}) != len(members) or any(not (m.isfile() or m.isdir()) for m in members):
        raise ValueError("unsupported archive member")
    rows, file_hashes = [], {}
    for member in sorted(members, key=lambda m: m.name):
        if not member.isfile() or not member.name.startswith(PREFIX):
            continue
        name = member.name[len(PREFIX):]
        if "/" in name or not name.endswith(".json"):
            continue
        data = archive.extractfile(member).read()
        file_hashes[name] = sha256(data)
        for index, row in enumerate(json.loads(data)):
            if row.get("header_type") not in ("dictionary", "item", "list"):
                raise ValueError("unknown upstream header type")
            if not isinstance(row.get("raw"), list) or not all(isinstance(v, str) for v in row["raw"]):
                raise ValueError("invalid upstream raw values")
            if not row.get("must_fail") and "expected" not in row:
                raise ValueError("missing upstream oracle")
            rows.append((name + "#" + str(index), row))
    return rows, file_hashes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--go", default="go")
    args = parser.parse_args()
    if args.archive.stat().st_size > 8 << 20 or sha256(args.archive.read_bytes()) != ARCHIVE_SHA256:
        parser.error("archive must match the pinned HTTPWG revision and hash")
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    with tarfile.open(args.archive, "r:gz") as archive:
        rows, corpus_hashes = read_catalog(archive)
        # Preserve upstream notices with the derivative audit inputs.
        for name in ("README.md", "LICENSE.md"):
            (out / ("UPSTREAM-" + name)).write_bytes(archive.extractfile(PREFIX + name).read())
    inputs, excluded, unexpected, verdicts = [], [], [], bytearray()
    for identity, row in rows:
        mode, reason = select(identity, row)
        if mode is None:
            excluded.append({"id": identity, "name": row["name"], "reason": reason})
            continue
        entry = {"id": identity, "name": row["name"], "header_type": row["header_type"],
                 "mode": mode, "raw": row["raw"], "upstream_must_fail": row.get("must_fail", False),
                 "upstream_can_fail": row.get("can_fail", False), "variants": []}
        for field, values in variants(row, mode):
            expected, reason = oracle(identity, row, mode, values)
            accepted = python_accepts(field, values)
            if expected is not None and accepted != expected:
                unexpected.append(identity + "/" + field)
            verdicts.append(int(accepted))
            entry["variants"].append({"field": field, "values": values, "expected": expected,
                                      "reason": reason, "python": accepted})
        inputs.append(entry)
    input_path = out / "inputs.jsonl"
    input_path.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in inputs))
    (out / "excluded.json").write_text(json.dumps(excluded, indent=2) + "\n")
    (out / "main.go").write_text(GO_DRIVER)
    process = subprocess.run([args.go, "run", str(out / "main.go"), str(input_path)],
                             cwd=ROOT, capture_output=True, text=True, timeout=120)
    (out / "go.json").write_text(process.stdout)
    (out / "go.stderr").write_text(process.stderr)
    go = json.loads(process.stdout) if process.stdout.strip() else {"error": process.stderr}
    python = {"selected_cases": len(inputs), "variant_executions": len(verdicts), "accepted": sum(verdicts),
              "denied": len(verdicts) - sum(verdicts), "unexpected_verdicts": unexpected,
              "verdict_sha256": sha256(verdicts)}
    sources = [Path(__file__), ROOT / "cmd/ax-mcp-proxy/ax_mcp_proxy.py",
               ROOT / "pkg/security/httpguard/digest.go", ROOT / "pkg/security/httpguard/digest_preferences.go"]
    summary = {"archive_url": ARCHIVE_URL, "archive_sha256": ARCHIVE_SHA256, "commit": COMMIT,
               "catalog_entries": len(rows), "selected_cases": len(inputs), "excluded_cases": len(excluded),
               "unique_original_values": len({json.dumps(r["raw"]) for r in inputs}),
               "case_verdicts": dict(Counter("accepted" if all(v["python"] for v in r["variants"]) else
                                            "denied" if not any(v["python"] for v in r["variants"]) else
                                            "mixed" for r in inputs)),
               "selection_modes": dict(Counter(r["mode"] for r in inputs)),
               "excluded_reasons": dict(Counter(r["reason"] for r in excluded)),
               "variant_oracles": dict(Counter(v["reason"] for r in inputs for v in r["variants"])),
               "python": python, "go": go, "corpus_sha256": corpus_hashes,
               "source_sha256": {str(p.relative_to(ROOT)): sha256(p.read_bytes()) for p in sources},
               "output_sha256": {name: sha256((out / name).read_bytes()) for name in
                                 ("inputs.jsonl", "excluded.json", "main.go", "go.json", "go.stderr", "UPSTREAM-README.md", "UPSTREAM-LICENSE.md")}}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"selected_cases": len(inputs), "excluded_cases": len(excluded),
                      "variant_executions_per_runtime": len(verdicts), "python_unexpected": unexpected,
                      "go_unexpected": go.get("unexpected_verdicts"), "parity_mismatches": go.get("parity_mismatches")}))
    if process.returncode or unexpected or go.get("verdict_sha256") != python["verdict_sha256"]:
        raise SystemExit("structured-field audit failed; inspect the recorded evidence")


if __name__ == "__main__":
    main()
