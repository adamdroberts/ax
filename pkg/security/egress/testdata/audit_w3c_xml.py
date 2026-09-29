"""Audit the bounded XML admission profile against W3C XML TS 20130923.

Supply the official ZIP locally; this helper performs no network access and
does not extract or execute archive members. It checks the pinned archive hash,
reads catalog fragments as data, and passes original document bytes to both
admission recognizers. DTDs and external entities in test documents are never
loaded. The Go driver uses the production recognizer with only its package name
changed; transport integration belongs to the ordinary regression suites.
"""

import argparse
import base64
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "cmd/ax-mcp-proxy"))
import ax_mcp_proxy as proxy

ARCHIVE_URL = "https://www.w3.org/XML/Test/xmlts20130923.zip"
ARCHIVE_SHA256 = "f9510b3532926e1b4c2e54855b021e4b8a66ec98a5337dcf4ff07e8a41968deb"
XML_BASE = "{http://www.w3.org/XML/1998/namespace}base"
MARKUP = re.compile(r"<!--.*?-->|<!\[CDATA\[.*?\]\]>|<\?.*?\?>|<!DOCTYPE(?=[ \t\r\n])", re.S)

GO_DRIVER = '''package main
import("bufio";"crypto/sha256";"encoding/hex";"encoding/json";"fmt";"os")
const MaxResponseBodyBytes=RESPONSE_LIMIT
func main(){
 f,err:=os.Open(os.Args[1]);if err!=nil{panic(err)};defer f.Close()
 scanner:=bufio.NewScanner(f);scanner.Buffer(make([]byte,65536),32<<20)
 n,accepted:=0,0;var unexpected,mismatch []string;h:=sha256.New()
 for scanner.Scan(){var c struct{ID string;Data []byte;Expected *bool;Python bool}
 if err:=json.Unmarshal(scanner.Bytes(),&c);err!=nil{panic(err)}
 ok:=checkResponseXML(c.Data)==nil
 if ok{accepted++;h.Write([]byte{1})}else{h.Write([]byte{0})}
 if c.Expected!=nil&&ok!=*c.Expected{unexpected=append(unexpected,c.ID)}
 if ok!=c.Python{mismatch=append(mismatch,c.ID)};n++
 };if err:=scanner.Err();err!=nil{panic(err)}
 data,_:=json.Marshal(map[string]any{"executions":n,"accepted":accepted,"denied":n-accepted,"unexpected_verdicts":unexpected,"parity_mismatches":mismatch,"verdict_sha256":hex.EncodeToString(h.Sum(nil))})
 fmt.Println(string(data));if len(unexpected)+len(mismatch)>0{os.Exit(1)}
}
'''


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def member_path(base, relative):
    """Only simple, relative paths inside the pinned archive are needed."""
    path = PurePosixPath(relative)
    if not relative or path.is_absolute() or ".." in path.parts or "\\" in relative or ":" in relative:
        raise ValueError(f"unsupported archive reference: {relative!r}")
    return str(PurePosixPath(base) / path)


def catalogs(archive):
    # These particular fragments contain no declarations or entity references
    # requiring resolution. Some have several top-level TEST siblings. Wrap
    # those after removing their leading XML text declaration. ElementTree does
    # not load external resources, and declarations are additionally rejected.
    root = archive.read("xmlconf/xmlconf.xml").decode("utf-8")
    references = re.findall(r'<!ENTITY\s+[\w.-]+\s+SYSTEM\s+"([^"]+)"\s*>', root)
    if len(references) != 21 or len(set(references)) != 21:
        raise ValueError("unexpected catalog structure")
    for relative in references:
        name = member_path("xmlconf", relative)
        raw = archive.read(name).decode("utf-8")
        if "<!DOCTYPE" in raw or "<!ENTITY" in raw:
            raise ValueError("catalog declarations are not supported")
        raw = re.sub(r"^<\?xml[^?]*\?>", "", raw)
        tree = ET.fromstring("<CATALOG>" + raw + "</CATALOG>")

        def walk(node, base):
            if XML_BASE in node.attrib:
                base = member_path(base, node.attrib[XML_BASE])
            if node.tag == "TEST":
                attrs = {"ENTITIES": "none", "NAMESPACE": "yes", "RECOMMENDATION": "XML1.0", **node.attrib}
                yield attrs, name, member_path(base, attrs["URI"])
            for child in node:
                yield from walk(child, base)

        # Test URIs are relative to the fragment's own source location. This
        # also handles eduni/misc correctly: the root wrapper's xml:base for
        # that external fragment names a nonexistent namespaces/misc directory.
        yield from walk(tree, str(PurePosixPath(name).parent))


def edition_exclusion(attrs):
    if "1.1" in attrs["RECOMMENDATION"] or attrs.get("VERSION") and "1.0" not in attrs["VERSION"].split():
        return "XML or Namespaces 1.1"
    if attrs.get("EDITION") and "5" not in attrs["EDITION"].split():
        return "earlier XML edition only"
    return None


def policy_exclusion(data, attrs):
    """Classify only catalog-declared well-formed documents, independently.

    'invalid' is a DTD-validity label, not a well-formedness failure. Recognizers
    that do not validate DTDs should accept it when it fits the local profile.
    Markers inside comments, CDATA or PIs do not declare a DTD.
    """
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return "non-UTF-8 representation"
    if any(m.group() == "<!DOCTYPE" for m in MARKUP.finditer(text)):
        return "DTD declaration"
    if attrs["NAMESPACE"] == "no":
        return "catalog requires namespace processing disabled"
    declaration = re.match(r"<\?xml\s[^?]*\?>", text)
    if declaration:
        for field, value in re.findall(r"(version|encoding)\s*=\s*['\"]([^'\"]+)['\"]", declaration.group()):
            if field == "version" and value != "1.0":
                return "other XML version declaration"
            if field == "encoding" and value.lower() != "utf-8":
                return "other encoding declaration"
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--go", default="go")
    args = parser.parse_args()
    if args.archive.stat().st_size > 25_000_000 or sha256(args.archive.read_bytes()) != ARCHIVE_SHA256:
        parser.error("archive must match the pinned official 20130923 release")
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    records, inputs, excluded, verdicts, unexpected = [], [], [], bytearray(), []
    with zipfile.ZipFile(args.archive) as archive:
        members = archive.infolist()
        if len(members) > 5000 or sum(m.file_size for m in members) > 32 << 20:
            raise ValueError("archive exceeds audit limits")
        if len({m.filename for m in members}) != len(members):
            raise ValueError("duplicate archive member")
        for attrs, catalog, path in catalogs(archive):
            identity = catalog + "#" + attrs["ID"]
            skip = edition_exclusion(attrs)
            if skip:
                excluded.append({"id": identity, "reason": skip})
                continue
            data = archive.read(path)
            kind = attrs["TYPE"]
            reason = policy_exclusion(data, attrs) if kind in ("valid", "invalid") else None
            if kind in ("valid", "invalid"):
                expected = reason is None
            elif kind == "not-wf":
                expected = False
            elif kind == "error":
                expected = None  # Catalog permits either outcome.
            else:
                raise ValueError(f"unknown catalog type: {kind}")
            try:
                proxy.validate_response_xml(data)
                accepted = True
            except proxy.ProtocolPolicyError:
                accepted = False
            if expected is not None and accepted != expected:
                unexpected.append(identity)
            verdicts.append(int(accepted))
            records.append({"id": identity, "member": path, "catalog_type": kind,
                            "policy_exclusion": reason, "expected": expected,
                            "accepted": accepted, "document_sha256": sha256(data)})
            inputs.append({"id": identity, "data": base64.b64encode(data).decode(),
                           "expected": expected, "python": accepted})
    input_path = out / "inputs.jsonl"
    input_path.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in inputs))
    (out / "cases.json").write_text(json.dumps(records, indent=2) + "\n")
    (out / "excluded.json").write_text(json.dumps(excluded, indent=2) + "\n")
    response_source = (ROOT / "pkg/security/egress/response.go").read_text()
    limit = re.search(r"MaxResponseBodyBytes\s*=\s*(\d+)\s*<<\s*(\d+)", response_source)
    if not limit or int(limit[1]) << int(limit[2]) != proxy.MAX_RESPONSE_BYTES:
        raise RuntimeError("Go/Python byte ceilings must match before the audit")
    production = (ROOT / "pkg/security/egress/xml_content.go").read_text()
    (out / "xml_content.go").write_text(production.replace("package egress", "package main", 1))
    (out / "main.go").write_text(GO_DRIVER.replace("RESPONSE_LIMIT", str(proxy.MAX_RESPONSE_BYTES)))
    process = subprocess.run([args.go, "run", str(out / "main.go"), str(out / "xml_content.go"), str(input_path)],
                             capture_output=True, text=True, timeout=120)
    (out / "go.json").write_text(process.stdout)
    (out / "go.stderr").write_text(process.stderr)
    if process.returncode:
        raise RuntimeError("Go audit failed; inspect go.json and go.stderr")
    go = json.loads(process.stdout)
    python = {"executions": len(records), "accepted": sum(verdicts), "denied": len(records) - sum(verdicts),
              "unexpected_verdicts": unexpected, "verdict_sha256": sha256(verdicts)}
    if unexpected or go["executions"] != len(records) or go["verdict_sha256"] != python["verdict_sha256"]:
        raise RuntimeError("XML profile or parity violation; inspect recorded cases")
    sources = [Path(__file__), ROOT / "cmd/ax-mcp-proxy/ax_mcp_proxy.py",
               ROOT / "pkg/security/egress/xml_content.go", ROOT / "pkg/security/egress/response.go"]
    summary = {"archive_url": ARCHIVE_URL, "archive_sha256": ARCHIVE_SHA256,
               "catalog_entries": len(records) + len(excluded), "selected_cases": len(records),
               "unique_payloads": len({row["document_sha256"] for row in records}),
               "catalog_types": dict(Counter(row["catalog_type"] for row in records)),
               "policy_denials": dict(Counter(row["policy_exclusion"] for row in records if row["policy_exclusion"])),
               "excluded_cases": len(excluded), "edition_exclusions": dict(Counter(row["reason"] for row in excluded)),
               "python": python, "go": go,
               "source_sha256": {str(p.relative_to(ROOT)): sha256(p.read_bytes()) for p in sources},
               "output_sha256": {name: sha256((out / name).read_bytes()) for name in ["inputs.jsonl", "cases.json", "excluded.json", "go.json", "go.stderr"]}}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"selected_cases": len(records), "excluded_cases": len(excluded), "accepted": sum(verdicts),
                      "unexpected_verdicts": 0, "parity_mismatches": 0}))


if __name__ == "__main__":
    main()
