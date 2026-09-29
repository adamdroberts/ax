// Test-only deterministic certificates. The published keys are not secrets and
// must never be used as production identities or trust anchors.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type identity struct {
	Name        string   `json:"name"`
	Host        string   `json:"host"`
	CommonName  string   `json:"common_name"`
	DNS         []string `json:"dns_names,omitempty"`
	IP          []string `json:"ip_addresses,omitempty"`
	URI         []string `json:"uris,omitempty"`
	Email       []string `json:"email_addresses,omitempty"`
	Trusted     bool     `json:"trusted"`
	Validity    string   `json:"validity"`
	ClientOnly  bool     `json:"client_only,omitempty"`
	Accepted    bool     `json:"accepted"`
	Certificate string   `json:"certificate"`
}

func main() {
	out := flag.String("output", "pkg/security/egress/testdata/tls-identity", "fixture directory")
	flag.Parse()
	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	must(os.MkdirAll(*out, 0755))
	write := func(name string, data []byte) { must(os.WriteFile(filepath.Join(*out, name), data, 0644)) }
	key := func(label string) ed25519.PrivateKey {
		seed := sha256.Sum256([]byte("AX PUBLIC TLS TEST FIXTURE ONLY: " + label))
		return ed25519.NewKeyFromSeed(seed[:])
	}
	rootKey, leafKey := key("root"), key("leaf")
	ski := func(key ed25519.PrivateKey) []byte {
		hash := sha256.Sum256(key.Public().(ed25519.PublicKey))
		return hash[:20]
	}
	start, end := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "AX public TLS identity test CA"}, NotBefore: start, NotAfter: end,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: ski(rootKey)}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	must(err)
	write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	leafDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	must(err)
	write("server-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafDER}))

	var cases []identity
	add := func(name, host, cn string, dns, ips, uris, emails []string, accepted bool) {
		cases = append(cases, identity{Name: name, Host: host, CommonName: cn, DNS: dns, IP: ips, URI: uris, Email: emails, Trusted: true, Validity: "current", Accepted: accepted})
	}
	add("san-exact", "api.example.com", "other.example.com", []string{"api.example.com"}, nil, nil, nil, true)
	add("san-without-cn", "api.example.com", "", []string{"api.example.com"}, nil, nil, nil, true)
	add("san-case", "api.example.com", "", []string{"API.EXAMPLE.COM"}, nil, nil, nil, true)
	add("san-many", "api.example.com", "", []string{"wrong.example.com", "api.example.com"}, nil, nil, nil, true)
	add("san-wildcard", "api.example.com", "", []string{"*.example.com"}, nil, nil, nil, true)
	add("san-alabel", "xn--bcher-kva.example.com", "", []string{"xn--bcher-kva.example.com"}, nil, nil, nil, true)
	add("cn-only-exact", "api.example.com", "api.example.com", nil, nil, nil, nil, false)
	add("cn-only-wildcard", "api.example.com", "*.example.com", nil, nil, nil, nil, false)
	add("cn-only-wrong", "api.example.com", "wrong.example.com", nil, nil, nil, nil, false)
	add("cn-matches-wrong-dns", "api.example.com", "api.example.com", []string{"wrong.example.com"}, nil, nil, nil, false)
	add("cn-matches-uri-only", "api.example.com", "api.example.com", nil, nil, []string{"https://api.example.com"}, nil, false)
	add("cn-matches-email-only", "api.example.com", "api.example.com", nil, nil, nil, []string{"service@api.example.com"}, false)
	add("cn-matches-ip-only", "api.example.com", "api.example.com", nil, []string{"8.8.8.8"}, nil, nil, false)
	add("no-identity", "api.example.com", "", nil, nil, nil, nil, false)
	add("san-wrong", "api.example.com", "other.example.com", []string{"wrong.example.com"}, nil, nil, nil, false)
	add("san-partial-prefix", "api.example.com", "", []string{"api*.example.com"}, nil, nil, nil, false)
	add("san-partial-suffix", "api.example.com", "", []string{"*api.example.com"}, nil, nil, nil, false)
	add("san-partial-middle", "api.example.com", "", []string{"a*i.example.com"}, nil, nil, nil, false)
	add("san-two-wildcards", "api.mail.example.com", "", []string{"*.*.example.com"}, nil, nil, nil, false)
	add("san-wildcard-deep", "deep.api.example.com", "", []string{"*.example.com"}, nil, nil, nil, false)
	add("san-wildcard-apex", "example.com", "", []string{"*.example.com"}, nil, nil, nil, false)
	add("ip4-match", "8.8.8.8", "", nil, []string{"8.8.8.8"}, nil, nil, true)
	add("ip4-dns-only", "8.8.8.8", "", []string{"8.8.8.8"}, nil, nil, nil, false)
	add("ip4-cn-only", "8.8.8.8", "8.8.8.8", nil, nil, nil, nil, false)
	add("ip4-wrong", "8.8.8.8", "", nil, []string{"8.8.4.4"}, nil, nil, false)
	add("ip6-match", "2001:4860:4860::8888", "", nil, []string{"2001:4860:4860::8888"}, nil, nil, true)
	add("ip6-dns-only", "2001:4860:4860::8888", "", []string{"2001:4860:4860::8888"}, nil, nil, nil, false)
	add("ip6-wrong", "2001:4860:4860::8888", "", nil, []string{"2001:4860:4860::8844"}, nil, nil, false)
	add("mixed-san", "api.example.com", "", []string{"api.example.com"}, []string{"8.8.4.4"}, []string{"https://other.example.com"}, nil, true)
	add("untrusted-root", "api.example.com", "", []string{"api.example.com"}, nil, nil, nil, false)
	cases[len(cases)-1].Trusted = false
	add("expired", "api.example.com", "", []string{"api.example.com"}, nil, nil, nil, false)
	cases[len(cases)-1].Validity = "expired"
	add("not-yet-valid", "api.example.com", "", []string{"api.example.com"}, nil, nil, nil, false)
	cases[len(cases)-1].Validity = "future"
	add("client-eku-only", "api.example.com", "", []string{"api.example.com"}, nil, nil, nil, false)
	cases[len(cases)-1].ClientOnly = true
	for i := range cases {
		c := &cases[i]
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(100 + i)), Subject: pkix.Name{CommonName: c.CommonName, Organization: []string{"AX offline TLS tests"}},
			NotBefore: start, NotAfter: end, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: c.DNS, EmailAddresses: c.Email, SubjectKeyId: ski(leafKey), AuthorityKeyId: root.SubjectKeyId}
		if c.ClientOnly {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		if c.Validity == "expired" {
			leaf.NotAfter = start.AddDate(1, 0, 0)
		}
		if c.Validity == "future" {
			leaf.NotBefore = end
			leaf.NotAfter = end.AddDate(1, 0, 0)
		}
		for _, ip := range c.IP {
			leaf.IPAddresses = append(leaf.IPAddresses, net.ParseIP(ip))
		}
		for _, raw := range c.URI {
			u, err := url.Parse(raw)
			must(err)
			leaf.URIs = append(leaf.URIs, u)
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, root, leafKey.Public(), rootKey)
		must(err)
		c.Certificate = c.Name + ".pem"
		write(c.Certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	manifest := struct {
		Version     int        `json:"version"`
		TLSVersions []string   `json:"tls_versions"`
		Cases       []identity `json:"cases"`
	}{1, []string{"TLSv1.2", "TLSv1.3"}, cases}
	data, err := json.MarshalIndent(manifest, "", "  ")
	must(err)
	write("cases.json", append(data, '\n'))
	fmt.Printf("generated %d certificates and %d TLS identity cases\n", len(cases), 2*len(cases))
}
