# Public TLS test fixtures

These deterministic certificates and the published server key are test data.
Tests install the fixture CA only into isolated client contexts and exchange TLS
over local in-memory or Unix socket pairs. Production clients use system roots;
these files are never loaded by the production configuration.

Run `go run pkg/security/egress/testdata/tls-identity/generate.go` from the
repository root to reproduce them, or pass `-output` for a separate directory.
The fixture key seeds are public constants. They are unsuitable for production
identities or machine trust stores.

The manifest covers DNS/IP subject alternative names, legacy Common Name-only
certificates, wildcard boundaries, alternative SAN types and certificate trust,
time and server-purpose failures under TLS 1.2 and TLS 1.3. Fixtures use fixed
dates; current certificates are valid from 2000 to 2100, with separate expired
and future controls. The cases exercise HTTP's DNS/IP reference identities;
they are not a complete PKIX, revocation, TLS or certificate-issuance audit.
