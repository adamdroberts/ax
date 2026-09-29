package egress

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"testing"
)

func TestPublicAddressAdmissionCases(t *testing.T) {
	data, err := os.ReadFile("testdata/address_admission_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name, Address string
			Public        bool
		} `json:"address_cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			ip, _ := netip.ParseAddr(tc.Address)
			if got := IsPublicAddress(ip); got != tc.Public {
				t.Fatalf("address=%q public=%v want=%v", tc.Address, got, tc.Public)
			}
		})
	}
}

func TestDNSAnswerAdmissionCases(t *testing.T) {
	data, err := os.ReadFile("testdata/address_admission_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name      string
			Addresses []string
			Admitted  bool
		} `json:"dns_cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			dns := fakeDNS(tc.Addresses...)
			p := mustPolicy(t, "https://api.example.com")
			var dialed []string
			dial := p.pinnedDialer(dns, func(_ context.Context, network, address string) (net.Conn, error) {
				dialed = append(dialed, network+":"+address)
				client, server := net.Pipe()
				server.Close()
				return client, nil
			})
			conn, err := dial(context.Background(), "tcp", "api.example.com:443")
			if conn != nil {
				conn.Close()
			}
			if (err == nil) != tc.Admitted {
				t.Fatalf("admitted=%v want=%v err=%v", err == nil, tc.Admitted, err)
			}
			if len(dns.calls) != 1 || dns.calls[0] != "ip:api.example.com." {
				t.Fatal("resolver was not called once with the absolute approved name")
			}
			if !tc.Admitted {
				if len(dialed) != 0 {
					t.Fatal("rejected answer set opened a socket")
				}
				return
			}
			first := netip.MustParseAddr(tc.Addresses[0])
			family := "tcp4"
			if first.Is6() {
				family = "tcp6"
			}
			if len(dialed) != 1 || dialed[0] != family+":"+net.JoinHostPort(first.String(), "443") {
				t.Fatal("accepted answer was not pinned to the numeric address and requested port")
			}
		})
	}
}
