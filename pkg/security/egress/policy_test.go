package egress

import (
	"net/netip"
	"testing"
)

func TestExactOriginPolicy(t *testing.T) {
	p, err := NewPolicy([]string{"https://API.example.com", "http://api.example.com:8080", "https://[2606:4700:4700::1111]"})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"https://api.example.com/path?q=x", "https://API.EXAMPLE.COM:443/", "http://api.example.com:8080/a", "https://[2606:4700:4700::1111]:443/"} {
		if err := p.CheckURL(raw); err != nil {
			t.Errorf("allowed request %q failed: %v", raw, err)
		}
	}
	for _, raw := range []string{"http://api.example.com", "https://api.example.com:444", "https://sub.api.example.com", "https://api.example.com.attacker.com", "https://other.example.com", "https://api.example.com./", "https://user@api.example.com", "https://api.example.com/#fragment", "https://api.example.com/#", "https://api.example.com:0443/", "https://api.example.com:0/", "https://[2606:4700:4700:0:0:0:0:1111]:443/"} {
		if err := p.CheckURL(raw); err == nil {
			t.Errorf("unexpectedly allowed %q", raw)
		}
	}
	empty, err := NewPolicy(nil)
	if err != nil || empty.CheckURL("https://api.example.com") == nil {
		t.Fatal("empty allowlist did not deny outbound")
	}
}

func TestRejectAmbiguousAndNonpublicOriginConfiguration(t *testing.T) {
	for _, raw := range []string{
		"", "api.example.com", "//api.example.com", "ftp://api.example.com", "https://api.example.com/", "https://api.example.com?q=x", "https://api.example.com?", "https://api.example.com#", "https://x@y.example.com",
		"https://localhost", "https://a.localhost", "https://a.local", "https://a.internal", "https://a.home.arpa", "https://a.onion",
		"https://example.com.", "https://éxample.com", "https://a..example.com", "https://a_b.example.com", "https://-a.example.com", "https://a-.example.com", "https://*.example.com", "https://api.example.com:", "https://api.example.com:65536",
		"https://127.0.0.1", "https://169.254.169.254", "https://10.0.0.1", "https://168.63.129.16", "https://2130706433", "https://0177.0.0.1", "https://127.1", "https://0x7f000001", "https://[::1]", "https://[::ffff:8.8.8.8]", "https://[fe80::1%25en0]", "https://[2001:db8::1]", "https://[example.com]", "https://[8.8.8.8]", "https://2001:4860:4860::8888",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := NewPolicy([]string{raw}); err == nil {
				t.Fatal("invalid origin accepted")
			}
		})
	}
}

func TestPublicAddressBoundaries(t *testing.T) {
	for _, raw := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "2001:4860:4860::8888"} {
		if !publicAddress(netip.MustParseAddr(raw)) {
			t.Errorf("public address denied: %s", raw)
		}
	}
	for _, raw := range []string{
		"0.1.2.3", "10.1.2.3", "100.100.100.200", "127.255.255.254", "169.254.169.254", "172.31.255.255", "192.0.0.9", "192.0.2.1", "192.31.196.1", "192.52.193.1", "192.88.99.1", "192.168.1.1", "192.175.48.1", "198.19.255.255", "198.51.100.1", "203.0.113.1", "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255", "168.63.129.16",
		"::", "::1", "::ffff:127.0.0.1", "::ffff:8.8.8.8", "64:ff9b::a00:1", "64:ff9b:1::1", "100::1", "100:0:0:1::1", "2001::1", "2001:1::1", "2001:2::1", "2001:3::1", "2001:4:112::1", "2001:20::1", "2001:db8::1", "2002:0808:0808::1", "2620:4f:8000::1", "3fff::1", "5f00::1", "fc00::1", "fd00:ec2::254", "fe80::1", "ff02::1", "2606:4700:4700::1111%en0",
	} {
		if publicAddress(netip.MustParseAddr(raw)) {
			t.Errorf("special address accepted: %s", raw)
		}
	}
	if publicAddress(netip.Addr{}) {
		t.Fatal("invalid address accepted")
	}
}
