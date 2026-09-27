package egress

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
)

func TestRawResponseHeaderAmbiguitiesRejectedBeforeNormalization(t *testing.T) {
	for name, wire := range map[string]string{
		"length and transfer":        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
		"duplicate equal length":     "HTTP/1.1 200 OK\r\nContent-Length: 2\r\ncontent-length: 2\r\n\r\nok",
		"duplicate different length": "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok",
		"duplicate encoding":         "HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Encoding: identity\r\nContent-Length: 2\r\n\r\nok",
		"bare LF":                    "HTTP/1.1 200 OK\nContent-Length: 2\n\nok",
		"bare LF field":              "HTTP/1.1 200 OK\r\nContent-Length: 2\n\r\nok",
		"folded field":               "HTTP/1.1 200 OK\r\nX-Test: safe\r\n unsafe\r\nContent-Length: 2\r\n\r\nok",
		"folded tab":                 "HTTP/1.1 200 OK\r\nX-Test: safe\r\n\tunsafe\r\nContent-Length: 2\r\n\r\nok",
		"space before colon":         "HTTP/1.1 200 OK\r\nContent-Length : 2\r\n\r\nok",
		"space before name":          "HTTP/1.1 200 OK\r\n Content-Length: 2\r\n\r\nok",
		"status tab":                 "HTTP/1.1\t200 OK\r\nContent-Length: 2\r\n\r\nok",
		"status two spaces":          "HTTP/1.1  200 OK\r\nContent-Length: 2\r\n\r\nok",
		"status injected CR":         "HTTP/1.1 200 OK\rinjected\r\nContent-Length: 2\r\n\r\nok",
		"header obs text":            "HTTP/1.1 200 OK\r\nX-Test: \xff\r\nContent-Length: 2\r\n\r\nok",
		"nondecimal length":          "HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\nok",
		"length with leading zero":   "HTTP/1.1 200 OK\r\nContent-Length: 02\r\n\r\nok",
		"oversized field":            "HTTP/1.1 200 OK\r\nX-Test: " + strings.Repeat("a", 8192) + "\r\nContent-Length: 2\r\n\r\nok",
		"too many fields":            "HTTP/1.1 200 OK\r\n" + strings.Repeat("X-Test: a\r\n", MaxResponseHeaders) + "Content-Length: 2\r\n\r\nok",
		"too many bytes":             "HTTP/1.1 200 OK\r\n" + strings.Repeat("X-Test: "+strings.Repeat("a", 8000)+"\r\n", 9) + "Content-Length: 2\r\n\r\nok",
		"informational with length":  "HTTP/1.1 103 Early Hints\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
		"204 with length":            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
		"204 with transfer":          "HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"content transfer encoding":  "HTTP/1.1 200 OK\r\nContent-Transfer-Encoding: base64\r\nContent-Length: 0\r\n\r\n",
		"missing status separator":   "HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n",
		"excessive informational":    strings.Repeat("HTTP/1.1 103 Early Hints\r\n\r\n", 5) + "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
	} {
		t.Run(name, func(t *testing.T) {
			client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), pipeResponse(wire, nil))
			resp, err := client.Get("http://api.example.com")
			if resp != nil {
				resp.Body.Close()
			}
			if err == nil {
				t.Fatal("raw response ambiguity passed header gate")
			}
		})
	}
}

func TestInformationalResponseAndHeaderOrderingPreserved(t *testing.T) {
	wire := "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: 2\r\n\r\nok"
	client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), pipeResponse(wire, nil))
	resp, err := client.Get("http://api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if body, err := io.ReadAll(resp.Body); err != nil || string(body) != "ok" || len(resp.Cookies()) != 2 {
		t.Fatalf("ordinary response changed: body=%q cookies=%d err=%v", body, len(resp.Cookies()), err)
	}
}

func TestIPLiteralDialDoesNotResolveDNS(t *testing.T) {
	for origin, address := range map[string]string{"https://8.8.8.8": "8.8.8.8:443", "https://[2606:4700:4700::1111]": "[2606:4700:4700::1111]:443"} {
		p := mustPolicy(t, origin)
		dns := fakeDNS("127.0.0.1")
		var called string
		dial := p.pinnedDialer(dns, func(_ context.Context, _, addr string) (net.Conn, error) {
			called = addr
			client, server := net.Pipe()
			server.Close()
			return client, nil
		})
		conn, err := dial(context.Background(), "tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
		if len(dns.calls) != 0 || called != address {
			t.Fatalf("literal was re-resolved: calls=%v address=%q", dns.calls, called)
		}
	}
}
