package egress

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestParsedResponseGuard(t *testing.T) {
	good := func() *http.Response {
		return &http.Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: 200, ContentLength: -1, Header: http.Header{}}
	}
	for name, change := range map[string]func(*http.Response){
		"HTTP2":              func(r *http.Response) { r.ProtoMajor = 2 },
		"HTTP10":             func(r *http.Response) { r.ProtoMinor = 0 },
		"upgrade status":     func(r *http.Response) { r.StatusCode = 101 },
		"gzip":               func(r *http.Response) { r.Header.Set("Content-Encoding", "gzip") },
		"multiple encoding":  func(r *http.Response) { r.Header["Content-Encoding"] = []string{"identity", "identity"} },
		"decompressed":       func(r *http.Response) { r.Uncompressed = true },
		"transfer encoding":  func(r *http.Response) { r.TransferEncoding = []string{"gzip"} },
		"conflicting length": func(r *http.Response) { r.TransferEncoding = []string{"chunked"}; r.ContentLength = 2 },
		"trailer":            func(r *http.Response) { r.Trailer = http.Header{"Digest": nil} },
		"upgrade header":     func(r *http.Response) { r.Header.Set("Upgrade", "websocket") },
		"connection upgrade": func(r *http.Response) { r.Header.Set("Connection", "keep-alive, Upgrade") },
		"header control":     func(r *http.Response) { r.Header.Set("X-Test", "x\r\ny") },
		"duplicate case":     func(r *http.Response) { r.Header["X-Test"] = []string{"a"}; r.Header["x-test"] = []string{"b"} },
		"duplicate length":   func(r *http.Response) { r.ContentLength = 2; r.Header["Content-Length"] = []string{"2", "2"} },
		"bad length":         func(r *http.Response) { r.ContentLength = 2; r.Header.Set("Content-Length", "3") },
		"oversized length":   func(r *http.Response) { r.ContentLength = MaxResponseBodyBytes + 1 },
		"oversized header":   func(r *http.Response) { r.Header.Set("X-Test", strings.Repeat("a", MaxResponseHeaderBytes)) },
		"too many headers":   func(r *http.Response) { r.Header["X-Test"] = make([]string, MaxResponseHeaders+1) },
	} {
		t.Run(name, func(t *testing.T) {
			r := good()
			change(r)
			if err := CheckResponse(r); err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
	r := good()
	r.TransferEncoding = []string{"chunked"}
	r.Header.Set("Content-Encoding", "identity")
	if err := CheckResponse(r); err != nil {
		t.Fatal(err)
	}
}

func TestWireResponseEncodingProtocolAndTrailers(t *testing.T) {
	for name, wire := range map[string]string{
		"compression":        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\nok",
		"HTTP10":             "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok",
		"upgrade":            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
		"announced trailer":  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Injected\r\n\r\n2\r\nok\r\n0\r\nX-Injected: bad\r\n\r\n",
		"undeclared trailer": "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-Injected: bad\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), pipeResponse(wire, nil))
			resp, err := client.Get("http://api.example.com")
			if err == nil {
				_, err = io.ReadAll(resp.Body)
				resp.Body.Close()
			}
			if err == nil {
				t.Fatal("invalid wire response passed")
			}
		})
	}
	client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), pipeResponse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n", nil))
	resp, err := client.Get("http://api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if body, err := io.ReadAll(resp.Body); err != nil || string(body) != "ok" {
		t.Fatalf("ordinary chunked response failed: %q %v", body, err)
	}
}

func TestResponseBodyLimitAtExactBoundary(t *testing.T) {
	for _, n := range []int{3, 4} {
		resp := &http.Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: 200, ContentLength: -1}
		body := &guardedBody{ReadCloser: io.NopCloser(strings.NewReader(strings.Repeat("x", n))), response: resp, remaining: 3}
		got, err := io.ReadAll(body)
		if n == 3 && (err != nil || string(got) != "xxx") || n == 4 && err == nil {
			t.Fatalf("length %d: %q %v", n, got, err)
		}
	}
}
