package egress

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
)

type digestCase struct {
	Name, Method   string
	RequestHeaders map[string]string `json:"request_headers"`
	Body           []byte            `json:"body_base64"`
	Wire           []byte            `json:"wire_base64"`
	Accepted       bool
}

func TestContentDigestBoundedStreaming(t *testing.T) {
	body := bytes.Repeat([]byte("x"), MaxResponseBodyBytes)
	smallHash, largeHash := sha256.Sum256(body), sha512.Sum512(body)
	value := "sha-256=:" + base64.StdEncoding.EncodeToString(smallHash[:]) + ":, sha-512=:" + base64.StdEncoding.EncodeToString(largeHash[:]) + ":"
	for _, size := range []int{1, 8193, 65536} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			d, err := responseDigests(http.Header{"Content-Digest": []string{value}})
			if err != nil {
				t.Fatal(err)
			}
			resp := &http.Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: 200, Header: http.Header{"Content-Digest": []string{value}}, ContentLength: int64(len(body))}
			guard := &guardedBody{ReadCloser: io.NopCloser(bytes.NewReader(body)), response: resp, remaining: MaxResponseBodyBytes, digest: d.Checker()}
			buffer := make([]byte, size)
			count := 0
			for {
				n, err := guard.Read(buffer)
				count += n
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if count != len(body) {
				t.Fatal("maximum content was truncated")
			}
		})
	}
	t.Run("altered-last-byte", func(t *testing.T) {
		body[len(body)-1] = 'y'
		resp := &http.Response{Header: http.Header{"Content-Digest": []string{value}}}
		if err := CheckResponseBody(resp, "GET", body); err == nil {
			t.Fatal("altered final byte admitted")
		}
	})
	t.Run("oversize-before-hashing", func(t *testing.T) {
		resp := &http.Response{Header: http.Header{"Content-Digest": []string{value}}}
		if err := CheckResponseBody(resp, "GET", append(body, 'x')); err == nil {
			t.Fatal("oversized content admitted")
		}
	})
}

func TestContentDigestEmptyParsedValues(t *testing.T) {
	resp := &http.Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: 200, Header: http.Header{"Content-Digest": nil}}
	if err := CheckResponse(resp); err == nil {
		t.Fatal("empty internal field list admitted")
	}
	if err := CheckResponseBody(resp, "GET", nil); err == nil {
		t.Fatal("empty field list bypassed body admission")
	}
}

func TestContentDigestWireAndBody(t *testing.T) {
	data, err := os.ReadFile("testdata/content_digest_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct{ Cases []digestCase }
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), pipeResponse(string(tc.Wire), nil))
			req, _ := http.NewRequest(tc.Method, "http://api.example.com/digest", nil)
			for name, value := range tc.RequestHeaders {
				req.Header.Set(name, value)
			}
			resp, err := client.Do(req)
			var body []byte
			if err == nil {
				defer resp.Body.Close()
				body, err = io.ReadAll(resp.Body)
			}
			if (err == nil) != tc.Accepted {
				t.Fatalf("accepted=%v want=%v error=%v", err == nil, tc.Accepted, err)
			}
			if tc.Accepted {
				if !bytes.Equal(body, tc.Body) {
					t.Fatal("accepted content changed")
				}
				if err := CheckResponseBody(resp, tc.Method, body); err != nil {
					t.Fatalf("complete body: %v", err)
				}
			} else if resp != nil {
				// A failed integrity check must remain a failure on subsequent reads.
				if _, again := resp.Body.Read(make([]byte, 1)); again == nil || again == io.EOF {
					t.Fatal("integrity failure was not sticky")
				}
			}
		})
	}
}
