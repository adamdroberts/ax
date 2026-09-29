package egress

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

type dispositionCase struct {
	Name     string
	Headers  [][2]string
	Accepted bool
}

func dispositionCases(t *testing.T) []dispositionCase {
	t.Helper()
	data, err := os.ReadFile("testdata/content_disposition_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct{ Cases []dispositionCase }
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	return corpus.Cases
}

func TestContentDispositionParsedContract(t *testing.T) {
	for _, tc := range dispositionCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			resp := &http.Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: 200,
				ContentLength: 2, Header: http.Header{}}
			for _, field := range tc.Headers {
				resp.Header.Add(field[0], field[1])
			}
			if err := CheckResponse(resp); (err == nil) != tc.Accepted {
				t.Fatalf("accepted=%v want=%v error=%v", err == nil, tc.Accepted, err)
			}
		})
	}
}

func TestContentDispositionWireContract(t *testing.T) {
	for _, tc := range dispositionCases(t) {
		var fields strings.Builder
		for _, field := range tc.Headers {
			fields.WriteString(field[0] + ": " + field[1] + "\r\n")
		}
		for _, stage := range []string{"final", "interim"} {
			t.Run(tc.Name+"/"+stage, func(t *testing.T) {
				wire := "HTTP/1.1 200 OK\r\n" + fields.String() + "Content-Length: 2\r\n\r\nok"
				if stage == "interim" {
					wire = "HTTP/1.1 103 Early Hints\r\n" + fields.String() + "\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
				}
				client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), pipeResponse(wire, nil))
				resp, err := client.Get("http://api.example.com/v1")
				if (err == nil) != tc.Accepted {
					if resp != nil {
						resp.Body.Close()
					}
					t.Fatalf("accepted=%v want=%v error=%v", err == nil, tc.Accepted, err)
				}
				if tc.Accepted {
					defer resp.Body.Close()
					body, err := io.ReadAll(resp.Body)
					if err != nil || string(body) != "ok" {
						t.Fatalf("accepted body changed: %q %v", body, err)
					}
				}
			})
		}
	}
}

func TestMIMEPartDispositionIsNotHTTPResponseDisposition(t *testing.T) {
	// RFC 6266 explicitly excludes fields inside MIME payloads. These remain
	// opaque part metadata, including RFC 2231 continuation syntax.
	for _, value := range []string{"attachment; filename*0*=UTF-8''report; filename*1*=.txt", "x-mime-extension; opaque"} {
		body := "--b\r\nContent-Range: bytes 0-0/1\r\nContent-Disposition: " + value + "\r\n\r\na\r\n--b--\r\n"
		if err := checkMultipartRanges([]byte(body), "b"); err != nil {
			t.Errorf("HTTP disposition rules applied to a MIME part: %v", err)
		}
	}
}
