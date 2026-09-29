package egress

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestXMLResponses(t *testing.T) {
	data, err := os.ReadFile("testdata/xml_response_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name     string
			Document []byte `json:"document_base64"`
			Accepted bool
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		for _, layout := range []string{"ordinary", "single", "multipart"} {
			if layout != "ordinary" && len(tc.Document) < 2 {
				continue
			}
			t.Run(tc.Name+"/"+layout, func(t *testing.T) {
				wire, body, headers := xmlResponseWire(tc.Document, layout)
				client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), pipeResponse(wire, nil))
				req, _ := http.NewRequest("GET", "http://api.example.com/xml", nil)
				for key, value := range headers {
					req.Header.Set(key, value)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal("XML fixture failed before body validation", err)
				}
				actual, err := io.ReadAll(resp.Body)
				if err == nil {
					err = CheckResponseBody(resp, "GET", actual)
				}
				resp.Body.Close()
				if (err == nil) != tc.Accepted {
					t.Fatalf("accepted=%v want=%v error=%v", err == nil, tc.Accepted, err)
				}
				if !bytes.Equal(actual, body) {
					t.Fatal("response bytes changed or consumed bytes were lost")
				}
			})
		}
	}
}

func xmlResponseWire(document []byte, layout string) (string, []byte, map[string]string) {
	status, fields, body := 200, "Content-Type: application/xml\r\n", document
	headers := map[string]string{}
	if layout != "ordinary" {
		status, headers["Range"] = 206, "bytes=0-"
		fields += fmt.Sprintf("Content-Range: bytes 0-%d/%d\r\n", len(document)-1, len(document))
	}
	if layout == "multipart" {
		cut := len(document) / 2
		for document[cut]&0xc0 == 0x80 {
			cut++
		}
		var out bytes.Buffer
		for i, part := range [][]byte{document[:cut], document[cut:]} {
			first := 0
			if i == 1 {
				first = cut
			}
			fmt.Fprintf(&out, "--xmlparts\r\nContent-Type: application/xml\r\nContent-Range: bytes %d-%d/%d\r\n\r\n", first, first+len(part)-1, len(document))
			out.Write(part)
			out.WriteString("\r\n")
		}
		out.WriteString("--xmlparts--\r\n")
		body, fields, headers["Range"] = out.Bytes(), "Content-Type: multipart/byteranges; boundary=xmlparts\r\n", "bytes=0-0,1-"
	}
	return fmt.Sprintf("HTTP/1.1 %d OK\r\n%sContent-Length: %d\r\n\r\n%s", status, fields, len(body), body), body, headers
}

func TestXMLResponseSelection(t *testing.T) {
	data, err := os.ReadFile("testdata/xml_response_flow_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name, Method string
			Accepted     bool
			Headers      map[string]string `json:"request_headers"`
			Wire         []byte            `json:"wire_base64"`
			Body         []byte            `json:"body_base64"`
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), pipeResponse(string(tc.Wire), nil))
			req, _ := http.NewRequest(tc.Method, "http://api.example.com/xml", nil)
			for k, v := range tc.Headers {
				req.Header.Set(k, v)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal("fixture failed before body checks", err)
			}
			actual, err := io.ReadAll(resp.Body)
			if err == nil {
				err = CheckResponseBody(resp, tc.Method, actual)
			}
			resp.Body.Close()
			if (err == nil) != tc.Accepted {
				t.Fatalf("accepted=%v want=%v error=%v", err == nil, tc.Accepted, err)
			}
			if !bytes.Equal(actual, tc.Body) {
				t.Fatal("response content changed or consumed bytes lost")
			}
		})
	}
}

func TestXMLLargeDocuments(t *testing.T) {
	for _, tc := range []struct{ name, prefix, suffix string }{{"text", "<r>", "</r>"}, {"cdata", "<r><![CDATA[", "]]></r>"}} {
		document := []byte(tc.prefix + strings.Repeat("a", MaxResponseBodyBytes-len(tc.prefix)-len(tc.suffix)) + tc.suffix)
		t.Run(tc.name+"/valid", func(t *testing.T) {
			if err := checkResponseXML(document); err != nil {
				t.Fatal(err)
			}
		})
		document[len(document)-1] = '!'
		t.Run(tc.name+"/invalid", func(t *testing.T) {
			if err := checkResponseXML(document); err == nil {
				t.Fatal("invalid final delimiter admitted")
			}
		})
	}
	t.Run("oversized", func(t *testing.T) {
		if err := checkResponseXML(bytes.Repeat([]byte{'x'}, MaxResponseBodyBytes+1)); err == nil {
			t.Fatal("oversized XML admitted")
		}
	})
}
