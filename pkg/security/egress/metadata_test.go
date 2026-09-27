package egress

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
)

type metadataCorpus struct {
	Version                     int      `json:"version"`
	ProtectedConnectionNames    []string `json:"protected_connection_names"`
	ProtectedConnectionPrefixes []string `json:"protected_connection_prefixes"`
	Singletons                  []string `json:"singletons"`
	MaxParts                    int      `json:"max_parts"`
	Cases                       []struct {
		Name     string      `json:"name"`
		Headers  [][2]string `json:"headers"`
		Accepted bool        `json:"accepted"`
	} `json:"cases"`
}

func TestSharedResponseMetadataContract(t *testing.T) {
	data, err := os.ReadFile("testdata/response_metadata_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus metadataCorpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Version != 1 || len(corpus.Cases) != 114 || corpus.MaxParts != MaxResponseMetadataParts {
		t.Fatalf("unexpected metadata corpus contract: version=%d cases=%d parts=%d", corpus.Version, len(corpus.Cases), corpus.MaxParts)
	}
	if !reflect.DeepEqual(headerSet(strings.Join(corpus.ProtectedConnectionNames, " ")), protectedConnectionNames) {
		t.Fatal("protected Connection names differ from the cross-runtime contract")
	}
	if !reflect.DeepEqual(corpus.ProtectedConnectionPrefixes, protectedConnectionPrefixes) {
		t.Fatal("protected Connection prefixes differ from the cross-runtime contract")
	}
	if !reflect.DeepEqual(headerSet(strings.Join(corpus.Singletons, " ")), responseSingletons) {
		t.Fatal("singleton fields differ from the cross-runtime contract")
	}
	for _, test := range corpus.Cases {
		t.Run(test.Name, func(t *testing.T) {
			metadata := responseMetadata{}
			var metadataErr error
			response := &http.Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: 200, ContentLength: -1, Header: http.Header{}}
			for _, header := range test.Headers {
				if metadataErr == nil {
					metadataErr = metadata.add(header[0], header[1])
				}
				response.Header.Add(header[0], header[1])
			}
			if (metadataErr == nil) != test.Accepted {
				t.Fatalf("metadata accepted=%v want=%v error=%v", metadataErr == nil, test.Accepted, metadataErr)
			}
			if err := CheckResponse(response); (err == nil) != test.Accepted {
				t.Fatalf("parsed guard accepted=%v want=%v error=%v", err == nil, test.Accepted, err)
			}
		})
	}
}

func TestMetadataRejectedOnFinalAndInformationalWireBlocks(t *testing.T) {
	for name, fields := range map[string]string{
		"framing nomination":       "Connection: content-length\r\n",
		"authorization nomination": "Connection: Authorization\r\nAuthorization: Bearer opaque\r\n",
		"invalid connection token": "Connection: \"close\"\r\n",
		"duplicate media type":     "Content-Type: text/plain\r\ncontent-type: application/json\r\n",
		"duplicate location":       "Location: /one\r\nLocation: /two\r\n",
		"duplicate date":           "Date: Sat, 26 Sep 2026 17:00:00 GMT\r\nDate: Sat, 26 Sep 2026 17:00:00 GMT\r\n",
		"combined media types":     "Content-Type: text/plain,application/json\r\n",
		"unsupported charset":      "Content-Type: text/plain; charset=utf-16\r\n",
		"duplicate media param":    "Content-Type: text/plain; charset=utf-8; CHARSET=utf-8\r\n",
		"extended media param":     "Content-Type: text/plain; charset*=utf-8''UTF-8\r\n",
		"parameter whitespace":     "Content-Type: text/plain; charset =utf-8\r\n",
	} {
		for _, interim := range []bool{false, true} {
			stage := "final/"
			wire := "HTTP/1.1 200 OK\r\n" + fields + "Content-Length: 2\r\n\r\nok"
			if interim {
				stage = "interim/"
				wire = "HTTP/1.1 103 Early Hints\r\n" + fields + "\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
			}
			t.Run(stage+name, func(t *testing.T) {
				client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), pipeResponse(wire, nil))
				response, err := client.Get("http://api.example.com")
				if response != nil {
					response.Body.Close()
				}
				if err == nil {
					t.Fatal("malformed metadata reached the body consumer")
				}
			})
		}
	}
}

func TestBenignMetadataAndExtensionOptionsPreservedOnWire(t *testing.T) {
	wire := "HTTP/1.1 103 Early Hints\r\nContent-Type: text/plain; title=\"hint;one,two\"\r\nConnection: x-early,,\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nConnection: close,, x-extension\r\nConnection: keep-alive\r\n" +
		"Content-Type: application/octet-stream; title=\"comma,semicolon;ok\"; charset=\"UTF-8\";;\r\n" +
		"WWW-Authenticate: Basic realm=\"one\"\r\nWWW-Authenticate: Bearer realm=\"two\"\r\n" +
		"Cache-Control: private\r\nCache-Control: max-age=0\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: 2\r\n\r\nok"
	client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), pipeResponse(wire, nil))
	response, err := client.Get("http://api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if body, err := io.ReadAll(response.Body); err != nil || string(body) != "ok" {
		t.Fatalf("body=%q error=%v", body, err)
	}
	for _, name := range []string{"Www-Authenticate", "Cache-Control", "Set-Cookie"} {
		if len(response.Header.Values(name)) != 2 {
			t.Fatalf("repeated field %s was lost: %v", name, response.Header.Values(name))
		}
	}
}

func TestParsedGuardRejectsNoncanonicalLengthsAndOversizedMedia(t *testing.T) {
	for _, value := range []string{"+2", "02"} {
		response := &http.Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: 200, ContentLength: 2, Header: http.Header{"Content-Length": {value}}}
		if err := CheckResponse(response); err == nil {
			t.Errorf("noncanonical parsed Content-Length %q accepted", value)
		}
	}
	if err := checkResponseContentType("text/plain;title=" + strings.Repeat("a", 8192)); err == nil {
		t.Fatal("unbounded direct media field accepted")
	}
}
