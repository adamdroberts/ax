package egress

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestChunkExtensionRFCGrammar(t *testing.T) {
	valid := []string{
		"2", "0002", "A;name", "2;name=value;other=next", `2;quoted=""`, `2;quoted="one;two=three"`,
		"2 \t; \tname \t= \tvalue;flag", "2;name=\"a\" \t;next=token", "2;quoted=\"a\\\"b\\\\c\"",
		"2;quoted=\"\t\x80\\\xff\"", "0;signature=complete",
	}
	for _, line := range valid {
		if _, _, err := parseChunkLine([]byte(line)); err != nil {
			t.Errorf("valid chunk extension %q rejected: %v", line, err)
		}
	}
	for _, line := range []string{
		"", " 2", "+2", "0x2", "2 ", "2\t", "2;", "2;=v", "2;;flag", "2;name=", "2;name= ",
		"2;name value", "2;name=v other", "2;name=v ", "2;name=\"v\"junk", "2;name=\"v\" ",
		"2;name=\"unterminated", "2;name=\"bad\\\"", "2;name=\"bad\r\"", "2;name=\"bad\n\"", "2;name=\"bad\x00\"", "2;name=\"bad\x7f\"", "2;name=\"bad\\\r\"", "2;\x80=v", "2;name=\xff", "10000000000000000",
	} {
		if _, _, err := parseChunkLine([]byte(line)); err == nil {
			t.Errorf("invalid chunk extension %q accepted", line)
		}
	}
}

func chunkResponse(t *testing.T, wireBody string) ([]byte, error) {
	t.Helper()
	wire := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + wireBody
	client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), pipeResponse(wire, nil))
	resp, err := client.Get("http://api.example.com")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func TestChunkWireGrammarAndTruncation(t *testing.T) {
	for _, body := range []string{
		"2\r\nok\r\n0\r\n\r\n", "2;flag;quoted=\"x;y=z\"\r\nok\r\n00;done=yes\r\n\r\n", "2 \t; \tname \t= \tvalue\r\nok\r\n0\r\n\r\n",
		"2;name=\"\x80\\\xff\"\r\nok\r\n0\r\n\r\n",
	} {
		got, err := chunkResponse(t, body)
		if err != nil || string(got) != "ok" {
			t.Errorf("valid body %q: %q %v", body, got, err)
		}
	}
	for name, body := range map[string]string{
		"bare LF size":             "2\nok\r\n0\r\n\r\n",
		"bare CR size":             "2\rX\nok\r\n0\r\n\r\n",
		"bad data ending":          "2\r\nok\n0\r\n\r\n",
		"missing data ending":      "2\r\nok",
		"truncated data":           "3\r\nok",
		"truncated size":           "2",
		"missing zero chunk":       "2\r\nok\r\n",
		"missing terminal blank":   "2\r\nok\r\n0\r\n",
		"truncated terminal blank": "2\r\nok\r\n0\r\n\r",
		"bare LF terminal blank":   "2\r\nok\r\n0\r\n\n",
		"unexpected trailer":       "2\r\nok\r\n0\r\nX-Trailer: hidden\r\n\r\n",
		"invalid extension":        "2;bad=\r\nok\r\n0\r\n\r\n",
		"oversized chunk":          "a00001\r\n",
		"overflow":                 "10000000000000000\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := chunkResponse(t, body); err == nil {
				t.Fatal("invalid chunk framing accepted")
			}
		})
	}
}

func TestChunkBudgetsAndLongValidExtensions(t *testing.T) {
	maxLine := "1;x=" + strings.Repeat("a", MaxChunkLineBytes-len("1;x=\r\n")) + "\r\nx\r\n0\r\n\r\n"
	if body, err := chunkResponse(t, maxLine); err != nil || string(body) != "x" {
		t.Fatalf("bounded8KiBextension rejected: %v", err)
	}
	tooLong := "1;x=" + strings.Repeat("a", MaxChunkLineBytes) + "\r\nx\r\n0\r\n\r\n"
	if _, err := chunkResponse(t, tooLong); err == nil {
		t.Fatal("oversized chunk line accepted")
	}
	for _, n := range []int{MaxResponseChunks, MaxResponseChunks + 1} {
		body, err := chunkResponse(t, strings.Repeat("1\r\nx\r\n", n)+"0\r\n\r\n")
		if n == MaxResponseChunks && (err != nil || len(body) != n) || n > MaxResponseChunks && err == nil {
			t.Fatalf("chunkcount%d len%d err%v", n, len(body), err)
		}
	}
	ext := ";x=" + strings.Repeat("a", 8000)
	for _, n := range []int{8, 9} {
		body, err := chunkResponse(t, strings.Repeat("1"+ext+"\r\nx\r\n", n)+"0\r\n\r\n")
		if n == 8 && (err != nil || len(body) != n) || n == 9 && err == nil {
			t.Fatalf("extensionbudget n%d len%d err%v", n, len(body), err)
		}
	}
	// Leading zeroes consume framing resources too, even with no extensions.
	longDigits := strings.Repeat("0", MaxChunkLineBytes-3) + "1\r\nx\r\n"
	if _, err := chunkResponse(t, strings.Repeat(longDigits, 25)+"0\r\n\r\n"); err == nil {
		t.Fatal("cumulative framing budget ignored")
	}
}

func TestBodylessAndFixedLengthResponseHandling(t *testing.T) {
	for _, tc := range []struct {
		method, status, headers, body string
		bad                           bool
	}{
		{"HEAD", "200 OK", "Content-Length: 999999999999\r\n", "", false},
		{"HEAD", "200 OK", "Transfer-Encoding: chunked\r\n", "", false},
		{"GET", "304 Not Modified", "Content-Length: 999999999999\r\n", "", false},
		{"GET", "304 Not Modified", "Transfer-Encoding: chunked\r\n", "", false},
		{"GET", "204 No Content", "", "", false},
		{"GET", "204 No Content", "Content-Length: 0\r\n", "", true},
		{"GET", "204 No Content", "Transfer-Encoding: chunked\r\n", "", true},
		{"GET", "205 Reset Content", "Content-Length: 0\r\n", "", false},
		{"GET", "205 Reset Content", "Content-Length: 1\r\n", "x", true},
		{"GET", "205 Reset Content", "", "", false},
		{"GET", "205 Reset Content", "", "x", true},
		{"GET", "200 OK", "Content-Length: 4\r\n", "abc", true},
		{"GET", "200 OK", "Content-Length: 3\r\n", "abc", false},
		{"GET", "200 OK", "", "abc", false},
	} {
		t.Run(fmt.Sprintf("%s/%s/%s", tc.method, tc.status, tc.headers), func(t *testing.T) {
			client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), pipeResponse("HTTP/1.1 "+tc.status+"\r\n"+tc.headers+"\r\n"+tc.body, nil))
			req, _ := http.NewRequest(tc.method, "http://api.example.com", nil)
			resp, err := client.Do(req)
			var got []byte
			if err == nil {
				got, err = io.ReadAll(resp.Body)
				resp.Body.Close()
			}
			if (err != nil) != tc.bad {
				t.Fatalf("body%q err%v bad%v", got, err, tc.bad)
			}
			if !tc.bad && string(got) != tc.body {
				t.Fatalf("body=%q want=%q", got, tc.body)
			}
		})
	}
}

func TestResetContentAllowsOnlyEmptyChunkedBody(t *testing.T) {
	for _, body := range []string{"0\r\n\r\n", "1\r\nx\r\n0\r\n\r\n"} {
		client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), pipeResponse("HTTP/1.1 205 Reset Content\r\nTransfer-Encoding: chunked\r\n\r\n"+body, nil))
		resp, err := client.Get("http://api.example.com")
		if err == nil {
			_, err = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		if (err == nil) != strings.HasPrefix(body, "0") {
			t.Fatalf("205 body %q err=%v", body, err)
		}
	}
}

func TestChunkBodyStreamsWithoutBufferingCompleteChunk(t *testing.T) {
	finished := make(chan struct{})
	client := newClient(mustPolicy(t, "http://api.example.com"), fakeDNS("8.8.8.8"), func(context.Context, string, string) (net.Conn, error) {
		c, s := net.Pipe()
		go func() {
			defer s.Close()
			s.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := http.ReadRequest(bufio.NewReader(s)); err != nil {
				return
			}
			io.WriteString(s, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n100000\r\nx")
			<-finished
		}()
		return c, nil
	})
	defer close(finished)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://api.example.com", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var one [1]byte
	if _, err := io.ReadFull(resp.Body, one[:]); err != nil || one[0] != 'x' {
		t.Fatalf("first byte unavailable before rest of chunk: %q %v", one, err)
	}
}

func FuzzChunkExtensionGrammar(f *testing.F) {
	for _, s := range []string{"2", `2;foo="bar"`, "0;end", "2 \t;foo=bar", "2;foo=\"\x80\"", "2;foo=\"bad\\\r\""} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		if len(line) <= MaxChunkLineBytes {
			_, _, _ = parseChunkLine(line)
		}
	})
}
