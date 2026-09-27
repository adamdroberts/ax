// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// responseConn validates bounded plaintext HTTP framing before net/http can
// normalize it. Bodies stream without full buffering; validated hop-by-hop chunk
// extensions are removed before downstream decoding. Connections are never reused.
type responseConn struct {
	net.Conn
	reader            *bufio.Reader
	pending           []byte
	finalHeaders      bool
	informational     int
	headerBytes       int
	headerFields      int
	failed            error
	method            string
	bodyState         bodyState
	bodyRemaining     int64
	bodyBytes         int64
	bodyLimit         int64
	chunks            int
	extensionBytes    int
	chunkFramingBytes int
}

func newResponseConn(conn net.Conn, method string) *responseConn {
	return &responseConn{Conn: conn, reader: bufio.NewReaderSize(conn, 4096), method: method, bodyLimit: MaxResponseBodyBytes}
}

func (c *responseConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.failed != nil {
		return 0, c.failed
	}
	if len(c.pending) == 0 && !c.finalHeaders {
		block, final, err := c.readHeaderBlock()
		if err != nil {
			c.failed = err
			return 0, err
		}
		c.pending, c.finalHeaders = block, final
	}
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	n, err := c.readBody(p)
	if err != nil && err != io.EOF {
		c.failed = err
	}
	return n, err
}

func (c *responseConn) readLine() ([]byte, error) {
	var line []byte
	for {
		fragment, err := c.reader.ReadSlice('\n')
		if len(line)+len(fragment) > 8192 || c.headerBytes+len(fragment) > MaxResponseHeaderBytes {
			return nil, fmt.Errorf("response wire headers exceed limits")
		}
		c.headerBytes += len(fragment)
		line = append(line, fragment...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("incomplete response header line: %w", err)
		}
		if len(line) < 2 || line[len(line)-2] != '\r' {
			return nil, fmt.Errorf("response headers require CRLF line endings")
		}
		return line, nil
	}
}

func (c *responseConn) readHeaderBlock() ([]byte, bool, error) {
	line, err := c.readLine()
	if err != nil {
		return nil, false, err
	}
	statusLine := string(line[:len(line)-2])
	if len(statusLine) < 13 || !strings.HasPrefix(statusLine, "HTTP/1.1 ") || statusLine[12] != ' ' {
		return nil, false, fmt.Errorf("invalid HTTP/1.1 response status line")
	}
	for _, ch := range statusLine[9:12] {
		if ch < '0' || ch > '9' {
			return nil, false, fmt.Errorf("invalid response status code")
		}
	}
	status, _ := strconv.Atoi(statusLine[9:12])
	if status < 100 || status > 599 || status == 101 {
		return nil, false, fmt.Errorf("unsupported response status")
	}
	for _, ch := range []byte(statusLine[13:]) {
		if ch < 32 || ch > 126 {
			return nil, false, fmt.Errorf("invalid response reason phrase")
		}
	}
	final := status >= 200
	if !final {
		c.informational++
		if c.informational > 4 || (status != 100 && status != 102 && status != 103) {
			return nil, false, fmt.Errorf("unsupported or excessive informational responses")
		}
	}
	block := append([]byte(nil), line...)
	framing := map[string]bool{}
	metadata := responseMetadata{}
	contentLength := int64(-1)
	bodyless := c.method == "HEAD" || status == 204 || status == 304
	for {
		line, err := c.readLine()
		if err != nil {
			return nil, false, err
		}
		block = append(block, line...)
		if len(line) == 2 {
			break
		}
		c.headerFields++
		if c.headerFields > MaxResponseHeaders {
			return nil, false, fmt.Errorf("too many response header fields")
		}
		field := string(line[:len(line)-2])
		name, rawValue, found := strings.Cut(field, ":")
		if !found || !headerToken(name) {
			return nil, false, fmt.Errorf("invalid or folded response header field")
		}
		for _, ch := range []byte(rawValue) {
			if ch < 32 || ch > 126 {
				return nil, false, fmt.Errorf("invalid response header bytes")
			}
		}
		name, value := strings.ToLower(name), strings.Trim(rawValue, " ")
		if err := metadata.add(name, value); err != nil {
			return nil, false, err
		}
		switch name {
		case "content-length", "transfer-encoding", "content-encoding":
			if framing[name] {
				return nil, false, fmt.Errorf("duplicate response framing or encoding field")
			}
			framing[name] = true
			if name == "content-length" {
				n, err := strconv.ParseUint(value, 10, 63)
				if err != nil || strconv.FormatUint(n, 10) != value || !bodyless && n > MaxResponseBodyBytes || status == 205 && n != 0 {
					return nil, false, fmt.Errorf("invalid or oversized response Content-Length")
				}
				contentLength = int64(n)
			} else if name == "transfer-encoding" && !strings.EqualFold(value, "chunked") {
				return nil, false, fmt.Errorf("unsupported response transfer encoding")
			} else if name == "content-encoding" && !strings.EqualFold(value, "identity") {
				return nil, false, fmt.Errorf("encoded response bodies are not allowed")
			}
		case "upgrade", "trailer", "http2-settings", "content-transfer-encoding":
			return nil, false, fmt.Errorf("response upgrades and trailers are not allowed")
		}
	}
	if framing["content-length"] && framing["transfer-encoding"] || (!final || status == 204) && (framing["content-length"] || framing["transfer-encoding"]) {
		return nil, false, fmt.Errorf("conflicting or forbidden response framing")
	}
	if final {
		if status == 205 {
			// 205 permits ordinary framing but must not contain content (RFC 9110).
			c.bodyLimit = 0
		}
		switch {
		case bodyless:
			c.bodyState = bodyDone
		case framing["transfer-encoding"]:
			c.bodyState = bodyChunkSize
		case framing["content-length"]:
			c.bodyState, c.bodyRemaining = bodyFixed, contentLength
		default:
			c.bodyState = bodyUntilClose
		}
	}
	return block, final, nil
}
