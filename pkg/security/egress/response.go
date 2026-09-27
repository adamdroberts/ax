// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const (
	MaxResponseHeaderBytes = 64 << 10
	MaxResponseHeaders     = 128
	MaxResponseBodyBytes   = 10 << 20
)

// CheckResponse checks the parsed response representation. net/http has already
// parsed the wire headers; this is not a claim to validate every wire-level HTTP
// ambiguity. Announced trailers, upgrades, compression, and HTTP/2 are rejected.
func CheckResponse(resp *http.Response) error {
	if resp == nil || resp.ProtoMajor != 1 || resp.ProtoMinor != 1 || resp.StatusCode < 200 || resp.StatusCode > 599 {
		return fmt.Errorf("unsupported outbound response protocol or status")
	}
	bodyless := resp.StatusCode == 204 || resp.StatusCode == 304 || resp.Request != nil && resp.Request.Method == "HEAD"
	if resp.StatusCode == 205 && resp.ContentLength > 0 {
		return fmt.Errorf("205 responses must not contain content")
	}
	if resp.Uncompressed || len(resp.Trailer) > 0 || !bodyless && resp.ContentLength > MaxResponseBodyBytes || resp.ContentLength < -1 {
		return fmt.Errorf("unsupported outbound response encoding, trailers, or length")
	}
	if len(resp.TransferEncoding) > 1 || len(resp.TransferEncoding) == 1 && resp.TransferEncoding[0] != "chunked" {
		return fmt.Errorf("unsupported outbound response transfer encoding")
	}
	if len(resp.TransferEncoding) > 0 && (!bodyless && resp.ContentLength >= 0 || resp.StatusCode == 204) {
		return fmt.Errorf("conflicting response body lengths")
	}
	count, size := 0, 0
	seen := map[string]bool{}
	metadata := responseMetadata{}
	for key, values := range resp.Header {
		name := strings.ToLower(key)
		if !headerToken(key) || seen[name] {
			return fmt.Errorf("invalid or duplicate response header name")
		}
		seen[name] = true
		for _, value := range values {
			count++
			size += len(key) + len(value) + 4
			if len(key)+len(value)+4 > 8192 {
				return fmt.Errorf("response header field exceeds limit")
			}
			for _, c := range value {
				if c < 32 || c > 126 {
					return fmt.Errorf("invalid response header value")
				}
			}
			if err := metadata.add(name, strings.Trim(value, " ")); err != nil {
				return err
			}
		}
		switch name {
		case "content-encoding":
			if len(values) != 1 || !strings.EqualFold(strings.TrimSpace(values[0]), "identity") {
				return fmt.Errorf("encoded response bodies are not allowed")
			}
		case "content-length":
			if len(values) != 1 {
				return fmt.Errorf("duplicate response Content-Length")
			}
			n, err := strconv.ParseInt(values[0], 10, 64)
			if err != nil || n < 0 || strconv.FormatInt(n, 10) != values[0] || !bodyless && n != resp.ContentLength || resp.StatusCode == 204 || len(resp.TransferEncoding) > 0 {
				return fmt.Errorf("invalid response Content-Length")
			}
		case "trailer", "upgrade", "transfer-encoding", "http2-settings", "content-transfer-encoding":
			return fmt.Errorf("unsupported response framing header")
		}
	}
	if count > MaxResponseHeaders || size > MaxResponseHeaderBytes {
		return fmt.Errorf("response headers exceed limits")
	}
	return nil
}

func headerToken(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	return true
}

type guardedBody struct {
	io.ReadCloser
	response  *http.Response
	remaining int
	failed    error
}

func (b *guardedBody) Read(p []byte) (int, error) {
	if b.failed != nil {
		return 0, b.failed
	}
	if len(p) > b.remaining+1 {
		p = p[:b.remaining+1]
	}
	n, err := b.ReadCloser.Read(p)
	if n > b.remaining {
		b.failed = fmt.Errorf("response body exceeds limits")
		// Return consumed bytes with the error so the caller can account for its
		// cumulative input budget even though it must discard this response.
		return n, b.failed
	}
	b.remaining -= n
	if err == io.EOF {
		// Chunked trailers may become visible only after the final read.
		if checkErr := CheckResponse(b.response); checkErr != nil {
			b.failed = checkErr
			return n, checkErr
		}
	}
	return n, err
}
