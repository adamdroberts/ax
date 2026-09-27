// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
)

const (
	MaxChunkLineBytes      = 8192
	MaxResponseChunks      = 4096
	MaxChunkExtensionBytes = 64 << 10
	MaxChunkFramingBytes   = 192 << 10
)

type bodyState uint8

const (
	bodyDone bodyState = iota
	bodyFixed
	bodyUntilClose
	bodyChunkSize
	bodyChunkData
	bodyChunkCRLF
	bodyChunkEnd
)

// readBody preserves framing while checking each piece before giving it to the
// downstream decoder. Memory is limited to one chunk-size line plus read buffers.
func (c *responseConn) readBody(p []byte) (int, error) {
	for {
		switch c.bodyState {
		case bodyDone:
			return 0, io.EOF
		case bodyFixed, bodyChunkData:
			if c.bodyRemaining == 0 {
				if c.bodyState == bodyFixed {
					c.bodyState = bodyDone
				} else {
					c.bodyState = bodyChunkCRLF
				}
				continue
			}
			if int64(len(p)) > c.bodyRemaining {
				p = p[:int(c.bodyRemaining)]
			}
			n, err := c.reader.Read(p)
			c.bodyRemaining -= int64(n)
			if err == io.EOF {
				if c.bodyRemaining != 0 || c.bodyState == bodyChunkData {
					err = io.ErrUnexpectedEOF
				} else {
					c.bodyState = bodyDone
				}
			}
			return n, err
		case bodyUntilClose:
			left := c.bodyLimit - c.bodyBytes
			if int64(len(p)) > left+1 {
				p = p[:int(left+1)]
			}
			n, err := c.reader.Read(p)
			c.bodyBytes += int64(n)
			if c.bodyBytes > c.bodyLimit {
				return n, fmt.Errorf("response body exceeds limits")
			}
			if err == io.EOF {
				c.bodyState = bodyDone
			}
			return n, err
		case bodyChunkSize:
			line, err := c.readChunkLine()
			if err != nil {
				return 0, err
			}
			size, extBytes, err := parseChunkLine(line[:len(line)-2])
			if err != nil {
				return 0, err
			}
			c.extensionBytes += extBytes
			if c.extensionBytes > MaxChunkExtensionBytes {
				return 0, fmt.Errorf("chunk extensions exceed cumulative limit")
			}
			if size > uint64(c.bodyLimit)-uint64(c.bodyBytes) {
				return 0, fmt.Errorf("chunked response body exceeds limits")
			}
			if size == 0 {
				c.bodyState = bodyChunkEnd
			} else {
				c.chunks++
				if c.chunks > MaxResponseChunks {
					return 0, fmt.Errorf("chunk count exceeds limit")
				}
				c.bodyBytes += int64(size)
				c.bodyState, c.bodyRemaining = bodyChunkData, int64(size)
			}
			// RFC 9112 permits removing hop-by-hop chunk extensions. Normalize
			// only after validation, preserving all content octets unchanged.
			c.pending = []byte(strconv.FormatUint(size, 16) + "\r\n")
			return c.copyPending(p), nil
		case bodyChunkCRLF:
			var ending [2]byte
			if _, err := io.ReadFull(c.reader, ending[:]); err != nil {
				return 0, fmt.Errorf("truncated chunk data terminator: %w", io.ErrUnexpectedEOF)
			}
			if ending != [2]byte{'\r', '\n'} {
				return 0, fmt.Errorf("chunk data requires CRLF terminator")
			}
			c.chunkFramingBytes += 2
			if c.chunkFramingBytes > MaxChunkFramingBytes {
				return 0, fmt.Errorf("chunk framing exceeds cumulative limit")
			}
			c.bodyState, c.pending = bodyChunkSize, []byte("\r\n")
			return c.copyPending(p), nil
		case bodyChunkEnd:
			line, err := c.readChunkLine()
			if err != nil {
				return 0, err
			}
			if len(line) != 2 {
				return 0, fmt.Errorf("response trailers are not allowed")
			}
			c.bodyState, c.pending = bodyDone, []byte("\r\n")
			return c.copyPending(p), nil
		default:
			return 0, fmt.Errorf("invalid response body framing state")
		}
	}
}

func (c *responseConn) copyPending(p []byte) int {
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n
}

func (c *responseConn) readChunkLine() ([]byte, error) {
	var line []byte
	for {
		fragment, err := c.reader.ReadSlice('\n')
		c.chunkFramingBytes += len(fragment)
		if len(line)+len(fragment) > MaxChunkLineBytes || c.chunkFramingBytes > MaxChunkFramingBytes {
			return nil, fmt.Errorf("chunk line exceeds limit")
		}
		line = append(line, fragment...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("truncated chunk line: %w", io.ErrUnexpectedEOF)
		}
		if len(line) < 2 || line[len(line)-2] != '\r' {
			return nil, fmt.Errorf("chunk lines require CRLF terminators")
		}
		return line, nil
	}
}

// parseChunkLine follows RFC 9112 section 7.1.1 and the quoted-string grammar
// from RFC 9110 section 5.6.4. Extensions are opaque connection metadata; obs-text
// is permitted there by the RFC, while CR, LF, NUL, and DEL are never accepted.
func parseChunkLine(line []byte) (uint64, int, error) {
	i := 0
	for i < len(line) && hexDigit(line[i]) {
		i++
	}
	if i == 0 {
		return 0, 0, fmt.Errorf("chunk size must contain hexadecimal digits")
	}
	size, err := strconv.ParseUint(string(line[:i]), 16, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("chunk size overflows supported integer range")
	}
	extBytes := len(line) - i
	for i < len(line) {
		for i < len(line) && bws(line[i]) {
			i++
		}
		if i == len(line) || line[i] != ';' {
			return 0, 0, fmt.Errorf("invalid chunk extension delimiter")
		}
		i++
		for i < len(line) && bws(line[i]) {
			i++
		}
		start := i
		for i < len(line) && tokenByte(line[i]) {
			i++
		}
		if i == start {
			return 0, 0, fmt.Errorf("empty or invalid chunk extension name")
		}
		afterName := i
		for i < len(line) && bws(line[i]) {
			i++
		}
		if i == len(line) || line[i] != '=' {
			// BWS belongs to a following delimiter, not the end of a line.
			i = afterName
			continue
		}
		i++
		for i < len(line) && bws(line[i]) {
			i++
		}
		if i < len(line) && line[i] == '"' {
			i++
			closed := false
			for i < len(line) {
				ch := line[i]
				i++
				if ch == '"' {
					closed = true
					break
				}
				if ch == '\\' {
					if i == len(line) || !quotedByte(line[i]) {
						return 0, 0, fmt.Errorf("invalid quoted chunk extension escape")
					}
					i++
				} else if !quotedByte(ch) {
					return 0, 0, fmt.Errorf("invalid quoted chunk extension byte")
				}
			}
			if !closed {
				return 0, 0, fmt.Errorf("unterminated quoted chunk extension")
			}
		} else {
			start = i
			for i < len(line) && tokenByte(line[i]) {
				i++
			}
			if i == start {
				return 0, 0, fmt.Errorf("empty or invalid chunk extension value")
			}
		}
	}
	return size, extBytes, nil
}

func hexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
func bws(c byte) bool        { return c == ' ' || c == '\t' }
func quotedByte(c byte) bool { return c == '\t' || c >= 32 && c != 127 }
func tokenByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~'
}
