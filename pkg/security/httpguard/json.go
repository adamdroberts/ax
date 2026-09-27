// Package httpguard defines the conservative protocol subset accepted at the
// agent tool boundary. It is deliberately separate from raw signature analysis.
package httpguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"unicode/utf8"
)

const MaxJSONDepth = 64
const MaxJSONTokens = 100000

// ValidateJSON rejects parser differentials permitted by ordinary JSON decoders:
// duplicate decoded keys, replacement of invalid Unicode, and nonfinite numbers.
// Depth/token limits are local policy; Unicode/unique names follow I-JSON.
func ValidateJSON(data []byte) error {
	if !utf8.Valid(data) || !json.Valid(data) {
		return fmt.Errorf("invalid UTF-8 JSON")
	}
	// encoding/json replaces lone UTF-16 surrogate escapes with U+FFFD. Check
	// the original escapes before decoding so that substitution cannot hide data.
	for i := 0; i < len(data); i++ {
		if data[i] != '"' {
			continue
		}
		i++
		for i < len(data) && data[i] != '"' {
			if data[i] != '\\' {
				i++
				continue
			}
			i++
			if data[i] != 'u' {
				i++
				continue
			}
			n, _ := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
			i += 5
			if n >= 0xdc00 && n <= 0xdfff {
				return fmt.Errorf("unpaired JSON surrogate")
			}
			if n >= 0xd800 && n <= 0xdbff {
				if i+6 > len(data) || data[i] != '\\' || data[i+1] != 'u' {
					return fmt.Errorf("unpaired JSON surrogate")
				}
				low, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 16)
				if err != nil || low < 0xdc00 || low > 0xdfff {
					return fmt.Errorf("unpaired JSON surrogate")
				}
				i += 6
			}
		}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	count := 0
	if err := jsonValue(dec, 0, &count); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

func validUnicode(s string) bool {
	for _, r := range s {
		if r >= 0xfdd0 && r <= 0xfdef || r&0xffff == 0xfffe || r&0xffff == 0xffff {
			return false
		}
	}
	return true
}

func jsonValue(dec *json.Decoder, depth int, count *int) error {
	if depth > MaxJSONDepth {
		return fmt.Errorf("JSON nesting exceeds policy limit")
	}
	*count++
	if *count > MaxJSONTokens {
		return fmt.Errorf("JSON token count exceeds policy limit")
	}
	token, err := dec.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON value")
	}
	switch value := token.(type) {
	case string:
		if !validUnicode(value) {
			return fmt.Errorf("JSON contains Unicode noncharacters")
		}
	case json.Number:
		n, err := strconv.ParseFloat(string(value), 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return fmt.Errorf("JSON number outside supported range")
		}
		if math.Trunc(n) == n && math.Abs(n) > 9007199254740991 {
			return fmt.Errorf("JSON integer exceeds interoperable range; encode identifiers as strings")
		}
	case json.Delim:
		if depth >= MaxJSONDepth {
			return fmt.Errorf("JSON nesting exceeds policy limit")
		}
		if value != '{' && value != '[' {
			return fmt.Errorf("invalid JSON delimiter")
		}
		seen := map[string]bool{}
		for dec.More() {
			if value == '{' {
				key, err := dec.Token()
				name, ok := key.(string)
				*count++
				if err != nil || !ok || !validUnicode(name) || seen[name] {
					return fmt.Errorf("duplicate or invalid JSON property")
				}
				seen[name] = true
			}
			if err := jsonValue(dec, depth+1, count); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return fmt.Errorf("invalid JSON container")
		}
	}
	return nil
}
