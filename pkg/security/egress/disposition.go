package egress

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var dispositionContinuation = regexp.MustCompile(`\*[0-9]+\*?$`)
var dispositionPercentEscape = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
var grandfatheredDispositionLanguages = headerSet(`en-gb-oed i-ami i-bnn i-default i-enochian i-hak
i-klingon i-lux i-mingo i-navajo i-pwn i-tao i-tay i-tsu sgn-be-fr sgn-be-nl sgn-ch-de
art-lojban cel-gaulish no-bok no-nyn zh-guoyu zh-hakka zh-min zh-min-nan zh-xiang`)

// RFC 5646 well-formedness, including uniqueness constraints. This does not
// assert registry membership or interpret extension-specific language subtags.
func dispositionLanguage(value string) bool {
	value = strings.ToLower(value)
	if value == "" || grandfatheredDispositionLanguages[value] {
		return true
	}
	parts := strings.Split(value, "-")
	alpha := func(s string) bool { return s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyz") == "" }
	digit := func(s string) bool { return s != "" && strings.Trim(s, "0123456789") == "" }
	for _, part := range parts {
		if len(part) < 1 || len(part) > 8 || strings.Trim(part, "abcdefghijklmnopqrstuvwxyz0123456789") != "" {
			return false
		}
	}
	if parts[0] == "x" {
		return len(parts) > 1
	}
	if len(parts[0]) < 2 || !alpha(parts[0]) {
		return false
	}
	i := 1
	if len(parts[0]) <= 3 {
		for n := 0; n < 3 && i < len(parts) && len(parts[i]) == 3 && alpha(parts[i]); n++ {
			i++
		}
	}
	if i < len(parts) && len(parts[i]) == 4 && alpha(parts[i]) {
		i++
	}
	if i < len(parts) && (len(parts[i]) == 2 && alpha(parts[i]) || len(parts[i]) == 3 && digit(parts[i])) {
		i++
	}
	variants, extensions := map[string]bool{}, map[string]bool{}
	for i < len(parts) && (len(parts[i]) >= 5 || len(parts[i]) == 4 && parts[i][0] >= '0' && parts[i][0] <= '9') {
		if variants[parts[i]] {
			return false
		}
		variants[parts[i]] = true
		i++
	}
	for i < len(parts) && parts[i] != "x" {
		if len(parts[i]) != 1 || extensions[parts[i]] {
			return false
		}
		extensions[parts[i]] = true
		i++
		first := i
		for i < len(parts) && len(parts[i]) >= 2 {
			i++
		}
		if i == first {
			return false
		}
	}
	return i == len(parts) || i+1 < len(parts) // Remaining private-use subtags were checked above.
}

func decodeDispositionExtended(value string) (string, bool) {
	parts := strings.SplitN(value, "'", 3)
	if len(parts) != 3 || !dispositionLanguage(parts[1]) {
		return "", false
	}
	for i := 0; i < len(parts[2]); i++ {
		c := parts[2][i]
		if c == '%' {
			if i+2 >= len(parts[2]) {
				return "", false
			}
			i += 2 // PathUnescape checks both hexadecimal digits below.
		} else if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$&+-.^_`|~", rune(c))) {
			return "", false
		}
	}
	decoded, err := url.PathUnescape(parts[2]) // '+' is literal, not form whitespace.
	if err != nil {
		return "", false
	}
	switch strings.ToLower(parts[0]) {
	case "utf-8":
		return decoded, utf8.ValidString(decoded)
	case "iso-8859-1": // RFC 8187 permits legacy RFC 5987 recipient support.
		var text strings.Builder
		for _, c := range []byte(decoded) {
			text.WriteRune(rune(c))
		}
		return text.String(), true
	default:
		return "", false
	}
}

// Filenames remain advisory. These conservative exclusions prevent common
// path/normalization differentials; they do not authorize any file write.
func checkDispositionFilename(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || strings.HasSuffix(value, ".") ||
		strings.ContainsAny(value, "\\/:<>|?*\"") || dispositionPercentEscape.MatchString(value) {
		return false
	}
	for _, c := range value {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) || c >= 0xfdd0 && c <= 0xfdef || c&0xffff >= 0xfffe {
			return false
		}
	}
	return true
}

// Validate HTTP Content-Disposition before generic MIME libraries can merge
// duplicates, recover malformed parameters, or apply RFC 2231 continuations.
func checkResponseDisposition(value string) error {
	bad := func() error { return fmt.Errorf("invalid or unsafe HTTP Content-Disposition") }
	if len(value) > 8192 {
		return bad()
	}
	for _, c := range []byte(value) {
		if c < 32 || c > 126 {
			return bad()
		}
	}
	value = strings.Trim(value, " ")
	i := 0
	spaces := func() {
		for i < len(value) && value[i] == ' ' {
			i++
		}
	}
	token := func() string {
		start := i
		for i < len(value) && tokenByte(value[i]) {
			i++
		}
		return value[start:i]
	}
	if token() == "" {
		return bad()
	}
	seen := map[string]bool{}
	for {
		spaces()
		if i == len(value) {
			return nil
		}
		if value[i] != ';' {
			return bad()
		}
		i++
		spaces()
		name := strings.ToLower(token())
		if name == "" || seen[name] || len(seen) >= MaxResponseMetadataParts || dispositionContinuation.MatchString(name) {
			return bad()
		}
		seen[name] = true
		spaces()
		if i == len(value) || value[i] != '=' {
			return bad()
		}
		i++
		spaces()
		quoted, escaped := i < len(value) && value[i] == '"', false
		var parameter string
		if quoted {
			i++
			var decoded strings.Builder
			for {
				if i == len(value) {
					return bad()
				}
				c := value[i]
				i++
				if c == '"' {
					break
				}
				if c == '\\' {
					escaped = true
					if i == len(value) {
						return bad()
					}
					c = value[i]
					i++
				}
				decoded.WriteByte(c)
			}
			parameter = decoded.String()
		} else {
			parameter = token()
			if parameter == "" {
				return bad()
			}
		}
		if strings.HasSuffix(name, "*") {
			var ok bool
			if quoted {
				return bad()
			}
			parameter, ok = decodeDispositionExtended(parameter)
			if !ok {
				return bad()
			}
		}
		if (name == "filename" || name == "filename*") && (escaped || !checkDispositionFilename(parameter)) {
			return bad()
		}
	}
}
