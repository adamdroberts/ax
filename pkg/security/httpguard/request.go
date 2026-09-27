package httpguard

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxFormFields = 100000

// Requests use a subset of RFC 9110 section 5.6.6: one optional UTF-8 charset,
// with SP allowed around the semicolon but never '='. Quoted pairs follow
// section 5.6.4 and are decoded before checking the supported charset.
// Validate the original bytes instead of MIME parsing, which tolerates invalid
// whitespace around '=' and may normalize it before inspection.
const mediaToken = "[!#$%&'*+.^_`|~0-9a-z-]+"

var requestMediaType = regexp.MustCompile("(?i)^(" + mediaToken + "/" + mediaToken + ")(?: *; *charset=(" + mediaToken + "|\"(?:[\\x20-\\x21\\x23-\\x5b\\x5d-\\x7e]|\\\\[\\x20-\\x7e])*\"))?$")

// ValidateURL accepts an ASCII RFC 3986 HTTP URI subset without browser-style
// repairs (backslashes, legacy IPv4 forms, whitespace, fragments or userinfo).
func ValidateURL(raw string) error {
	if raw == "" || len(raw) > 16*1024 {
		return fmt.Errorf("invalid URL length")
	}
	for _, c := range []byte(raw) {
		if c < 33 || c > 126 || strings.ContainsRune("\\\"<>`{}|^", rune(c)) {
			return fmt.Errorf("URL must use unambiguous ASCII URI syntax")
		}
	}
	if strings.Contains(raw, "#") {
		return fmt.Errorf("URL fragments are not sent to the origin and are not permitted")
	}
	if err := validateEscapes(raw); err != nil {
		return err
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || !strings.HasPrefix(raw, u.Scheme+"://") {
		return fmt.Errorf("absolute lowercase HTTP(S) URL without userinfo required")
	}
	host := u.Hostname()
	if host == "" || strings.Contains(host, "%") || strings.HasSuffix(host, ".") {
		return fmt.Errorf("invalid or ambiguous URL host")
	}
	if strings.Contains(u.Host, ":") && !strings.HasSuffix(u.Host, "]") {
		port := u.Port()
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return fmt.Errorf("URL port must be canonical decimal 1..65535")
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if strings.HasPrefix(u.Host, "[") != ip.Is6() {
			return fmt.Errorf("invalid address authority brackets")
		}
		if ip.Zone() != "" || ip.Is4In6() {
			return fmt.Errorf("scoped or mapped IP literals are not permitted")
		}
		if ip.Is4() && ip.String() != host {
			return fmt.Errorf("noncanonical IPv4 literal")
		}
		if ip.Is6() && ip.String() != host {
			return fmt.Errorf("noncanonical IPv6 literal")
		}
		if ip.Is6() && !strings.HasPrefix(u.Host, "[") {
			return fmt.Errorf("IPv6 literals require brackets")
		}
	} else {
		if len(host) > 253 || strings.ContainsAny(host, ":[]") {
			return fmt.Errorf("invalid DNS hostname")
		}
		labels := strings.Split(host, ".")
		for _, label := range labels {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return fmt.Errorf("invalid DNS label")
			}
			for _, c := range []byte(label) {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
					return fmt.Errorf("DNS host must use ASCII LDH labels")
				}
			}
		}
		last := strings.ToLower(labels[len(labels)-1])
		// WHATWG numeric-host parsing and libc inet_aton accept alternative IPs.
		if strings.Trim(last, "0123456789") == "" || strings.HasPrefix(last, "0x") {
			return fmt.Errorf("ambiguous numeric host")
		}
	}
	if strings.ContainsAny(u.EscapedPath()+u.RawQuery, "[]") {
		return fmt.Errorf("URI brackets must be percent encoded outside the host")
	}
	query, err := url.QueryUnescape(u.RawQuery)
	if err != nil || !utf8.ValidString(u.Path) || !utf8.ValidString(query) {
		return fmt.Errorf("URL components must decode to UTF-8")
	}
	return nil
}

func validateEscapes(s string) error {
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		if i+2 >= len(s) {
			return fmt.Errorf("invalid URI percent escape")
		}
		n, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		if err != nil {
			return fmt.Errorf("invalid URI percent escape")
		}
		if n < 32 || n == 127 || n == '\\' {
			return fmt.Errorf("encoded controls or backslashes are not permitted")
		}
		i += 2
	}
	return nil
}

func ValidateHeader(name, value string) error {
	if name == "" {
		return fmt.Errorf("empty header name")
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return fmt.Errorf("invalid HTTP header name")
		}
	}
	if len(name)+len(value)+4 > 8192 {
		return fmt.Errorf("header field exceeds 8 KiB limit")
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("header value has surrounding whitespace")
	}
	for _, c := range []byte(value) {
		if c < 32 || c > 126 {
			return fmt.Errorf("headers must contain visible ASCII or spaces")
		}
	}
	key := strings.ToLower(name)
	if strings.HasPrefix(key, "proxy-") || strings.HasPrefix(key, "sec-") || strings.HasPrefix(key, "x-forwarded") {
		return fmt.Errorf("proxy, routing and browser-context headers are managed by policy")
	}
	switch key {
	case "host", "content-length", "transfer-encoding", "connection", "keep-alive", "upgrade", "trailer", "te", "expect", "http2-settings", "forwarded", "x-original-url", "x-rewrite-url", "x-http-method-override", "x-method-override", "x-http-method", "x-host", "x-original-host", "x-real-ip", "x-agent-id", "x-approval-token", "origin", "referer", "content-transfer-encoding":
		return fmt.Errorf("framing, routing and browser-context headers are managed by policy")
	case "content-encoding", "accept-encoding":
		if !strings.EqualFold(value, "identity") {
			return fmt.Errorf("only identity content encoding is supported")
		}
	}
	return nil
}

// Prepare validates the exact request representation before signature matching.
// The transport only adds framing/connection headers, never cookies or redirects.
func Prepare(req *http.Request, body string) error {
	switch req.Method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
	default:
		return fmt.Errorf("unsupported or noncanonical HTTP method")
	}
	if (req.Method == "GET" || req.Method == "HEAD") && body != "" {
		return fmt.Errorf("GET and HEAD bodies are not supported")
	}
	if !utf8.ValidString(body) {
		return fmt.Errorf("request body must be UTF-8")
	}
	ct := req.Header.Get("Content-Type")
	if _, exists := req.Header["Content-Type"]; exists && ct == "" {
		return fmt.Errorf("empty Content-Type")
	}
	if body != "" && ct == "" {
		ct = "text/plain; charset=utf-8"
		if strings.HasPrefix(strings.TrimSpace(body), "{") || strings.HasPrefix(strings.TrimSpace(body), "[") {
			ct = "application/json"
		}
		req.Header.Set("Content-Type", ct)
	}
	if ct != "" {
		media := requestMediaType.FindStringSubmatch(ct)
		if media == nil {
			return fmt.Errorf("invalid Content-Type or unsupported charset parameter")
		}
		kind := strings.ToLower(media[1])
		if charset := media[2]; charset != "" {
			if charset[0] == '"' {
				var decoded strings.Builder
				for i := 1; i < len(charset)-1; i++ {
					if charset[i] == '\\' {
						i++ // The grammar guarantees a following visible ASCII byte.
					}
					decoded.WriteByte(charset[i])
				}
				charset = decoded.String()
			}
			if !strings.EqualFold(charset, "utf-8") {
				return fmt.Errorf("only UTF-8 charset media parameters are supported")
			}
		}
		switch {
		case kind == "application/json" || strings.HasPrefix(kind, "application/") && strings.HasSuffix(kind, "+json"):
			if err := ValidateJSON([]byte(body)); err != nil {
				return err
			}
		case kind == "application/x-www-form-urlencoded":
			// Match parse_qsl's pre-parse limit, including empty components.
			// Counting separators avoids allocating a slice for attacker input;
			// semicolons and escaped ampersands are ordinary field data.
			if body != "" && strings.Count(body, "&") >= MaxFormFields {
				return fmt.Errorf("form exceeds %d fields", MaxFormFields)
			}
			if err := validateEscapes(body); err != nil {
				return err
			}
			decoded, err := url.QueryUnescape(body)
			if err != nil || !utf8.ValidString(decoded) {
				return fmt.Errorf("form must decode to UTF-8")
			}
			for _, c := range decoded {
				if c < 32 || c == 127 || c == '\\' {
					return fmt.Errorf("form contains controls or backslash")
				}
			}
		case kind == "text/plain":
		default:
			return fmt.Errorf("unsupported request media type; use UTF-8 text, JSON or form data")
		}
	}
	// Set before inspection: clients must not negotiate hidden decompression.
	req.Header.Set("Accept-Encoding", "identity")
	return nil
}
