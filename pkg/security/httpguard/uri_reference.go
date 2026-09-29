package httpguard

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

func uriReferenceError() error { return fmt.Errorf("invalid HTTP URI-reference metadata") }

// ValidateURIReference checks RFC 3986 component grammar without decoding,
// resolving, repairing, or authorizing the reference. RFC 9110 Content-Location
// excludes fragments. HTTP(S) references require an authority and nonempty
// host, and cannot contain userinfo. Network-path references inherit HTTP(S)
// from this broker's target. Other schemes receive generic syntax checks only.
func ValidateURIReference(value string, allowFragment bool) error {
	if len(value) > 8192 {
		return uriReferenceError()
	}
	for i := 0; i < len(value); i++ {
		if value[i] <= 32 || value[i] > 126 {
			return uriReferenceError()
		}
	}
	rest, fragment, hasFragment := strings.Cut(value, "#")
	if hasFragment && (!allowFragment || !uriComponent(fragment, ":@/?", true)) {
		return uriReferenceError()
	}
	path, query, hasQuery := strings.Cut(rest, "?")
	if hasQuery && !uriComponent(query, ":@/?", true) {
		return uriReferenceError()
	}
	scheme := ""
	colon, slash := strings.IndexByte(path, ':'), strings.IndexByte(path, '/')
	if colon >= 0 && (slash < 0 || colon < slash) {
		scheme = path[:colon]
		if scheme == "" || !uriAlpha(scheme[0]) {
			return uriReferenceError()
		}
		for i := 1; i < len(scheme); i++ {
			c := scheme[i]
			if !uriAlpha(c) && !uriDigit(c) && !strings.ContainsRune("+-.", rune(c)) {
				return uriReferenceError()
			}
		}
		scheme = strings.ToLower(scheme)
		path = path[colon+1:]
	}
	httpScheme := scheme == "http" || scheme == "https"
	if strings.HasPrefix(path, "//") {
		authority, tail, hasPath := strings.Cut(path[2:], "/")
		if !uriAuthority(authority, httpScheme || scheme == "") {
			return uriReferenceError()
		}
		path = ""
		if hasPath {
			path = "/" + tail
		}
	} else if httpScheme {
		return uriReferenceError()
	}
	if !uriComponent(path, ":@/", true) {
		return uriReferenceError()
	}
	return nil
}

func uriAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func uriDigit(c byte) bool { return c >= '0' && c <= '9' }
func uriHex(c byte) bool   { return uriDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }
func uriComponent(value, extra string, percent bool) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '%' && percent {
			if i+2 >= len(value) || !uriHex(value[i+1]) || !uriHex(value[i+2]) {
				return false
			}
			i += 2
		} else if !uriAlpha(c) && !uriDigit(c) && !strings.ContainsRune("-._~!$&'()*+,;="+extra, rune(c)) {
			return false
		}
	}
	return true
}

func uriAuthority(authority string, httpContext bool) bool {
	if userinfo, host, found := strings.Cut(authority, "@"); found {
		if httpContext || !uriComponent(userinfo, ":", true) {
			return false
		}
		authority = host
	}
	host, port := "", ""
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return false
		}
		host = authority[1:end]
		suffix := authority[end+1:]
		if suffix != "" {
			if suffix[0] != ':' {
				return false
			}
			port = suffix[1:]
		}
		if len(host) > 0 && (host[0] == 'v' || host[0] == 'V') {
			version, address, found := strings.Cut(host[1:], ".")
			if !found || version == "" || address == "" || !uriComponent(address, ":", false) {
				return false
			}
			for i := 0; i < len(version); i++ {
				if !uriHex(version[i]) {
					return false
				}
			}
		} else {
			address, err := netip.ParseAddr(host)
			if err != nil || !address.Is6() || address.Zone() != "" {
				return false
			}
		}
	} else {
		host, port, _ = strings.Cut(authority, ":")
		if !uriComponent(host, "", true) {
			return false
		}
	}
	if httpContext && host == "" {
		return false
	}
	for i := 0; i < len(port); i++ {
		if !uriDigit(port[i]) {
			return false
		}
	}
	return true
}

// ValidateLocationHeaders also catches empty internal value arrays and
// case-variant duplicate map keys before parsed-response or direct-client use.
// HTTP request Location has no standard response-field semantics here.
func ValidateLocationHeaders(headers http.Header, response bool) error {
	seen := map[string]bool{}
	for field, values := range headers {
		name := strings.ToLower(field)
		if name != "content-location" && !(response && name == "location") {
			continue
		}
		if seen[name] || len(values) != 1 || len(field)+len(values[0])+4 > 8192 {
			return uriReferenceError()
		}
		seen[name] = true
		if err := ValidateURIReference(strings.Trim(values[0], " "), name == "location"); err != nil {
			return err
		}
	}
	return nil
}
