package httpguard

import (
	"net/http"
	"strings"
	"testing"
)

func TestStrictJSONDifferentials(t *testing.T) {
	bad := []string{
		`{"a":1,"a":2}`, `{"a":1,"\u0061":2}`, `{"outer":{"x":1,"x":2}}`,
		`"\ud800"`, `"\udc00"`, `"\ud800\u0061"`, `"\uffff"`, `"\ud83f\udffe"`,
		`NaN`, `1e999`, `9007199254740992`, `9.007199254740992e15`, `"` + string([]byte{0xff}) + `"`,
		strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66),
		"[" + strings.Repeat("0,", MaxJSONTokens) + "0]",
	}
	for _, value := range bad {
		if err := ValidateJSON([]byte(value)); err == nil {
			t.Errorf("accepted ambiguous JSON %.100q", value)
		}
	}
	for _, value := range []string{`{"text":"safe","number":42}`, `"\ud83d\ude00"`, `"\\ud800"`, `{"a":1,"A":2}`, `-9007199254740991`, `0.0125`, `true`, `null`, `"新しい"`} {
		if err := ValidateJSON([]byte(value)); err != nil {
			t.Errorf("rejected %q: %v", value, err)
		}
	}
}

func TestStrictURLSyntax(t *testing.T) {
	for _, raw := range []string{
		"https://example.com/path?q=ok", "https://EXAMPLE.com/%E2%82%AC", "http://8.8.8.8:8080/", "https://[2606:4700:4700::1111]/",
	} {
		if err := ValidateURL(raw); err != nil {
			t.Errorf("valid URL %q: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"https://example.com/#", "https://example.com/#hidden", "https://example.com\\@evil.test/", "https://user@example.com/", "http://2130706433/", "http://127.1/", "http://0177.0.0.1/", "http://0x7f.0x1/", "https://example.com./", "https://example.com:0443/", "https://example.com:0/", "https://example.com:/", "https://[fe80::1%25en0]/", "https://[::ffff:127.0.0.1]/", "https://example.com/?q=%zz", "https://example.com/?q=%0d%0a", "https://example.com/%5cadmin", "https://example.com/%c0%afadmin", "https://example.com/%ff", "https://example.com/?q=%ed%a0%80", "https://example.com/[a]", "https://example.com/{a}", "https://example.com/£", "HTTPS://example.com/", "https://example.com:65536/",
	} {
		if err := ValidateURL(raw); err == nil {
			t.Errorf("accepted URL %q", raw)
		}
	}
}

func TestManagedHeaders(t *testing.T) {
	for _, name := range []string{"Host", "Content-Length", "Transfer-Encoding", "TE", "Trailer", "Connection", "Keep-Alive", "Upgrade", "Expect", "Proxy-Connection", "Proxy-Authorization", "Proxy-Custom", "HTTP2-Settings", "Sec-Fetch-Site", "Sec-WebSocket-Key", "Forwarded", "X-Forwarded-For", "X-Original-URL", "X-Rewrite-URL", "X-HTTP-Method-Override", "X-Original-Host", "X-Real-IP", "X-Agent-ID", "X-Approval-Token", "Origin", "Referer", "Content-Transfer-Encoding"} {
		if err := ValidateHeader(name, "x"); err == nil {
			t.Errorf("accepted managed header %q", name)
		}
	}
	for _, value := range []string{"one\r\nInjected: yes", "one\ntwo", "one\ttwo", "one\x00two", "béarer", " spaced", "spaced ", strings.Repeat("a", 8192)} {
		if err := ValidateHeader("X-Test", value); err == nil {
			t.Errorf("accepted header %.50q", value)
		}
	}
	for _, pair := range [][2]string{{"Authorization", "Bearer scoped-token"}, {"Content-Type", "application/json"}, {"Accept-Encoding", "identity"}} {
		if err := ValidateHeader(pair[0], pair[1]); err != nil {
			t.Errorf("valid header %v: %v", pair, err)
		}
	}
}

func TestBodyContract(t *testing.T) {
	cases := []struct {
		method, ct, body string
		blocked          bool
	}{
		{"POST", "application/json", `{"ok":true}`, false}, {"POST", "application/problem+json; charset=UTF-8", `{}`, false},
		{"POST", "", `{"key":1,"key":2}`, true}, {"POST", "application/json", `{"key":1,"\u006bey":2}`, true},
		{"POST", "application/json; charset=utf-8; charset=utf-8", `{}`, true}, {"POST", "application/json; charset=utf-16", `{}`, true},
		{"POST", "application/xml", `<x/>`, true}, {"POST", "multipart/form-data; boundary=x", "x", true}, {"POST", "application/octet-stream", "abc", true},
		{"POST", "application/x-www-form-urlencoded", "q=%E2%82%AC", false}, {"POST", "application/x-www-form-urlencoded", "q=%ff", true}, {"POST", "application/x-www-form-urlencoded", "q=%0a", true},
		{"POST", "text/plain", "safe\ntext", false}, {"POST", "text/plain", string([]byte{0xff}), true}, {"GET", "", "hidden", true}, {"HEAD", "", "hidden", true}, {"get", "", "", true}, {"CONNECT", "", "", true}, {"TRACE", "", "", true},
	}
	for _, tc := range cases {
		req, _ := http.NewRequest(tc.method, "https://example.com", strings.NewReader(tc.body))
		if tc.ct != "" {
			req.Header.Set("Content-Type", tc.ct)
		}
		err := Prepare(req, tc.body)
		if (err != nil) != tc.blocked {
			t.Errorf("%s %s %.30q blocked=%v err=%v", tc.method, tc.ct, tc.body, tc.blocked, err)
		}
		if err == nil && req.Header.Get("Accept-Encoding") != "identity" {
			t.Error("missing explicit identity encoding")
		}
	}
}

func TestFormFieldLimitAndBackslashParity(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		blocked    bool
	}{
		{"raw value backslash", `q=\`, true},
		{"raw name backslash", `\=value`, true},
		{"encoded backslash", "q=%5c", true},
		{"empty form", "", false},
		{"maximum fields", strings.Repeat("a&", MaxFormFields-1) + "a", false},
		{"excess fields", strings.Repeat("a&", MaxFormFields) + "a", true},
		{"maximum empty components", strings.Repeat("&", MaxFormFields-1), false},
		{"excess empty components", strings.Repeat("&", MaxFormFields), true},
		{"semicolon data", "q=" + strings.Repeat("a;", MaxFormFields), false},
		{"escaped separator data", "q=" + strings.Repeat("%26", MaxFormFields), false},
		{"blank components and missing equals", "&name&&value=&", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", "https://example.com", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if err := Prepare(req, tc.body); (err != nil) != tc.blocked {
				t.Fatalf("blocked=%v, error=%v", tc.blocked, err)
			}
		})
	}
}

func FuzzValidateJSON(f *testing.F) {
	for _, seed := range []string{`{"a":1}`, `"\ud800"`, `"\\\"\u0061"`, `[]`, `{"x":"\ud83d\ude00"}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) <= 16384 {
			_ = ValidateJSON([]byte(input))
		}
	})
}
