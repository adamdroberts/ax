// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package snort

import (
	"strings"
)

// DefaultRulesSnort contains the embedded baseline Snort rule definitions
// for zero-day mitigation, RCE prevention, SQLi, SSRF, and exploit protection.
const DefaultRulesSnort = `
# ==============================================================================
# AX Intrusion Prevention & Zero-Day Exploit Protection Rules
# ==============================================================================

# --- Remote Code Execution (RCE) & Command Injection ---
drop tcp any any -> any any (msg:"EXPLOIT Log4Shell JNDI injection attempt"; content:"${jndi:"; nocase; classtype:"attempted-admin"; sid:1000001; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT Log4Shell obfuscated JNDI pattern"; pcre:"/\$\{[^}]*jndi[^}]*:/i"; classtype:"attempted-admin"; sid:1000002; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT Reverse Shell /dev/tcp payload"; content:"/dev/tcp/"; nocase; classtype:"attempted-admin"; sid:1000003; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT Netcat reverse shell execution"; pcre:"/nc(\.traditional)?\s+.*-e\s+(\/bin\/(ba)?sh)/i"; classtype:"attempted-admin"; sid:1000004; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT Remote pipe to shell execution"; pcre:"/(curl|wget)\s+.*\|\s*(ba)?sh/i"; classtype:"attempted-admin"; sid:1000005; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT Shell command injection attempt"; pcre:"/(;|\||`|\$\().*\b(cat\s+\/etc\/passwd|whoami|id|uname\s+-a|rm\s+-rf)/i"; classtype:"attempted-admin"; sid:1000006; rev:1;)

# --- Zero-Day & Framework Exploits ---
drop tcp any any -> any any (msg:"EXPLOIT Spring4Shell classLoader manipulation"; content:"class.module.classLoader"; nocase; classtype:"attempted-admin"; sid:1000010; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT Apache Struts OGNL injection"; content:"#_memberAccess"; nocase; classtype:"attempted-admin"; sid:1000011; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT PHP CGI argument injection"; pcre:"/\?-d\+allow_url_include/i"; classtype:"attempted-admin"; sid:1000012; rev:1;)

# --- Path Traversal & Sensitive File Exposure ---
drop tcp any any -> any any (msg:"EXPLOIT Path Traversal directory climbing"; content:"../../"; http_uri; classtype:"web-application-attack"; sid:1000020; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT URL-encoded path traversal"; pcre:"/(\.\.%2f|\.\.%5c|%2e%2e%2f)/i"; http_uri; classtype:"web-application-attack"; sid:1000021; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT Sensitive system file access /etc/passwd"; content:"/etc/passwd"; nocase; classtype:"attempted-recon"; sid:1000022; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT Windows system file access"; pcre:"/(win\.ini|boot\.ini|system32\/config\/sam)/i"; nocase; classtype:"attempted-recon"; sid:1000023; rev:1;)

# --- Server-Side Request Forgery (SSRF) & Metadata Theft ---
drop tcp any any -> any any (msg:"ATTACK SSRF Cloud instance metadata probe"; content:"169.254.169.254"; http_uri; classtype:"bad-unknown"; sid:1000030; rev:1;)
drop tcp any any -> any any (msg:"ATTACK SSRF GCP metadata header probe"; content:"metadata.google.internal"; nocase; http_uri; classtype:"bad-unknown"; sid:1000031; rev:1;)
drop tcp any any -> any any (msg:"ATTACK SSRF Loopback service probe"; pcre:"/https?:\/\/(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])(:\d+)?(\/|$)/i"; http_uri; classtype:"bad-unknown"; sid:1000032; rev:1;)

# --- SQL Injection (SQLi) ---
drop tcp any any -> any any (msg:"EXPLOIT SQL Injection UNION SELECT"; pcre:"/union(\s+all)?\s+select/i"; classtype:"web-application-attack"; sid:1000040; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT SQL Injection classic OR tautology"; pcre:"/('\s*or\s+'?1'?\s*=\s*'?1|or\s+1\s*=\s*1\s*(--|#))/i"; classtype:"web-application-attack"; sid:1000041; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT SQL Injection stacked DROP/DELETE query"; pcre:"/(;\s*drop\s+(table|database)|;\s*truncate\s+table)/i"; classtype:"web-application-attack"; sid:1000042; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT SQL Injection time delay"; pcre:"/(waitfor\s+delay\s+'|sleep\(\s*\d+\s*\)|benchmark\(\s*\d+\s*,)/i"; classtype:"web-application-attack"; sid:1000043; rev:1;)

# --- Cross-Site Scripting (XSS) & CRLF Injection ---
drop tcp any any -> any any (msg:"EXPLOIT Cross-Site Scripting script injection"; pcre:"/<script[^>]*>|javascript:\s*/i"; classtype:"web-application-attack"; sid:1000050; rev:1;)
drop tcp any any -> any any (msg:"EXPLOIT CRLF header injection attempt"; pcre:"/(\r\n|\n\r|%0d%0a|%0a%0d)(Set-Cookie|Location):/i"; classtype:"web-application-attack"; sid:1000051; rev:1;)

# --- Automated Scanning & Hacking Tools ---
drop tcp any any -> any any (msg:"ATTACK Automated vulnerability scanner detected"; pcre:"/(sqlmap|nikto|havij|acunetix|dirbuster|nmap)/i"; http_header; classtype:"attempted-recon"; sid:1000060; rev:1;)
`

// DefaultEngine returns an Engine preloaded with the default baseline rules.
func DefaultEngine() (*Engine, error) {
	eng := NewEngine()
	_, err := eng.LoadRulesFromReader(strings.NewReader(DefaultRulesSnort))
	if err != nil {
		return nil, err
	}
	return eng, nil
}
