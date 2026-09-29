package egress

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxXMLDepth       = 64
	maxXMLAttributes  = 128
	maxXMLNameBytes   = 1024
	maxXMLMarkupBytes = 65536
	maxXMLUnits       = 100000
	xmlNamespace      = "http://www.w3.org/XML/1998/namespace"
	xmlnsNamespace    = "http://www.w3.org/2000/xmlns/"
)

var xmlDeclaration = regexp.MustCompile(`^<\?xml[ \t\r\n]+version[ \t\r\n]*=[ \t\r\n]*("1\.0"|'1\.0')([ \t\r\n]+encoding[ \t\r\n]*=[ \t\r\n]*("(?i:utf-8)"|'(?i:utf-8)'))?([ \t\r\n]+standalone[ \t\r\n]*=[ \t\r\n]*("(yes|no)"|'(yes|no)'))?[ \t\r\n]*\?>$`)

type xmlBinding struct {
	prefix, previous string
	existed          bool
}
type xmlFrame struct {
	name     string
	bindings []xmlBinding
}
type xmlAttribute struct{ name, value string }
type xmlAdmission struct {
	text                       string
	position, beginning, units int
	root                       bool
	stack                      []xmlFrame
	namespaces                 map[string]string
}

// This is a bounded admission recognizer, not a document interpreter. It never
// loads entities, DTDs, schemas, stylesheets or other external resources and
// never rewrites the returned bytes. Name ranges follow XML 1.0 Fifth Edition,
// including supplementary-plane names absent from older runtime parser tables.
func checkResponseXML(body []byte) error {
	if len(body) > MaxResponseBodyBytes || !utf8.Valid(body) {
		return fmt.Errorf("response violates the XML interoperability policy")
	}
	p := xmlAdmission{text: string(body), namespaces: map[string]string{"xml": xmlNamespace}}
	for _, c := range p.text {
		if !xmlCharacter(c) {
			return fmt.Errorf("response violates the XML interoperability policy")
		}
	}
	if strings.HasPrefix(p.text, "\ufeff") {
		p.position, p.beginning = 3, 3
	}
	if !p.document() {
		return fmt.Errorf("response violates the XML interoperability policy")
	}
	return nil
}

func xmlCharacter(c rune) bool {
	return c == 9 || c == 10 || c == 13 || c >= 0x20 && c <= 0xd7ff || c >= 0xe000 && c <= 0xfffd || c >= 0x10000 && c <= 0x10ffff
}
func xmlSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }
func xmlNameStart(c rune) bool {
	return c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ||
		c >= 0xc0 && c <= 0xd6 || c >= 0xd8 && c <= 0xf6 || c >= 0xf8 && c <= 0x2ff ||
		c >= 0x370 && c <= 0x37d || c >= 0x37f && c <= 0x1fff || c >= 0x200c && c <= 0x200d ||
		c >= 0x2070 && c <= 0x218f || c >= 0x2c00 && c <= 0x2fef || c >= 0x3001 && c <= 0xd7ff ||
		c >= 0xf900 && c <= 0xfdcf || c >= 0xfdf0 && c <= 0xfffd || c >= 0x10000 && c <= 0xeffff
}
func xmlNameContinue(c rune) bool {
	return xmlNameStart(c) || c == '-' || c == '.' || c >= '0' && c <= '9' || c == 0xb7 || c >= 0x300 && c <= 0x36f || c >= 0x203f && c <= 0x2040
}
func xmlNCName(name string) bool {
	if name == "" {
		return false
	}
	for i, c := range name {
		if i == 0 && !xmlNameStart(c) || i != 0 && !xmlNameContinue(c) {
			return false
		}
	}
	return true
}
func xmlQName(name string) bool {
	prefix, local, found := strings.Cut(name, ":")
	return !found && xmlNCName(name) || found && xmlNCName(prefix) && xmlNCName(local)
}
func (p *xmlAdmission) unit() bool { p.units++; return p.units <= maxXMLUnits }
func (p *xmlAdmission) space() {
	for p.position < len(p.text) && xmlSpace(p.text[p.position]) {
		p.position++
	}
}
func (p *xmlAdmission) take(value string) bool {
	if !strings.HasPrefix(p.text[p.position:], value) {
		return false
	}
	p.position += len(value)
	return true
}
func (p *xmlAdmission) name() string {
	start := p.position
	for p.position < len(p.text) {
		c, size := utf8.DecodeRuneInString(p.text[p.position:])
		if c != ':' && !(p.position == start && xmlNameStart(c) || p.position != start && xmlNameContinue(c)) {
			break
		}
		p.position += size
		if p.position-start > maxXMLNameBytes {
			return ""
		}
	}
	return p.text[start:p.position]
}

// References are expanded only into bounded attribute values for namespace
// comparison. Content references are checked without constructing a DOM/string.
func (p *xmlAdmission) value(raw string, attribute bool) (string, bool) {
	var out strings.Builder
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if attribute && c == '<' {
			return "", false
		}
		if c == '&' {
			end := strings.IndexByte(raw[i:min(len(raw), i+32)], ';')
			if end < 0 || !p.unit() {
				return "", false
			}
			ref := raw[i+1 : i+end]
			var decoded rune
			switch ref {
			case "amp":
				decoded = '&'
			case "lt":
				decoded = '<'
			case "gt":
				decoded = '>'
			case "quot":
				decoded = '"'
			case "apos":
				decoded = '\''
			default:
				if !strings.HasPrefix(ref, "#") {
					return "", false
				}
				digits, base := ref[1:], 10
				if strings.HasPrefix(digits, "x") {
					digits, base = digits[1:], 16
				}
				if digits == "" {
					return "", false
				}
				for _, d := range digits {
					if !(d >= '0' && d <= '9' || base == 16 && (d >= 'a' && d <= 'f' || d >= 'A' && d <= 'F')) {
						return "", false
					}
				}
				n, err := strconv.ParseUint(digits, base, 32)
				if err != nil || n > 0x10ffff || !xmlCharacter(rune(n)) {
					return "", false
				}
				decoded = rune(n)
			}
			if attribute {
				out.WriteRune(decoded)
			}
			i += end
		} else if attribute {
			if c == '\r' {
				if i+1 < len(raw) && raw[i+1] == '\n' {
					i++
				}
				c = ' '
			} else if c == '\n' || c == '\t' {
				c = ' '
			}
			out.WriteByte(c)
		}
	}
	return out.String(), true
}

func (p *xmlAdmission) document() bool {
	for p.position < len(p.text) {
		start := p.position
		if p.text[start] != '<' {
			end := strings.IndexByte(p.text[start:], '<')
			if end < 0 {
				end = len(p.text) - start
			}
			raw := p.text[start : start+end]
			if len(p.stack) == 0 {
				for i := range len(raw) {
					if !xmlSpace(raw[i]) {
						return false
					}
				}
			} else {
				if strings.Contains(raw, "]]>") {
					return false
				}
				if _, ok := p.value(raw, false); !ok {
					return false
				}
			}
			p.position += end
			continue
		}
		if !p.unit() {
			return false
		}
		switch {
		case p.take("<!--"):
			end := strings.Index(p.text[p.position:], "-->")
			if end < 0 || p.position+end+3-start > maxXMLMarkupBytes {
				return false
			}
			content := p.text[p.position : p.position+end]
			if strings.Contains(content, "--") || strings.HasSuffix(content, "-") {
				return false
			}
			p.position += end + 3
		case p.take("<![CDATA["):
			if len(p.stack) == 0 {
				return false
			}
			end := strings.Index(p.text[p.position:], "]]>")
			if end < 0 {
				return false
			}
			p.position += end + 3
		case p.take("<?"):
			target := p.name()
			if !xmlNCName(target) {
				return false
			}
			end := strings.Index(p.text[p.position:], "?>")
			if end < 0 || p.position+end+2-start > maxXMLMarkupBytes || end > 0 && !xmlSpace(p.text[p.position]) {
				return false
			}
			p.position += end + 2
			if strings.EqualFold(target, "xml") && (target != "xml" || start != p.beginning || !xmlDeclaration.MatchString(p.text[start:p.position])) {
				return false
			}
		case p.take("</"):
			name := p.name()
			p.space()
			if !xmlQName(name) || !p.take(">") || len(p.stack) == 0 || p.stack[len(p.stack)-1].name != name || p.position-start > maxXMLMarkupBytes {
				return false
			}
			p.close()
		case strings.HasPrefix(p.text[p.position:], "<!"):
			return false // DTDs and all other declarations are outside this profile.
		default:
			if !p.element() {
				return false
			}
		}
	}
	return p.root && len(p.stack) == 0
}

func (p *xmlAdmission) element() bool {
	start := p.position
	if !p.take("<") {
		return false
	}
	name := p.name()
	if !xmlQName(name) || len(p.stack) >= maxXMLDepth || len(p.stack) == 0 && p.root {
		return false
	}
	var attrs []xmlAttribute
	seen := map[string]bool{}
	empty := false
	for {
		before := p.position
		p.space()
		if p.take("/>") {
			empty = true
			break
		}
		if p.take(">") {
			break
		}
		if before == p.position || len(attrs) >= maxXMLAttributes {
			return false
		}
		key := p.name()
		if !xmlQName(key) || seen[key] {
			return false
		}
		seen[key] = true
		p.space()
		if !p.take("=") {
			return false
		}
		p.space()
		if p.position >= len(p.text) || p.text[p.position] != '\'' && p.text[p.position] != '"' {
			return false
		}
		quote := p.text[p.position]
		p.position++
		end := strings.IndexByte(p.text[p.position:], quote)
		if end < 0 || p.position+end+1-start > maxXMLMarkupBytes {
			return false
		}
		value, ok := p.value(p.text[p.position:p.position+end], true)
		if !ok {
			return false
		}
		p.position += end + 1
		attrs = append(attrs, xmlAttribute{key, value})
	}
	if p.position-start > maxXMLMarkupBytes {
		return false
	}
	frame := xmlFrame{name: name}
	for _, a := range attrs {
		prefix, local, colon := strings.Cut(a.name, ":")
		if a.name != "xmlns" && !(colon && prefix == "xmlns") {
			continue
		}
		binding := ""
		if colon {
			binding = local
		}
		if binding == "xmlns" || binding == "xml" && a.value != xmlNamespace || binding != "xml" && a.value == xmlNamespace || a.value == xmlnsNamespace || binding != "" && a.value == "" {
			return false
		}
		for _, c := range a.value {
			if c <= 32 || c == 127 {
				return false
			}
		}
		previous, exists := p.namespaces[binding]
		frame.bindings = append(frame.bindings, xmlBinding{binding, previous, exists})
		p.namespaces[binding] = a.value
	}
	if prefix, _, colon := strings.Cut(name, ":"); colon && (prefix == "xmlns" || p.namespaces[prefix] == "") {
		return false
	}
	expanded := map[[2]string]bool{}
	for _, a := range attrs {
		prefix, local, colon := strings.Cut(a.name, ":")
		if a.name == "xmlns" || colon && prefix == "xmlns" {
			continue
		}
		uri := ""
		if colon {
			uri = p.namespaces[prefix]
			if uri == "" {
				return false
			}
		} else {
			local = a.name
		}
		key := [2]string{uri, local}
		if expanded[key] {
			return false
		}
		expanded[key] = true
	}
	p.root = true
	p.stack = append(p.stack, frame)
	if empty {
		p.close()
	}
	return true
}

func (p *xmlAdmission) close() {
	frame := p.stack[len(p.stack)-1]
	p.stack = p.stack[:len(p.stack)-1]
	for _, binding := range frame.bindings {
		if binding.existed {
			p.namespaces[binding.prefix] = binding.previous
		} else {
			delete(p.namespaces, binding.prefix)
		}
	}
}
