package txtsanitize

import "strings"

func TXTSanitize(in string) string {
	if isQuoted(in) {
		return in
	}
	var b strings.Builder
	b.Grow(len(in) + 2)
	b.WriteByte('"')
	for i := range len(in) {
		if c := in[i]; c == '\\' || c == '"' {
			b.WriteByte('\\')
		}
		b.WriteByte(in[i])
	}
	b.WriteByte('"')
	return b.String()
}

func TXTUnquote(in string) string {
	if out, ok := decodeCharacterStrings(in); ok {
		return out
	}
	return in
}

func decodeCharacterStrings(in string) (string, bool) {
	var b strings.Builder
	b.Grow(len(in))
	var sawString bool
	for i := 0; i < len(in); {
		for i < len(in) && (in[i] == ' ' || in[i] == '\t') {
			i++
		}
		if i >= len(in) {
			break
		}
		next, ok := decodeQuotedString(in, i, &b)
		if !ok {
			return "", false
		}
		sawString = true
		i = next
	}
	return b.String(), sawString
}

func decodeQuotedString(in string, start int, b *strings.Builder) (int, bool) {
	if in[start] != '"' {
		return 0, false
	}
	for i := start + 1; i < len(in); {
		c := in[i]
		if c == '"' {
			return i + 1, true
		}
		if c != '\\' {
			b.WriteByte(c)
			i++
			continue
		}
		decoded, next, ok := decodeEscape(in, i)
		if !ok {
			return 0, false
		}
		b.WriteByte(decoded)
		i = next
	}
	return 0, false
}

func decodeEscape(in string, i int) (byte, int, bool) {
	if i+1 >= len(in) {
		return 0, 0, false
	}
	if d := in[i+1]; d < '0' || d > '9' {
		return d, i + 2, true
	}
	if i+3 >= len(in) || in[i+2] < '0' || in[i+2] > '9' || in[i+3] < '0' || in[i+3] > '9' {
		return 0, 0, false
	}
	v := int(in[i+1]-'0')*100 + int(in[i+2]-'0')*10 + int(in[i+3]-'0')
	if v > 0xFF {
		return 0, 0, false
	}
	return byte(v & 0xFF), i + 4, true
}

func isQuoted(s string) bool {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return false
	}
	body := s[1 : len(s)-1]
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '\\':
			if i+1 >= len(body) || (body[i+1] != '\\' && body[i+1] != '"') {
				return false
			}
			i++
		case '"':
			return false
		}
	}
	return true
}
