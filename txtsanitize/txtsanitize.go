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
