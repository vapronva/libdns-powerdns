package txtsanitize

import (
	"strings"
	"testing"
)

func TestTXTSanitize(t *testing.T) {
	for _, tst := range []struct {
		name     string
		input    string
		expected string
	}{
		{"acme token", "abc123_-XYZ", `"abc123_-XYZ"`},
		{"empty", ``, `""`},
		{"spf", `v=spf1 -all`, `"v=spf1 -all"`},
		{"embedded quotes", `has "quotes"`, `"has \"quotes\""`},
		{"libdns contract example", `quotes " backslashes \000`, `"quotes \" backslashes \\000"`},
		{"lone backslash", `back\slash`, `"back\\slash"`},
		{"trailing backslash", `ends\`, `"ends\\"`},
		{"single quote char", `"`, `"\""`},
		{"multi-string-looking input is literal", `"a" "b"`, `"\"a\" \"b\""`},
		{"already quoted", `"abc123"`, `"abc123"`},
		{"already quoted empty", `""`, `""`},
		{"already quoted with escapes", `"i\"m \\ done"`, `"i\"m \\ done"`},
	} {
		t.Run(tst.name, func(t *testing.T) {
			out := TXTSanitize(tst.input)
			if out != tst.expected {
				t.Errorf("got %q, want %q", out, tst.expected)
			}
			if again := TXTSanitize(out); again != out {
				t.Errorf("not idempotent: %q -> %q", out, again)
			}
		})
	}
}

func TestTXTUnquote(t *testing.T) {
	for _, tst := range []struct {
		name     string
		input    string
		expected string
	}{
		{"simple", `"hello world"`, "hello world"},
		{"special chars", `"value with symbols !@#$%"`, "value with symbols !@#$%"},
		{"embedded quotes", `"he said \"hi\""`, `he said "hi"`},
		{"backslashes", `"path\\to\\file"`, `path\to\file`},
		{"empty quoted", `""`, ""},
		{"empty input", ``, ``},
		{"space inside one string", `"a b"`, "a b"},
		{"multi-string concatenates", `"a" "b"`, "ab"},
		{"multi-string words", `"foo" "bar"`, "foobar"},
		{"decimal escape control byte", `"del: \127"`, "del: \x7f"},
		{"decimal escape tab", `"tab\009here"`, "tab\there"},
		{"decimal escape utf8 bytes", `"\195\167"`, "ç"},
		{"bareword returned as-is", `hello`, `hello`},
		{"unterminated returned as-is", `"oops`, `"oops`},
		{"dangling backslash returned as-is", `"oops\`, `"oops\`},
	} {
		t.Run(tst.name, func(t *testing.T) {
			if out := TXTUnquote(tst.input); out != tst.expected {
				t.Errorf("got %q, want %q", out, tst.expected)
			}
		})
	}
}

func TestTXTRoundTrip(t *testing.T) {
	for _, raw := range []string{
		"hello world",
		"value with symbols !@#$%",
		`he said "hi"`,
		`path\to\file`,
		`ends\`,
		`"a" "b"`,
		"tab\there",
		"ç is equal to \\195\\167",
		"",
		`"`,
		`\`,
		strings.Repeat("long-dkim-key-", 40),
	} {
		if got := TXTUnquote(TXTSanitize(raw)); got != raw {
			t.Errorf("round-trip failed for %q: got %q", raw, got)
		}
	}
}

func TestTXTSanitizeIdempotent(t *testing.T) {
	for _, in := range []string{
		``, `"`, `\`, `\\`, `\\\`, `""`, `"a" "b\"`, `"" " " "\"`,
		`a"b`, `a\"b`, `a\\"b`, `ends with \`, "raw\x00null", `\195\167`,
	} {
		first := TXTSanitize(in)
		if second := TXTSanitize(first); first != second {
			t.Errorf("not idempotent for %q:\n  first:  %q\n  second: %q", in, first, second)
		}
	}
}
