package txtsanitize

import "testing"

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
