package powerdns

import (
	"testing"

	"github.com/libdns/libdns"

	"github.com/vapronva/libdns-powerdns/txtsanitize"
)

func TestParseZoneRecordUnquotesTXT(t *testing.T) {
	const zone = "example.org."
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"simple", "hello world"},
		{"special", "value with symbols !@#$%"},
		{"embedded-quotes", `he said "hi"`},
		{"backslashes", `path\to\file`},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stored := txtsanitize.TXTSanitize(tc.raw)
			rec := parseZoneRecord(zone, "host."+zone, "TXT", 60, stored)
			txt, ok := rec.(libdns.TXT)
			if !ok {
				t.Fatalf("expected libdns.TXT, got %T", rec)
			}
			if txt.Text != tc.raw {
				t.Errorf("TXT.Text = %q, want raw %q (stored %q)", txt.Text, tc.raw, stored)
			}
		})
	}
}

func TestParseZoneRecordUnquotesSPF(t *testing.T) {
	const zone = "example.org."
	stored := txtsanitize.TXTSanitize("v=spf1 -all")
	rec := parseZoneRecord(zone, "host."+zone, "SPF", 60, stored)
	if got := rec.RR().Data; got != "v=spf1 -all" {
		t.Errorf("SPF read Data = %q, want unquoted %q", got, "v=spf1 -all")
	}
}

func TestTXTWriteReadRoundTrip(t *testing.T) {
	const zone = "example.org."
	for _, raw := range []string{
		"123456",
		`he said "hi"`,
		`ç is equal to \195\167`,
		"",
	} {
		converted := convertNamesToAbsolute(zone, []libdns.Record{
			libdns.RR{Name: "_acme", Type: "TXT", Data: raw},
		})
		stored := converted[0].RR().Data
		got, ok := parseZoneRecord(zone, converted[0].RR().Name, "TXT", 60, stored).(libdns.TXT)
		if !ok {
			t.Fatalf("raw %q: expected libdns.TXT", raw)
		}
		if got.Text != raw {
			t.Errorf("round trip for %q: got %q (stored %q)", raw, got.Text, stored)
		}
	}
}
