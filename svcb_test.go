package powerdns

import (
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func TestConvertNamesToAbsoluteQuotesECHParam(t *testing.T) {
	in := []libdns.Record{
		libdns.ServiceBinding{
			Name:     "svc",
			TTL:      60 * time.Second,
			Scheme:   "https",
			Priority: 1,
			Target:   ".",
			Params: libdns.SvcParams{
				"ech": {"foobar"},
			},
		},
	}
	out := convertNamesToAbsolute("example.org.", in)
	if len(out) != 1 {
		t.Fatalf("expected 1 record, got %d", len(out))
	}
	rr := out[0].RR()
	if rr.Name != "svc.example.org." {
		t.Fatalf("unexpected name: %q", rr.Name)
	}
	if !strings.Contains(rr.Data, `ech="foobar"`) {
		t.Fatalf("expected quoted ech parameter, got %q", rr.Data)
	}
	if strings.Contains(rr.Data, "ech=foobar") {
		t.Fatalf("ech parameter should always be quoted, got %q", rr.Data)
	}
}

func TestConvertNamesToAbsoluteCanonicalizesSvcParamOrderAndQuoting(t *testing.T) {
	in := []libdns.Record{
		libdns.ServiceBinding{
			Name:     "svc",
			TTL:      60 * time.Second,
			Scheme:   "https",
			Priority: 1,
			Target:   ".",
			Params: libdns.SvcParams{
				"key666":    {"foobar"},
				"ipv6hint":  {"2001:db8::1"},
				"alpn":      {"h2"},
				"mandatory": {"ipv4hint", "alpn"},
				"ipv4hint":  {"192.0.2.1", "192.0.2.2"},
				"ech":       {"Zm9vYmFy"},
			},
		},
	}
	out := convertNamesToAbsolute("example.org.", in)
	if len(out) != 1 {
		t.Fatalf("expected 1 record, got %d", len(out))
	}
	rr := out[0].RR()
	want := `1 . mandatory=alpn,ipv4hint alpn=h2 ipv4hint=192.0.2.1,192.0.2.2 ech="Zm9vYmFy" ipv6hint=2001:db8::1 key666="foobar"`
	if rr.Data != want {
		t.Fatalf("unexpected data: got %q want %q", rr.Data, want)
	}
}

func TestConvertNamesToAbsoluteCanonicalizesKnownGenericKeys(t *testing.T) {
	in := []libdns.Record{
		libdns.ServiceBinding{
			Name:     "svc",
			TTL:      60 * time.Second,
			Scheme:   "https",
			Priority: 1,
			Target:   ".",
			Params: libdns.SvcParams{
				"key8": {},
				"key7": {"/dns-query{?dns}"},
				"key5": {"Zm9vYmFy"},
				"key2": {},
			},
		},
	}
	out := convertNamesToAbsolute("example.org.", in)
	if len(out) != 1 {
		t.Fatalf("expected 1 record, got %d", len(out))
	}
	rr := out[0].RR()
	want := `1 . no-default-alpn ech="Zm9vYmFy" dohpath="/dns-query{?dns}" ohttp`
	if rr.Data != want {
		t.Fatalf("unexpected data: got %q want %q", rr.Data, want)
	}
}
