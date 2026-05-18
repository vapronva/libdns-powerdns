package powerdns

import (
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func TestConvertLDHashConvertsTTLToSeconds(t *testing.T) {
	rrsets := convertLDHash(map[string][]libdns.RR{
		"example.com.:A": {{Name: "example.com.", Type: "A", TTL: 60 * time.Second, Data: "127.0.0.1"}},
	})
	if len(rrsets) != 1 || rrsets[0].TTL != 60 {
		t.Fatalf("expected TTL 60s, got %#v", rrsets)
	}
}

func TestConvertLDHashDefaultsZeroTTL(t *testing.T) {
	rrsets := convertLDHash(map[string][]libdns.RR{
		"example.com.:A": {{Name: "example.com.", Type: "A", TTL: 0, Data: "127.0.0.1"}},
	})
	if len(rrsets) != 1 || rrsets[0].TTL != defaultTTL {
		t.Fatalf("expected fallback TTL %d, got %#v", defaultTTL, rrsets)
	}
}

func TestConvertLDHashDeduplicatesValues(t *testing.T) {
	rrsets := convertLDHash(makeLDRecHash([]libdns.Record{
		libdns.RR{Name: "a.example.com.", Type: "A", TTL: time.Minute, Data: "127.0.0.1"},
		libdns.RR{Name: "a.example.com.", Type: "A", TTL: time.Minute, Data: "127.0.0.1"},
	}))
	if len(rrsets) != 1 || len(rrsets[0].Records) != 1 {
		t.Fatalf("expected duplicate values collapsed to one record, got %#v", rrsets)
	}
}
