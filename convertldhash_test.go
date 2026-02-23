package powerdns

import (
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func TestConvertLDHashConvertsTTLToSeconds(t *testing.T) {
	inHash := map[string][]libdns.RR{
		"example.com.:A": {
			{
				Name: "example.com.",
				Type: "A",
				TTL:  60 * time.Second,
				Data: "127.0.0.1",
			},
		},
	}
	rrsets := convertLDHash(inHash)
	if len(rrsets) != 1 {
		t.Fatalf("expected 1 rrset, got %d", len(rrsets))
	}
	if got, want := rrsets[0].TTL, 60; got != want {
		t.Fatalf("wrong TTL: got %d, want %d", got, want)
	}
}
