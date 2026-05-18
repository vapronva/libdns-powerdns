package powerdns

import (
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/mittwald/go-powerdns/apis/zones"
)

func TestMergeRRecsCaseInsensitiveNameAndType(t *testing.T) {
	fullZone := &zones.Zone{ResourceRecordSets: []zones.ResourceRecordSet{{
		Name: "www.example.com.", Type: "A", TTL: 60,
		Records: []zones.Record{{Content: "1.1.1.1"}},
	}}}
	result := mergeRRecs(fullZone, []libdns.Record{
		libdns.RR{Name: "WWW.EXAMPLE.COM.", Type: "a", TTL: 60 * time.Second, Data: "2.2.2.2"},
	})
	if len(result) != 1 {
		t.Fatalf("expected 1 rrset, got %d", len(result))
	}
	if len(result[0].Records) != 2 {
		t.Fatalf("expected uppercase input merged into lowercase set, got %#v", result[0].Records)
	}
}

func TestMergeRRecsSkipsValueAlreadyPresent(t *testing.T) {
	fullZone := &zones.Zone{ResourceRecordSets: []zones.ResourceRecordSet{{
		Name: "www.example.com.", Type: "A", TTL: 60,
		Records: []zones.Record{{Content: "1.1.1.1"}},
	}}}
	result := mergeRRecs(fullZone, []libdns.Record{
		libdns.RR{Name: "www.example.com.", Type: "A", Data: "1.1.1.1"},
	})
	if len(result) != 1 || len(result[0].Records) != 1 {
		t.Fatalf("appending an existing value must be a no-op, got %#v", result)
	}
}
