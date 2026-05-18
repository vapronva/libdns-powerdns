package powerdns

import (
	"sort"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/mittwald/go-powerdns/apis/zones"
)

func newDeleteTestZone() *zones.Zone {
	return &zones.Zone{
		ID:   "example.org.",
		Name: "example.org.",
		ResourceRecordSets: []zones.ResourceRecordSet{
			{
				Name:    "a.example.org.",
				Type:    "A",
				TTL:     60,
				Records: []zones.Record{{Content: "192.0.2.1"}, {Content: "192.0.2.2"}, {Content: "192.0.2.3"}},
			},
			{
				Name:    "a.example.org.",
				Type:    "TXT",
				TTL:     120,
				Records: []zones.Record{{Content: `"hello"`}},
			},
			{
				Name:    "b.example.org.",
				Type:    "A",
				TTL:     300,
				Records: []zones.Record{{Content: "198.51.100.1"}},
			},
		},
	}
}

func runCull(fullZone *zones.Zone, input []libdns.Record) ([]zones.ResourceRecordSet, []libdns.Record) {
	const zone = "example.org."
	return cullRRecs(zone, fullZone, convertNamesToAbsolute(zone, input), input)
}

func deletedValues(recs []libdns.Record) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.RR().Type+":"+r.RR().Name+":"+r.RR().Data)
	}
	sort.Strings(out)
	return out
}

func rrsetByName(sets []zones.ResourceRecordSet, name, typ string) (zones.ResourceRecordSet, bool) {
	for _, s := range sets {
		if s.Name == name && s.Type == typ {
			return s, true
		}
	}
	return zones.ResourceRecordSet{}, false
}

func TestDeleteRecords_NonExistentNameIgnored(t *testing.T) {
	sets, deleted := runCull(newDeleteTestZone(), []libdns.Record{
		libdns.RR{Name: "nope", Type: "A", Data: "192.0.2.9"},
	})
	if len(deleted) != 0 || len(sets) != 0 {
		t.Fatalf("expected no-op for unknown name, got sets=%#v deleted=%#v", sets, deleted)
	}
}

func TestDeleteRecords_NonExistentValueInExistingSetIgnored(t *testing.T) {
	sets, deleted := runCull(newDeleteTestZone(), []libdns.Record{
		libdns.RR{Name: "a", Type: "A", Data: "192.0.2.99"},
	})
	if len(deleted) != 0 || len(sets) != 0 {
		t.Fatalf("expected no-op when value absent, got sets=%#v deleted=%#v", sets, deleted)
	}
}

func TestDeleteRecords_ExactMatchPartialReplace(t *testing.T) {
	sets, deleted := runCull(newDeleteTestZone(), []libdns.Record{
		libdns.RR{Name: "a", Type: "A", Data: "192.0.2.2"},
	})
	if len(deleted) != 1 {
		t.Fatalf("expected 1 deleted, got %#v", deleted)
	}
	addr, ok := deleted[0].(libdns.Address)
	if !ok {
		t.Fatalf("expected deleted record parsed as libdns.Address, got %T", deleted[0])
	}
	if addr.Name != "a" || addr.TTL != 60*time.Second || addr.IP.String() != "192.0.2.2" {
		t.Fatalf("unexpected parsed delete: %+v", addr)
	}
	rs, ok := rrsetByName(sets, "a.example.org.", "A")
	if !ok || len(rs.Records) != 2 {
		t.Fatalf("expected A rrset with 2 survivors, got %#v", sets)
	}
}

func TestDeleteRecords_CaseInsensitiveNameAndType(t *testing.T) {
	z := &zones.Zone{ResourceRecordSets: []zones.ResourceRecordSet{{
		Name: "www.example.org.", Type: "A", TTL: 60,
		Records: []zones.Record{{Content: "1.1.1.1"}, {Content: "2.2.2.2"}},
	}}}
	sets, deleted := runCull(z, []libdns.Record{
		libdns.RR{Name: "WWW.EXAMPLE.ORG.", Type: "a", Data: "2.2.2.2"},
	})
	if len(deleted) != 1 || deleted[0].RR().Data != "2.2.2.2" {
		t.Fatalf("expected only 2.2.2.2 deleted, got %#v", deleted)
	}
	if len(sets) != 1 || len(sets[0].Records) != 1 || sets[0].Records[0].Content != "1.1.1.1" {
		t.Fatalf("expected 1.1.1.1 to survive, got %#v", sets)
	}
}

func TestDeleteRecords_TTLMatching(t *testing.T) {
	for _, tt := range []struct {
		name    string
		ttl     time.Duration
		deleted int
	}{
		{"mismatch ignored", 999 * time.Second, 0},
		{"exact match", 60 * time.Second, 1},
		{"zero is wildcard", 0, 1},
		{"sub-second truncates to zero wildcard", 500 * time.Millisecond, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, deleted := runCull(newDeleteTestZone(), []libdns.Record{
				libdns.RR{Name: "a", Type: "A", TTL: tt.ttl, Data: "192.0.2.1"},
			})
			if len(deleted) != tt.deleted {
				t.Fatalf("ttl=%v: expected %d deleted, got %#v", tt.ttl, tt.deleted, deleted)
			}
		})
	}
}

func TestDeleteRecords_EmptyTypeWildcardAcrossTypes(t *testing.T) {
	sets, deleted := runCull(newDeleteTestZone(), []libdns.Record{
		libdns.RR{Name: "a", Type: "", Data: ""},
	})
	if len(deleted) != 4 {
		t.Fatalf("expected 4 deleted across A and TXT, got %#v", deletedValues(deleted))
	}
	if _, ok := rrsetByName(sets, "a.example.org.", "A"); !ok {
		t.Fatalf("expected A rrset mutation")
	}
	if _, ok := rrsetByName(sets, "a.example.org.", "TXT"); !ok {
		t.Fatalf("expected TXT rrset mutation")
	}
	if _, ok := rrsetByName(sets, "b.example.org.", "A"); ok {
		t.Fatalf("unrelated name b.example.org. should not be mutated")
	}
	var sawTXT bool
	for _, r := range deleted {
		if _, ok := r.(libdns.TXT); ok {
			sawTXT = true
		}
	}
	if !sawTXT {
		t.Fatalf("expected a parsed libdns.TXT among deleted: %#v", deleted)
	}
}

func TestDeleteRecords_EmptyValueWildcardScopedToType(t *testing.T) {
	sets, deleted := runCull(newDeleteTestZone(), []libdns.Record{
		libdns.RR{Name: "a", Type: "A", Data: ""},
	})
	if len(deleted) != 3 {
		t.Fatalf("expected all 3 A values deleted, got %#v", deletedValues(deleted))
	}
	if _, ok := rrsetByName(sets, "a.example.org.", "TXT"); ok {
		t.Fatalf("TXT must be untouched when value wildcard is scoped to type A")
	}
}

func TestDeleteRecords_TXTMatchUsesSanitizedValue(t *testing.T) {
	_, deleted := runCull(newDeleteTestZone(), []libdns.Record{
		libdns.RR{Name: "a", Type: "TXT", Data: "hello"},
	})
	if len(deleted) != 1 {
		t.Fatalf("expected raw \"hello\" to match stored %q, got %#v", `"hello"`, deletedValues(deleted))
	}
	if _, ok := deleted[0].(libdns.TXT); !ok {
		t.Fatalf("expected parsed libdns.TXT, got %T", deleted[0])
	}
}

func TestDeleteRecords_DuplicateInputDeletesOnce(t *testing.T) {
	_, deleted := runCull(newDeleteTestZone(), []libdns.Record{
		libdns.RR{Name: "a", Type: "A", Data: "192.0.2.1"},
		libdns.RR{Name: "a", Type: "A", Data: "192.0.2.1"},
	})
	if len(deleted) != 1 {
		t.Fatalf("expected duplicate input to delete a value once, got %#v", deletedValues(deleted))
	}
}
