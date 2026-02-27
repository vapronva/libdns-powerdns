package powerdns

import (
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/mittwald/go-powerdns/apis/zones"
)

func TestMergeRRecsCaseInsensitiveNameAndType(t *testing.T) {
	fullZone := &zones.Zone{
		ResourceRecordSets: []zones.ResourceRecordSet{
			{
				Name: "www.example.com.",
				Type: "A",
				TTL:  60,
				Records: []zones.Record{
					{Content: "1.1.1.1"},
				},
			},
		},
	}
	newRecords := []libdns.Record{
		libdns.RR{
			Name: "WWW.EXAMPLE.COM.",
			Type: "a",
			TTL:  60 * time.Second,
			Data: "2.2.2.2",
		},
	}
	result, err := mergeRRecs(fullZone, newRecords)
	if err != nil {
		t.Fatalf("mergeRRecs returned error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 rrset, got %d", len(result))
	}
	if got, want := len(result[0].Records), 2; got != want {
		t.Fatalf("expected %d merged records, got %d: %#v", want, got, result[0].Records)
	}
}

func TestCullRRecsCaseInsensitiveNameAndType(t *testing.T) {
	fullZone := &zones.Zone{
		ResourceRecordSets: []zones.ResourceRecordSet{
			{
				Name: "www.example.com.",
				Type: "A",
				TTL:  60,
				Records: []zones.Record{
					{Content: "1.1.1.1"},
					{Content: "2.2.2.2"},
				},
			},
		},
	}
	toDelete := []libdns.Record{
		libdns.RR{
			Name: "WWW.EXAMPLE.COM.",
			Type: "a",
			Data: "2.2.2.2",
		},
	}
	result := cullRRecs(fullZone, toDelete)
	if len(result) != 1 {
		t.Fatalf("expected 1 rrset update, got %d", len(result))
	}
	if got, want := result[0].ChangeType, zones.ChangeTypeReplace; got != want {
		t.Fatalf("expected changetype %v, got %v", want, got)
	}
	if got, want := len(result[0].Records), 1; got != want {
		t.Fatalf("expected %d remaining record, got %d", want, got)
	}
	if got, want := result[0].Records[0].Content, "1.1.1.1"; got != want {
		t.Fatalf("expected remaining record %q, got %q", want, got)
	}
}
