package powerdns

import (
	"testing"

	"github.com/libdns/libdns"
	"github.com/mittwald/go-powerdns/apis/zones"
)

func TestRemoveRecordsDoesNotMutateInput(t *testing.T) {
	rRSet := zones.ResourceRecordSet{
		Name: "test.example.org.",
		Type: "A",
		TTL:  60,
		Records: []zones.Record{
			{Content: "127.0.0.1"},
			{Content: "127.0.0.2"},
			{Content: "127.0.0.3"},
		},
	}
	originalRecords := rRSet.Records
	result := removeRecords(rRSet, []libdns.RR{
		{Data: "127.0.0.2"},
	})
	if len(result.Records) != 2 {
		t.Fatalf("expected 2 records after deletion, got %d", len(result.Records))
	}
	if result.Records[0].Content != "127.0.0.1" || result.Records[1].Content != "127.0.0.3" {
		t.Fatalf("unexpected result records: %#v", result.Records)
	}
	if len(originalRecords) != 3 {
		t.Fatalf("expected original records length 3, got %d", len(originalRecords))
	}
	if originalRecords[0].Content != "127.0.0.1" ||
		originalRecords[1].Content != "127.0.0.2" ||
		originalRecords[2].Content != "127.0.0.3" {
		t.Fatalf("original records were mutated: %#v", originalRecords)
	}
}
