package powerdns

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/libdns/libdns"
	"github.com/vapronva/libdns-powerdns/txtsanitize"

	pdns "github.com/mittwald/go-powerdns"
	"github.com/mittwald/go-powerdns/apis/zones"
)

type client struct {
	sID string
	pdns.Client
}

func newClient(ServerID, ServerURL, APIToken string, debug io.Writer) (*client, error) {
	if debug == nil {
		debug = io.Discard
	}
	c, err := pdns.New(
		pdns.WithBaseURL(ServerURL),
		pdns.WithAPIKeyAuthentication(APIToken),
		pdns.WithDebuggingOutput(debug),
	)
	if err != nil {
		return nil, err
	}
	return &client{
		sID:    ServerID,
		Client: c,
	}, nil
}

func (c *client) updateRRs(ctx context.Context, zoneID string, recs []zones.ResourceRecordSet) error {
	err := c.Zones().AddRecordSetsToZone(ctx, c.sID, zoneID, recs)
	if err != nil {
		return err
	}
	return nil
}

func mergeRRecs(fullZone *zones.Zone, records []libdns.Record) ([]zones.ResourceRecordSet, error) {
	// pdns doesn't really have an append functionality, so we have to fake it by
	// fetching existing rrsets for the zone and see if any already exist.  If so,
	// merge those with the existing data.  Otherwise just add the record.
	inHash := makeLDRecHash(records)
	var rrsets []zones.ResourceRecordSet
	// Merge existing resource record sets with any that were passed in to modify.
	for _, t := range fullZone.ResourceRecordSets {
		k := key(t.Name, t.Type)
		if recs, ok := inHash[k]; ok && len(recs) > 0 {
			rr := zones.ResourceRecordSet{
				Name:       t.Name,
				Type:       t.Type,
				TTL:        t.TTL,
				ChangeType: zones.ChangeTypeReplace,
				Comments:   t.Comments,
				Records:    slices.Clone(t.Records),
			}
			copy(rr.Records, t.Records)
			// squash duplicate values
			dupes := make(map[string]bool)
			for _, prec := range t.Records {
				dupes[prec.Content] = true
			}
			// now for our additions
			for _, rec := range recs {
				if !dupes[rec.Data] {
					rr.Records = append(rr.Records, zones.Record{
						Content: rec.Data,
					})
					dupes[rec.Data] = true
				}
			}
			rrsets = append(rrsets, rr)
			delete(inHash, k)
		}
	}
	// Any remaining in our input hash need to be straight adds / creates.
	rrsets = append(rrsets, convertLDHash(inHash)...)
	return rrsets, nil
}

// generate RessourceRecordSets that will delete records from zone
func cullRRecs(fullZone *zones.Zone, records []libdns.Record) []zones.ResourceRecordSet {
	inHash := makeLDRecHash(records)
	var rRSets []zones.ResourceRecordSet
	for _, t := range fullZone.ResourceRecordSets {
		k := key(t.Name, t.Type)
		if recs, ok := inHash[k]; ok && len(recs) > 0 {
			rRec := removeRecords(t, recs)
			if len(rRec.Records) == 0 {
				rRec.ChangeType = zones.ChangeTypeDelete
			} else {
				rRec.ChangeType = zones.ChangeTypeReplace
			}
			rRSets = append(rRSets, rRec)
		}
	}
	return rRSets

}

// remove culls from rRSet record values
func removeRecords(rRSet zones.ResourceRecordSet, culls []libdns.RR) zones.ResourceRecordSet {
	deleteItem := func(item string) []zones.Record {
		recs := rRSet.Records
		for i := len(recs) - 1; i >= 0; i-- {
			if recs[i].Content == item {
				copy(recs[i:], recs[:i+1])
				recs = recs[:len(recs)-1]
			}
		}
		return recs
	}
	for _, c := range culls {
		rRSet.Records = deleteItem(c.Data)
	}
	return rRSet
}

func convertLDHash(inHash map[string][]libdns.RR) []zones.ResourceRecordSet {
	var rrsets []zones.ResourceRecordSet
	for _, recs := range inHash {
		if len(recs) == 0 {
			continue
		}

		rr := zones.ResourceRecordSet{
			Name:       recs[0].Name,
			Type:       recs[0].Type,
			TTL:        int(recs[0].TTL),
			ChangeType: zones.ChangeTypeReplace,
		}
		for _, rec := range recs {
			rr.Records = append(rr.Records, zones.Record{
				Content: rec.Data,
			})
		}
		rrsets = append(rrsets, rr)
	}
	return rrsets
}

func key(Name, Type string) string {
	return Name + ":" + Type
}

func makeLDRecHash(records []libdns.Record) map[string][]libdns.RR {
	// Keep track of records grouped by name + type
	inHash := make(map[string][]libdns.RR)

	for _, r := range records {
		k := key(r.RR().Name, r.RR().Type)
		inHash[k] = append(inHash[k], r.RR())
	}
	return inHash
}

func (c *client) fullZone(ctx context.Context, zoneName string) (*zones.Zone, error) {
	zc := c.Zones()
	shortZone, err := c.shortZone(ctx, zoneName)
	if err != nil {
		return nil, err
	}
	fullZone, err := zc.GetZone(ctx, c.sID, shortZone.ID)
	if err != nil {
		return nil, err
	}
	return fullZone, nil
}

func (c *client) shortZone(ctx context.Context, zoneName string) (*zones.Zone, error) {
	zc := c.Zones()
	shortZones, err := zc.ListZone(ctx, c.sID, zoneName)
	if err != nil {
		return nil, err
	}
	if len(shortZones) != 1 {
		return nil, fmt.Errorf("zone not found")
	}
	return &shortZones[0], nil
}

func (c *client) zoneID(ctx context.Context, zoneName string) (string, error) {
	shortZone, err := c.shortZone(ctx, zoneName)
	if err != nil {
		return "", err
	}
	return shortZone.ID, nil
}

func convertNamesToAbsolute(zone string, records []libdns.Record) []libdns.Record {
	out := make([]libdns.Record, 0, len(records))
	for _, rec := range records {
		r := rec.RR()
		abs := libdns.AbsoluteName(r.Name, zone)
		if !strings.HasSuffix(abs, ".") {
			abs += "."
		}
		data := r.Data
		if r.Type == "TXT" {
			data = txtsanitize.TXTSanitize(data)
		}
		out = append(out, libdns.RR{
			Name: abs,
			TTL:  r.TTL,
			Type: r.Type,
			Data: data,
		})
	}
	return out
}
