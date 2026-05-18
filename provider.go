package powerdns

import (
	"cmp"
	"context"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/libdns/libdns"
)

type Provider struct {
	ServerURL string `json:"server_url"`
	ServerID  string `json:"server_id,omitempty"`
	APIToken  string `json:"api_token,omitempty"`
	Debug     string `json:"debug,omitempty"`
	mu        sync.Mutex
	writeMu   sync.Mutex
	c         *client
}

func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}
	prec, err := c.fullZone(ctx, zone)
	if err != nil {
		return nil, err
	}
	recs := make([]libdns.Record, 0, len(prec.ResourceRecordSets))
	for _, rec := range prec.ResourceRecordSets {
		for _, v := range rec.Records {
			recs = append(recs, parseZoneRecord(zone, rec.Name, rec.Type, rec.TTL, v.Content))
		}
	}
	return recs, nil
}

func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	fullZone, err := c.fullZone(ctx, zone)
	if err != nil {
		return nil, libdns.AtomicErr(err)
	}
	rrecs := mergeRRecs(fullZone, convertNamesToAbsolute(zone, records))
	if err = c.updateRRs(ctx, fullZone.ID, rrecs); err != nil {
		return nil, libdns.AtomicErr(err)
	}
	return parseInputRecords(records), nil
}

func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	zID, err := c.zoneID(ctx, zone)
	if err != nil {
		return nil, libdns.AtomicErr(err)
	}
	rRecs := convertLDHash(makeLDRecHash(convertNamesToAbsolute(zone, records)))
	if err = c.updateRRs(ctx, zID, rRecs); err != nil {
		return nil, libdns.AtomicErr(err)
	}
	return recordsFromRRSets(zone, rRecs), nil
}

func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	fullZone, err := c.fullZone(ctx, zone)
	if err != nil {
		return nil, libdns.AtomicErr(err)
	}
	rRSets, deleted := cullRRecs(zone, fullZone, convertNamesToAbsolute(zone, records), records)
	if err = c.updateRRs(ctx, fullZone.ID, rRSets); err != nil {
		return nil, libdns.AtomicErr(err)
	}
	return deleted, nil
}

func (p *Provider) client() (*client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.c == nil {
		var debug io.Writer
		switch strings.ToLower(p.Debug) {
		case "stdout", "yes", "true", "1":
			debug = os.Stdout
		case "stderr":
			debug = os.Stderr
		}
		c, err := newClient(cmp.Or(p.ServerID, "localhost"), p.ServerURL, p.APIToken, debug)
		if err != nil {
			return nil, err
		}
		p.c = c
	}
	return p.c, nil
}

var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
