package powerdns

import (
	"context"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
	pdns "github.com/mittwald/go-powerdns"
	"github.com/mittwald/go-powerdns/apis/zones"

	"github.com/vapronva/libdns-powerdns/txtsanitize"
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
	rRSet.Records = slices.Clone(rRSet.Records)
	deleteItem := func(item string) []zones.Record {
		recs := rRSet.Records
		for i := len(recs) - 1; i >= 0; i-- {
			if recs[i].Content == item {
				copy(recs[i:], recs[i+1:])
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
			TTL:        int(recs[0].TTL / time.Second),
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
		switch svcb := rec.(type) {
		case libdns.ServiceBinding:
			r = svcbToRR(svcb)
		case *libdns.ServiceBinding:
			r = svcbToRR(*svcb)
		}
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

var svcParamNameToCode = map[string]int{
	"mandatory":            0,
	"alpn":                 1,
	"no-default-alpn":      2,
	"port":                 3,
	"ipv4hint":             4,
	"ech":                  5,
	"ipv6hint":             6,
	"dohpath":              7,
	"ohttp":                8,
	"tls-supported-groups": 9,
}

var svcParamCodeToName = map[int]string{
	0: "mandatory",
	1: "alpn",
	2: "no-default-alpn",
	3: "port",
	4: "ipv4hint",
	5: "ech",
	6: "ipv6hint",
	7: "dohpath",
	8: "ohttp",
	9: "tls-supported-groups",
}

func svcbToRR(s libdns.ServiceBinding) libdns.RR {
	rr := s.RR()
	var params string
	if s.Priority != 0 {
		params = paramsToString(s.Params)
	}
	switch {
	case s.Priority == 0 && s.Target == "" && params == "":
		rr.Data = ""
	case params == "":
		rr.Data = fmt.Sprintf("%d %s", s.Priority, s.Target)
	default:
		rr.Data = fmt.Sprintf("%d %s %s", s.Priority, s.Target, params)
	}
	return rr
}

func parseGenericSvcParamCode(key string) (int, bool) {
	if !strings.HasPrefix(key, "key") || len(key) <= 3 {
		return 0, false
	}
	code, err := strconv.Atoi(key[3:])
	if err != nil || code < 0 || code > 65535 {
		return 0, false
	}
	return code, true
}

func canonicalSvcParamKey(key string) string {
	if code, ok := parseGenericSvcParamCode(key); ok {
		if canonical, ok := svcParamCodeToName[code]; ok {
			return canonical
		}
	}
	return key
}

func svcParamCode(key string) (int, bool) {
	if code, ok := svcParamNameToCode[key]; ok {
		return code, true
	}
	return parseGenericSvcParamCode(key)
}

func lessSvcParamKey(left, right string) bool {
	leftCode, leftKnown := svcParamCode(left)
	rightCode, rightKnown := svcParamCode(right)
	switch {
	case leftKnown && rightKnown && leftCode != rightCode:
		return leftCode < rightCode
	case leftKnown != rightKnown:
		return leftKnown
	default:
		return left < right
	}
}

func canonicalMandatoryValues(vals []string) []string {
	if len(vals) == 0 {
		return vals
	}
	seen := make(map[string]struct{}, len(vals))
	uniq := make([]string, 0, len(vals))
	for _, val := range vals {
		key := canonicalSvcParamKey(strings.ToLower(val))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		uniq = append(uniq, key)
	}
	sort.Slice(uniq, func(i, j int) bool {
		return lessSvcParamKey(uniq[i], uniq[j])
	})
	return uniq
}

func svcParamAlwaysQuotes(key string) bool {
	switch key {
	case "ech", "dohpath":
		return true
	default:
		_, known := svcParamNameToCode[key]
		return !known
	}
}

func paramsToString(params libdns.SvcParams) string {
	canonicalParams := make(libdns.SvcParams, len(params))
	for key, vals := range params {
		key = canonicalSvcParamKey(strings.ToLower(key))
		canonicalParams[key] = append(canonicalParams[key], slices.Clone(vals)...)
	}
	keys := make([]string, 0, len(canonicalParams))
	for key := range canonicalParams {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return lessSvcParamKey(keys[i], keys[j])
	})
	var sb strings.Builder
	for _, key := range keys {
		vals := canonicalParams[key]
		if key == "mandatory" {
			vals = canonicalMandatoryValues(vals)
		}
		var hasVal bool
		for _, val := range vals {
			if len(val) > 0 {
				hasVal = true
				break
			}
		}
		if !hasVal {
			vals = nil
		}
		if sb.Len() > 0 {
			sb.WriteRune(' ')
		}
		sb.WriteString(key)
		needsQuotes := svcParamAlwaysQuotes(key)
		if !needsQuotes {
			for _, val := range vals {
				if strings.ContainsAny(val, `" `) {
					needsQuotes = true
					break
				}
			}
		}
		if hasVal {
			sb.WriteRune('=')
		}
		if hasVal && needsQuotes {
			sb.WriteRune('"')
		}
		for i, val := range vals {
			if i > 0 {
				sb.WriteRune(',')
			}
			val = strings.ReplaceAll(val, `"`, `\"`)
			val = strings.ReplaceAll(val, `,`, `\,`)
			sb.WriteString(val)
		}
		if hasVal && needsQuotes {
			sb.WriteRune('"')
		}
	}
	return sb.String()
}
