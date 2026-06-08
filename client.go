package powerdns

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
	pdns "github.com/mittwald/go-powerdns"
	"github.com/mittwald/go-powerdns/apis/zones"

	"github.com/vapronva/libdns-powerdns/txtsanitize"
)

type client struct {
	pdns.Client

	sID string
}

func newClient(serverID, serverURL, apiToken string, debug io.Writer) (*client, error) {
	if debug == nil {
		debug = io.Discard
	}
	c, err := pdns.New(
		pdns.WithBaseURL(serverURL),
		pdns.WithAPIKeyAuthentication(apiToken),
		pdns.WithDebuggingOutput(debug),
	)
	if err != nil {
		return nil, err
	}
	return &client{
		sID:    serverID,
		Client: c,
	}, nil
}

func (c *client) updateRRs(ctx context.Context, zoneID string, recs []zones.ResourceRecordSet) error {
	if len(recs) == 0 {
		return nil
	}
	return c.Zones().AddRecordSetsToZone(ctx, c.sID, zoneID, recs)
}

func newRRSet(name, typ string, ttl int, comments []zones.Comment, recs []zones.Record) zones.ResourceRecordSet {
	return zones.ResourceRecordSet{
		Name:     name,
		Type:     typ,
		TTL:      ttl,
		Comments: comments,
		Records:  recs,
	}
}

func mergeRRecs(fullZone *zones.Zone, records []libdns.Record) []zones.ResourceRecordSet {
	inHash := makeLDRecHash(records)
	var rrsets []zones.ResourceRecordSet
	for _, t := range fullZone.ResourceRecordSets {
		k := key(t.Name, t.Type)
		recs, ok := inHash[k]
		if !ok || len(recs) == 0 {
			continue
		}
		merged := slices.Clone(t.Records)
		seen := make(map[string]bool, len(merged)+len(recs))
		for _, prec := range t.Records {
			seen[prec.Content] = true
		}
		for _, rec := range recs {
			if !seen[rec.Data] {
				merged = append(merged, zones.Record{Content: rec.Data})
				seen[rec.Data] = true
			}
		}
		rrsets = append(rrsets, newRRSet(t.Name, t.Type, t.TTL, t.Comments, merged))
		delete(inHash, k)
	}
	rrsets = append(rrsets, convertLDHash(inHash)...)
	return rrsets
}

func indexByName(fullZone *zones.Zone) map[string][]int {
	idx := make(map[string][]int, len(fullZone.ResourceRecordSets))
	for i := range fullZone.ResourceRecordSets {
		n := strings.ToLower(fullZone.ResourceRecordSets[i].Name)
		idx[n] = append(idx[n], i)
	}
	return idx
}

type cull struct {
	all  bool
	vals map[string]struct{}
}

func cullPlans(fullZone *zones.Zone, converted, original []libdns.Record) map[int]*cull {
	plans := make(map[int]*cull)
	plan := func(idx int) *cull {
		if plans[idx] == nil {
			plans[idx] = &cull{vals: map[string]struct{}{}}
		}
		return plans[idx]
	}
	byName := indexByName(fullZone)
	for i := range min(len(converted), len(original)) {
		conv := converted[i].RR()
		orig := original[i].RR()
		wantTTL := int(conv.TTL / time.Second)
		for _, idx := range byName[strings.ToLower(conv.Name)] {
			t := &fullZone.ResourceRecordSets[idx]
			switch {
			case orig.Type != "" && !strings.EqualFold(t.Type, conv.Type):
			case wantTTL != 0 && wantTTL != t.TTL:
			case orig.Data == "":
				plan(idx).all = true
			default:
				want := conv.Data
				if charString(t.Type) {
					want = txtsanitize.TXTSanitize(orig.Data)
				}
				if slices.ContainsFunc(t.Records, func(r zones.Record) bool { return r.Content == want }) {
					plan(idx).vals[want] = struct{}{}
				}
			}
		}
	}
	return plans
}

func cullRRecs(
	zone string,
	fullZone *zones.Zone,
	converted, original []libdns.Record,
) ([]zones.ResourceRecordSet, []libdns.Record) {
	var rRSets []zones.ResourceRecordSet
	var deleted []libdns.Record
	for idx, p := range cullPlans(fullZone, converted, original) {
		t := &fullZone.ResourceRecordSets[idx]
		kept := make([]zones.Record, 0, len(t.Records))
		for _, rec := range t.Records {
			if _, drop := p.vals[rec.Content]; !p.all && !drop {
				kept = append(kept, rec)
				continue
			}
			deleted = append(deleted, parseZoneRecord(zone, t.Name, t.Type, t.TTL, rec.Content))
		}
		if len(kept) != len(t.Records) {
			rRSets = append(rRSets, newRRSet(t.Name, t.Type, t.TTL, t.Comments, kept))
		}
	}
	return rRSets, deleted
}

func charString(typ string) bool {
	switch strings.ToUpper(typ) {
	case "TXT", "SPF":
		return true
	default:
		return false
	}
}

func parseZoneRecord(zone, name, typ string, ttl int, content string) libdns.Record {
	if charString(typ) {
		content = txtsanitize.TXTUnquote(content)
	}
	return parseRR(libdns.RR{
		Name: libdns.RelativeName(name, zone),
		TTL:  time.Duration(ttl) * time.Second,
		Type: typ,
		Data: content,
	})
}

func parseRR(rr libdns.RR) libdns.Record {
	if parsed, err := rr.Parse(); err == nil {
		return parsed
	}
	return rr
}

func parseInputRecords(records []libdns.Record) []libdns.Record {
	out := make([]libdns.Record, 0, len(records))
	for _, rec := range records {
		out = append(out, parseRR(rec.RR()))
	}
	return out
}

func recordsFromRRSets(zone string, sets []zones.ResourceRecordSet) []libdns.Record {
	var out []libdns.Record
	for _, s := range sets {
		for _, r := range s.Records {
			out = append(out, parseZoneRecord(zone, s.Name, s.Type, s.TTL, r.Content))
		}
	}
	return out
}

const defaultTTL = 3600

func convertLDHash(inHash map[string][]libdns.RR) []zones.ResourceRecordSet {
	var rrsets []zones.ResourceRecordSet
	for _, recs := range inHash {
		if len(recs) == 0 {
			continue
		}
		ttl := int(recs[0].TTL / time.Second)
		if ttl <= 0 {
			ttl = defaultTTL
		}
		out := make([]zones.Record, 0, len(recs))
		seen := make(map[string]struct{}, len(recs))
		for _, rec := range recs {
			if _, dup := seen[rec.Data]; dup {
				continue
			}
			seen[rec.Data] = struct{}{}
			out = append(out, zones.Record{Content: rec.Data})
		}
		rrsets = append(rrsets, newRRSet(recs[0].Name, recs[0].Type, ttl, nil, out))
	}
	return rrsets
}

func key(name, typ string) string {
	return strings.ToLower(name) + ":" + strings.ToUpper(typ)
}

func makeLDRecHash(records []libdns.Record) map[string][]libdns.RR {
	inHash := make(map[string][]libdns.RR)
	for _, r := range records {
		rr := r.RR()
		k := key(rr.Name, rr.Type)
		inHash[k] = append(inHash[k], rr)
	}
	return inHash
}

func canonicalZone(zone string) string {
	if !strings.HasSuffix(zone, ".") {
		return zone + "."
	}
	return zone
}

func (c *client) fullZone(ctx context.Context, zoneName string) (*zones.Zone, error) {
	shortZone, err := c.shortZone(ctx, zoneName)
	if err != nil {
		return nil, err
	}
	return c.Zones().GetZone(ctx, c.sID, shortZone.ID)
}

func (c *client) shortZone(ctx context.Context, zoneName string) (*zones.Zone, error) {
	shortZones, err := c.Zones().ListZone(ctx, c.sID, canonicalZone(zoneName))
	if err != nil {
		return nil, err
	}
	if len(shortZones) != 1 {
		return nil, fmt.Errorf("zone %q: expected exactly one match, got %d", zoneName, len(shortZones))
	}
	return &shortZones[0], nil
}

func convertNamesToAbsolute(zone string, records []libdns.Record) []libdns.Record {
	zone = canonicalZone(zone)
	out := make([]libdns.Record, 0, len(records))
	for _, rec := range records {
		r := rec.RR()
		switch svcb := rec.(type) {
		case libdns.ServiceBinding:
			r = svcbToRR(svcb)
		case *libdns.ServiceBinding:
			r = svcbToRR(*svcb)
		default:
			if sb, ok := svcbFromRR(r); ok {
				r = svcbToRR(sb)
			}
		}
		data := r.Data
		if charString(r.Type) {
			data = txtsanitize.TXTSanitize(data)
		}
		out = append(out, libdns.RR{
			Name: libdns.AbsoluteName(r.Name, zone),
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

var svcParamCodeToName = func() map[int]string {
	m := make(map[int]string, len(svcParamNameToCode))
	for name, code := range svcParamNameToCode {
		m[code] = name
	}
	return m
}()

func svcbFromRR(r libdns.RR) (libdns.ServiceBinding, bool) {
	switch strings.ToUpper(r.Type) {
	case "HTTPS", "SVCB":
	default:
		return libdns.ServiceBinding{}, false
	}
	parsed, err := r.Parse()
	if err != nil {
		return libdns.ServiceBinding{}, false
	}
	sb, ok := parsed.(libdns.ServiceBinding)
	return sb, ok
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
	code, ok := parseGenericSvcParamCode(key)
	if !ok {
		return key
	}
	if canonical, found := svcParamCodeToName[code]; found {
		return canonical
	}
	return key
}

func svcParamCode(key string) (int, bool) {
	if code, ok := svcParamNameToCode[key]; ok {
		return code, true
	}
	return parseGenericSvcParamCode(key)
}

func compareSvcParamKey(left, right string) int {
	leftCode, leftKnown := svcParamCode(left)
	rightCode, rightKnown := svcParamCode(right)
	switch {
	case leftKnown && rightKnown:
		return cmp.Compare(leftCode, rightCode)
	case leftKnown != rightKnown:
		if leftKnown {
			return -1
		}
		return 1
	default:
		return cmp.Compare(left, right)
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
	slices.SortFunc(uniq, compareSvcParamKey)
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
		canonicalParams[key] = append(canonicalParams[key], vals...)
	}
	keys := make([]string, 0, len(canonicalParams))
	for key := range canonicalParams {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, compareSvcParamKey)
	var sb strings.Builder
	for _, key := range keys {
		writeSvcParam(&sb, key, canonicalParams[key])
	}
	return sb.String()
}

func svcParamHasValue(vals []string) bool {
	for _, val := range vals {
		if len(val) > 0 {
			return true
		}
	}
	return false
}

func svcParamNeedsQuotes(key string, vals []string) bool {
	if svcParamAlwaysQuotes(key) {
		return true
	}
	for _, val := range vals {
		if strings.ContainsAny(val, `" `) {
			return true
		}
	}
	return false
}

func writeSvcParam(sb *strings.Builder, key string, vals []string) {
	if key == "mandatory" {
		vals = canonicalMandatoryValues(vals)
	}
	hasVal := svcParamHasValue(vals)
	if !hasVal {
		vals = nil
	}
	if sb.Len() > 0 {
		sb.WriteRune(' ')
	}
	sb.WriteString(key)
	quoted := hasVal && svcParamNeedsQuotes(key, vals)
	if hasVal {
		sb.WriteRune('=')
	}
	if quoted {
		sb.WriteRune('"')
	}
	for i, val := range vals {
		if i > 0 {
			sb.WriteRune(',')
		}
		val = strings.ReplaceAll(val, `\`, `\\`)
		val = strings.ReplaceAll(val, `"`, `\"`)
		val = strings.ReplaceAll(val, `,`, `\,`)
		sb.WriteString(val)
	}
	if quoted {
		sb.WriteRune('"')
	}
}
