package powerdns

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/mittwald/go-powerdns/apis/zones"
)

func TestPDNSClient(t *testing.T) {
	doRun, _ := strconv.ParseBool(os.Getenv("PDNS_RUN_INTEGRATION_TEST"))
	if !doRun {
		t.Skip("skipping because PDNS_RUN_INTEGRATION_TEST was not set")
	}
	composeCmd, composePrefix, ok := composeRunner()
	if !ok {
		t.Skip("docker compose (plugin) or docker-compose is not present, skipping")
	}
	mustCompose(t, composeCmd, composePrefix, "rm", "-sfv")
	mustCompose(t, composeCmd, composePrefix, "down", "-v")
	mustCompose(t, composeCmd, composePrefix, "up", "-d")
	defer func() {
		if skipCleanup, _ := strconv.ParseBool(os.Getenv("PDNS_SKIP_CLEANUP")); !skipCleanup {
			if errCMD := runCompose(composeCmd, composePrefix, "down", "-v"); errCMD != nil {
				t.Errorf("docker compose cleanup failed: %s", errCMD)
			}
		}
	}()
	waitForAPI(t, "http://localhost:8081", "secret")
	z := zones.Zone{
		Name: "example.org.",
		Type: zones.ZoneTypeZone,
		Kind: zones.ZoneKindNative,
		ResourceRecordSets: []zones.ResourceRecordSet{
			{
				Name:    "1.example.org.",
				Type:    "A",
				TTL:     60,
				Records: []zones.Record{{Content: "127.0.0.1"}, {Content: "127.0.0.2"}, {Content: "127.0.0.3"}},
			},
			{
				Name:    "1.example.org.",
				Type:    "TXT",
				TTL:     60,
				Records: []zones.Record{{Content: `"This is text"`}},
			},
			{
				Name:    "2.example.org.",
				Type:    "A",
				TTL:     60,
				Records: []zones.Record{{Content: "127.0.0.4"}, {Content: "127.0.0.5"}, {Content: "127.0.0.6"}},
			},
		},
		Serial:      1,
		Nameservers: []string{"ns1.example.org.", "ns2.example.org."},
	}
	p := &Provider{
		ServerURL: "http://localhost:8081",
		ServerID:  "localhost",
		APIToken:  "secret",
		Debug:     os.Getenv("PDNS_DEBUG"),
	}
	mustCreateZone(t, p, z)
	for _, table := range []struct {
		name      string
		operation string
		zone      string
		Type      string
		records   []libdns.Record
		want      []string
	}{
		{
			name:      "Get zone without trailing dot",
			operation: "records",
			zone:      "example.org",
			Type:      "A",
			want:      []string{"1:127.0.0.1", "1:127.0.0.2", "1:127.0.0.3", "2:127.0.0.4", "2:127.0.0.5", "2:127.0.0.6"},
		},
		{
			name:      "Append A record",
			operation: "append",
			zone:      "example.org.",
			Type:      "A",
			records:   []libdns.Record{libdns.RR{Name: "2", Type: "A", Data: "127.0.0.7"}},
			want: []string{
				"1:127.0.0.1", "1:127.0.0.2", "1:127.0.0.3",
				"2:127.0.0.4", "2:127.0.0.5", "2:127.0.0.6", "2:127.0.0.7",
			},
		},
		{
			name:      "Append already-quoted TXT",
			operation: "append",
			zone:      "example.org.",
			Type:      "TXT",
			records:   []libdns.Record{libdns.RR{Name: "1", Type: "TXT", Data: `"This is also some text"`}},
			want:      []string{`1:"This is text"`, `1:"This is also some text"`},
		},
		{
			name:      "Append unquoted TXT",
			operation: "append",
			zone:      "example.org.",
			Type:      "TXT",
			records:   []libdns.Record{libdns.RR{Name: "1", Type: "TXT", Data: "This is some weird text that isn't quoted"}},
			want: []string{
				`1:"This is text"`, `1:"This is also some text"`,
				`1:"This is some weird text that isn't quoted"`,
			},
		},
		{
			name:      "Append TXT with embedded quotes",
			operation: "append",
			zone:      "example.org.",
			Type:      "TXT",
			records:   []libdns.Record{libdns.RR{Name: "1", Type: "TXT", Data: `This is some weird text that "has embedded quoting"`}},
			want: []string{
				`1:"This is text"`, `1:"This is also some text"`,
				`1:"This is some weird text that isn't quoted"`,
				`1:"This is some weird text that \"has embedded quoting\""`,
			},
		},
		{
			name:      "Append TXT with backslashes",
			operation: "append",
			zone:      "example.org.",
			Type:      "TXT",
			records:   []libdns.Record{libdns.RR{Name: "1", Type: "TXT", Data: `ç is equal to \195\167`}},
			want: []string{
				`1:"This is text"`, `1:"This is also some text"`,
				`1:"This is some weird text that isn't quoted"`,
				`1:"This is some weird text that \"has embedded quoting\""`,
				`1:"ç is equal to \\195\\167"`,
			},
		},
		{
			name:      "Append HTTPS record with ECH",
			operation: "append",
			zone:      "example.org.",
			Type:      "HTTPS",
			records: []libdns.Record{libdns.ServiceBinding{
				Name: "svc", Scheme: "https", Priority: 1, Target: ".",
				Params: libdns.SvcParams{"ech": {"Zm9vYmFy"}},
			}},
			want: []string{"svc:1 . ech=Zm9vYmFy"},
		},
		{
			name:      "Delete A record",
			operation: "delete",
			zone:      "example.org.",
			Type:      "A",
			records:   []libdns.Record{libdns.RR{Name: "2", Type: "A", Data: "127.0.0.7"}},
			want:      []string{"1:127.0.0.1", "1:127.0.0.2", "1:127.0.0.3", "2:127.0.0.4", "2:127.0.0.5", "2:127.0.0.6"},
		},
		{
			name:      "Set replaces only the named rrsets",
			operation: "set",
			zone:      "example.org.",
			Type:      "A",
			records: []libdns.Record{
				libdns.RR{Name: "2", Type: "A", Data: "127.0.0.1"},
				libdns.RR{Name: "1", Type: "A", Data: "127.0.0.1"},
			},
			want: []string{"1:127.0.0.1", "2:127.0.0.1"},
		},
	} {
		t.Run(table.name, func(t *testing.T) {
			var err error
			switch table.operation {
			case "records":
			case "append":
				_, err = p.AppendRecords(context.Background(), table.zone, table.records)
			case "set":
				_, err = p.SetRecords(context.Background(), table.zone, table.records)
			case "delete":
				_, err = p.DeleteRecords(context.Background(), table.zone, table.records)
			}
			if err != nil {
				t.Fatalf("failed to %s records: %s", table.operation, err)
			}
			recs, err := p.GetRecords(context.Background(), table.zone)
			if err != nil {
				t.Fatalf("error fetching zone: %s", err)
			}
			var have []string
			for _, rr := range recs {
				if rr.RR().Type != table.Type {
					continue
				}
				have = append(have, fmt.Sprintf("%s:%s", rr.RR().Name, rr.RR().Data))
			}
			sort.Strings(have)
			sort.Strings(table.want)
			if !reflect.DeepEqual(have, table.want) {
				t.Errorf("assertion failed: have %#v want %#v", have, table.want)
			}
		})
	}
}

func waitForAPI(t *testing.T, baseURL, apiKey string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/servers", nil)
		req.Header.Set("X-Api-Key", apiKey)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatal("PowerDNS API did not become ready within 90s")
}

func which(cmd string) (string, bool) {
	pth, err := exec.LookPath(cmd)
	if err != nil {
		return "", false
	}
	return pth, true
}

func runCmd(cmd string, args ...string) error {
	c := exec.Command(cmd, args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func runCompose(cmd string, prefix []string, args ...string) error {
	composeArgs := make([]string, 0, len(prefix)+len(args))
	composeArgs = append(composeArgs, prefix...)
	composeArgs = append(composeArgs, args...)
	return runCmd(cmd, composeArgs...)
}

func mustCompose(t *testing.T, cmd string, prefix []string, args ...string) {
	t.Helper()
	if err := runCompose(cmd, prefix, args...); err != nil {
		t.Fatalf("docker compose %v failed: %s", args, err)
	}
}

func mustCreateZone(t *testing.T, p *Provider, z zones.Zone) {
	t.Helper()
	c, err := p.client()
	if err != nil {
		t.Fatalf("could not create client: %s", err)
	}
	if _, err = c.Client.Zones().CreateZone(context.Background(), c.sID, z); err != nil {
		t.Fatalf("failed to create test zone: %s", err)
	}
}

func composeRunner() (string, []string, bool) {
	docker, ok := which("docker")
	if ok {
		check := exec.Command(docker, "compose", "version")
		if err := check.Run(); err == nil {
			return docker, []string{"compose"}, true
		}
	}
	dockerCompose, ok := which("docker-compose")
	if ok {
		return dockerCompose, nil, true
	}
	return "", nil, false
}
