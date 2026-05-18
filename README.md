# PowerDNS Provider for [`libdns`](https://github.com/libdns/libdns)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for [PowerDNS](https://powerdns.com), allowing you to manage DNS records.

It uses [mittwald/go-powerdns](https://github.com/mittwald/go-powerdns) under the covers to talk to PowerDNS.

To configure this, specify the server URL and the API token:

```go
package main

import (
	"context"

	"github.com/libdns/libdns"

	powerdns "github.com/vapronva/libdns-powerdns"
)

func main() {
	p := &powerdns.Provider{
		ServerURL: "http://localhost", // required
		ServerID:  "localhost",        // optional; defaults to "localhost"
		APIToken:  "asdfasdfasdf",     // required
		// Debug: "stderr",            // optional; logs the API token in cleartext
	}
	_, err := p.AppendRecords(context.Background(), "example.org.", []libdns.Record{
		libdns.RR{
			Name: "_acme_whatever",
			Type: "TXT",
			Data: "123456",
		},
	})
	if err != nil {
		panic(err)
	}
}
```
