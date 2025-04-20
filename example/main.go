package main

import (
	"context"

	"github.com/libdns/libdns"

	"github.com/libdns/powerdns"
)

func main() {
	p := &powerdns.Provider{
		ServerURL: "http://localhost", // required
		ServerID:  "localhost",        // if left empty, defaults to localhost.
		APIToken:  "asdfasdfasdf",     // required
	}

	_, err := p.AppendRecords(context.Background(), "example.org.", []libdns.Record{
		libdns.RR{
			Name:  "_acme_whatever",
			Type:  "TXT",
			Data: "123456",
		},
	})
	if err != nil {
		panic(err)
	}

}
