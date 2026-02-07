package infra

import (
	"context"
	"net"

	"github.com/ammario/ipisp/v2"
)

// ASNClient abstracts IP-to-ASN lookups for testing.
type ASNClient interface {
	LookupIP(ctx context.Context, ip net.IP) (*ipisp.Response, error)
}

// cymruClient wraps ipisp for Team Cymru DNS lookups.
type cymruClient struct{}

func (c *cymruClient) LookupIP(ctx context.Context, ip net.IP) (*ipisp.Response, error) {
	return ipisp.LookupIP(ctx, ip)
}

// NewASNClient returns an ASNClient backed by Team Cymru DNS.
func NewASNClient() ASNClient {
	return &cymruClient{}
}

// ASNInfo holds the result of an ASN lookup for a single IP.
type ASNInfo struct {
	ASN       int
	ASNName   string
	BGPPrefix string
	Country   string
}

// LookupASN performs an IP-to-ASN lookup and returns the ASN info.
func LookupASN(ctx context.Context, client ASNClient, ip string) (*ASNInfo, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, &net.ParseError{Type: "IP address", Text: ip}
	}

	resp, err := client.LookupIP(ctx, parsed)
	if err != nil {
		return nil, err
	}

	bgpPrefix := ""
	if resp.Range != nil {
		bgpPrefix = resp.Range.String()
	}

	return &ASNInfo{
		ASN:       int(resp.ASN),
		ASNName:   resp.ISPName,
		BGPPrefix: bgpPrefix,
		Country:   resp.Country,
	}, nil
}
