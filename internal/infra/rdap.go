package infra

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/openrdap/rdap"
)

// RDAPClient abstracts RDAP lookups for testing.
type RDAPClient interface {
	LookupIP(ctx context.Context, ip string) (*rdap.IPNetwork, error)
}

// defaultRDAPClient uses the openrdap library.
type defaultRDAPClient struct{}

func (c *defaultRDAPClient) LookupIP(ctx context.Context, ip string) (*rdap.IPNetwork, error) {
	client := &rdap.Client{}
	req := &rdap.Request{
		Type:  rdap.IPRequest,
		Query: ip,
	}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	ipNet, ok := resp.Object.(*rdap.IPNetwork)
	if !ok {
		return nil, fmt.Errorf("rdap: unexpected response type for IP %s", ip)
	}
	return ipNet, nil
}

// NewRDAPClient returns an RDAPClient backed by the standard RDAP bootstrap.
func NewRDAPClient() RDAPClient {
	return &defaultRDAPClient{}
}

// LookupAbuseContact queries RDAP for the abuse contact email of the given IP.
func LookupAbuseContact(ctx context.Context, client RDAPClient, ip string) (string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", &net.ParseError{Type: "IP address", Text: ip}
	}

	ipNet, err := client.LookupIP(ctx, ip)
	if err != nil {
		return "", fmt.Errorf("rdap lookup for %s: %w", ip, err)
	}

	return extractAbuseContact(ipNet.Entities), nil
}

// extractAbuseContact walks the RDAP entity tree looking for an abuse role
// with an email in the vCard.
func extractAbuseContact(entities []rdap.Entity) string {
	for _, entity := range entities {
		for _, role := range entity.Roles {
			if strings.EqualFold(role, "abuse") {
				if email := extractEmailFromVCard(entity); email != "" {
					return email
				}
			}
		}
		// Check nested entities.
		if email := extractAbuseContact(entity.Entities); email != "" {
			return email
		}
	}
	return ""
}

// extractEmailFromVCard extracts an email from the vCard in an RDAP entity.
func extractEmailFromVCard(entity rdap.Entity) string {
	if entity.VCard == nil {
		return ""
	}
	// Use the VCard.Email() helper which returns the first email property value.
	return entity.VCard.Email()
}
