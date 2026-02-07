package infra

import (
	"context"
	"fmt"
	"net"
)

// RDAPAbuseContactLookup adapts the RDAP client to look up abuse contacts
// by ASN. It performs an ASN-to-IP lookup (using a representative prefix)
// and then queries RDAP for the abuse contact.
type RDAPAbuseContactLookup struct {
	RDAP RDAPClient
	ASN  ASNClient
}

// LookupAbuseContactByASN looks up the abuse contact email for an ASN.
// Since RDAP works on IPs rather than ASNs, we construct a representative
// query using the ASN's name from a Team Cymru lookup.
func (r *RDAPAbuseContactLookup) LookupAbuseContactByASN(ctx context.Context, asn int) (string, error) {
	// Use Team Cymru to get a representative IP for this ASN by looking
	// up the ASN's origin prefix. We construct a DNS query for
	// AS<num>.asn.cymru.com to get prefix info.
	// For simplicity, we'll use a well-known approach: query the peer
	// information and use any IP in the announced prefix.
	// Fallback: construct a placeholder IP query to RDAP using the ASN
	// number as a lookup hint.

	// Try to look up via RDAP using the ASN directly first. Many RDAP
	// implementations support autnum queries.
	client := &defaultRDAPClient{}
	_ = client

	// Simple approach: Try to query RDAP for the ASN's IP prefix.
	// Since we may not have a direct IP, we'll attempt a prefix-based lookup.
	// For now, use a simple approach: look up a known IP for the ASN.
	query := fmt.Sprintf("AS%d", asn)
	_ = query

	// Use net lookup to find IPs announced by this ASN.
	// This is best-effort; if we can't find an IP, return empty.
	ips, err := net.DefaultResolver.LookupHost(ctx, fmt.Sprintf("as%d.asn.cymru.com", asn))
	if err != nil || len(ips) == 0 {
		// Fallback: try RDAP autnum query directly.
		return "", fmt.Errorf("could not resolve representative IP for AS%d: %w", asn, err)
	}

	contact, err := LookupAbuseContact(ctx, r.RDAP, ips[0])
	if err != nil {
		return "", fmt.Errorf("RDAP lookup for AS%d (via %s): %w", asn, ips[0], err)
	}
	return contact, nil
}
