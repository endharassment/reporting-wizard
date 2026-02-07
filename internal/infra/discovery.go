package infra

import (
	"context"
	"sync"

	"github.com/endharassment/reporting-wizard/internal/model"
	"golang.org/x/sync/errgroup"
)

// MaxConcurrency is the default bound on parallel lookups.
const MaxConcurrency = 8

// Discovery orchestrates the full infrastructure discovery pipeline.
type Discovery struct {
	DNS  DNSResolver
	ASN  ASNClient
	RDAP RDAPClient
	BGP  BGPClient
}

// NewDiscovery returns a Discovery with production clients.
func NewDiscovery() *Discovery {
	return &Discovery{
		DNS:  NewDNSResolver(),
		ASN:  NewASNClient(),
		RDAP: NewRDAPClient(),
		BGP:  NewBGPClient(),
	}
}

// Run executes the full discovery pipeline for a domain:
//  1. DNS lookup to get IPs
//  2. For each IP: ASN lookup, Cloudflare check, RDAP abuse contact
//  3. For each unique ASN: BGP upstream lookup
//  4. Returns complete []model.InfraResult
func (d *Discovery) Run(ctx context.Context, domain string) ([]model.InfraResult, error) {
	// Step 1: DNS resolution.
	results, err := LookupDomain(ctx, d.DNS, domain)
	if err != nil {
		return nil, err
	}

	// Step 2: Parallel ASN + RDAP lookups per IP.
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(MaxConcurrency)

	var mu sync.Mutex

	for i := range results {
		i := i
		ip := results[i].IP

		// ASN lookup.
		g.Go(func() error {
			info, err := LookupASN(gctx, d.ASN, ip)
			if err != nil {
				return err
			}
			mu.Lock()
			results[i].ASN = info.ASN
			results[i].ASNName = info.ASNName
			results[i].BGPPrefix = info.BGPPrefix
			results[i].Country = info.Country
			mu.Unlock()
			return nil
		})

		// RDAP abuse contact lookup.
		g.Go(func() error {
			contact, err := LookupAbuseContact(gctx, d.RDAP, ip)
			if err != nil {
				// RDAP failures are non-fatal; we still have other data.
				return nil
			}
			mu.Lock()
			results[i].AbuseContact = contact
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Mark Cloudflare.
	MarkCloudflare(results)

	// Step 3: Collect unique ASNs and look up BGP upstreams.
	asnSet := make(map[int]bool)
	for _, r := range results {
		if r.ASN != 0 {
			asnSet[r.ASN] = true
		}
	}

	upstreamMap := make(map[int][]int)
	var upMu sync.Mutex

	g2, gctx2 := errgroup.WithContext(ctx)
	g2.SetLimit(MaxConcurrency)

	for asn := range asnSet {
		asn := asn
		g2.Go(func() error {
			upstreams, err := d.BGP.LookupUpstreams(gctx2, asn)
			if err != nil {
				// BGP failures are non-fatal.
				return nil
			}
			upMu.Lock()
			upstreamMap[asn] = upstreams
			upMu.Unlock()
			return nil
		})
	}

	if err := g2.Wait(); err != nil {
		return nil, err
	}

	// Attach upstream ASNs to results.
	for i := range results {
		if ups, ok := upstreamMap[results[i].ASN]; ok {
			results[i].UpstreamASNs = ups
		}
	}

	return results, nil
}
